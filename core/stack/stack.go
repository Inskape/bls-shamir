package stack

import (
	"Inskape/bls-shamir/internal/global"
	"context"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
)

var (
	meter = otel.Meter(global.Name + ":core:stack")
)

var (
	peekCounter   metric.Int64Counter
	popCounter    metric.Int64Counter
	pushCounter   metric.Int64Counter
	expireCounter metric.Int64Counter
)

func init() {
	var err error
	peekCounter, err = meter.Int64Counter("stack.peek", metric.WithDescription("The number of times the Peek method was called"), metric.WithUnit("call"))
	if err != nil {
		panic(err)
	}
	popCounter, err = meter.Int64Counter("stack.pop", metric.WithDescription("The number of times the Pop method was called"), metric.WithUnit("call"))
	if err != nil {
		panic(err)
	}
	pushCounter, err = meter.Int64Counter("stack.push", metric.WithDescription("The number of times the Push method was called"), metric.WithUnit("call"))
	if err != nil {
		panic(err)
	}
	expireCounter, err = meter.Int64Counter("stack.expire", metric.WithDescription("The number of times an item on the stack's time to live expired"), metric.WithUnit("call"))
	if err != nil {
		panic(err)
	}
}

type node[T any] struct {
	value    *T
	timer    *time.Timer
	next     *node[T]
	previous *node[T]
}

type Stack[T any] struct {
	mu     sync.RWMutex
	top    *node[T]
	length int
	ttl    time.Duration
}

// Create a new stack. If ttl is greater than 0, the stack will automatically remove items after the given duration.
func New[T any](ttl time.Duration) *Stack[T] {
	return &Stack[T]{ttl: ttl}
}

// Return the number of items in the stack
func (s *Stack[T]) Len(ctx context.Context) int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.length
}

// View the top item on the stack
func (s *Stack[T]) Peek(ctx context.Context) *T {
	peekCounter.Add(ctx, 1)

	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.length == 0 {
		return nil
	}
	return s.top.value
}

// Pop the top item of the stack and return it
func (s *Stack[T]) Pop(ctx context.Context) *T {
	popCounter.Add(ctx, 1)

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.length == 0 {
		return nil
	}

	n := s.top
	if n.timer != nil {
		n.timer.Stop()
	}

	s.top = n.previous
	if s.top != nil {
		s.top.next = nil
	}
	s.length--
	return n.value
}

// Push a value onto the top of the stack
func (s *Stack[T]) Push(ctx context.Context, value *T) {
	pushCounter.Add(ctx, 1)

	s.mu.Lock()
	defer s.mu.Unlock()

	n := &node[T]{value: value, previous: s.top}
	if s.ttl > 0 {
		n.timer = time.AfterFunc(s.ttl, func() {
			expireCounter.Add(ctx, 1)
			if n.next != nil {
				n.next.previous = n.previous
			}

			if n.previous != nil {
				n.previous.next = n.next
			}

			n.next, n.previous, n.timer = nil, nil, nil

			s.mu.Lock()
			defer s.mu.Unlock()
			s.length--
		})
	}
	if s.top != nil {
		s.top.next = n
	}
	s.top = n
	s.length++
}
