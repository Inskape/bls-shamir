package atomic

import (
	"Inskape/bls-shamir/core/stack"
	"Inskape/bls-shamir/internal/global"
	"context"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
)

var (
	meter = otel.Meter(global.Name + ":core:atomic:pool")
)

var (
	putCounter    metric.Int64Counter
	getCounter    metric.Int64Counter
	createCounter metric.Int64Counter
)

func init() {
	var err error
	putCounter, err = meter.Int64Counter("pool.put", metric.WithDescription("The number of times the Put method was called"), metric.WithUnit("call"))
	if err != nil {
		panic(err)
	}
	getCounter, err = meter.Int64Counter("pool.get", metric.WithDescription("The number of times the Get method was called"), metric.WithUnit("call"))
	if err != nil {
		panic(err)
	}
	createCounter, err = meter.Int64Counter("pool.create", metric.WithDescription("The number of times a new value was created"), metric.WithUnit("call"))
	if err != nil {
		panic(err)
	}
}

// A Pool is a set of temporary objects that may be individually saved and
// retrieved.
//
// Any item stored in the Pool may be removed automatically at any time without
// notification. If the Pool holds the only reference when this happens, the
// item might be deallocated.
//
// A Pool is safe for use by multiple goroutines simultaneously.
//
// Pool's purpose is to cache allocated but unused items for later reuse,
// relieving pressure on the garbage collector. That is, it makes it easy to
// build efficient, thread-safe free lists. However, it is not suitable for all
// free lists.
//
// An appropriate use of a Pool is to manage a group of temporary items
// silently shared among and potentially reused by concurrent independent
// clients of a package. Pool provides a way to amortize allocation overhead
// across many clients.
//
// An example of good use of a Pool is in the fmt package, which maintains a
// dynamically-sized store of temporary output buffers. The store scales under
// load (when many goroutines are actively printing) and shrinks when
// quiescent.
//
// On the other hand, a free list maintained as part of a short-lived object is
// not a suitable use for a Pool, since the overhead does not amortize well in
// that scenario. It is more efficient to have such objects implement their own
// free list.
//
// A Pool must not be copied after first use.
//
// In the terminology of the Go memory model, a call to Put(x) “synchronizes before”
// a call to Get returning that same value x.
// Similarly, a call to New returning x “synchronizes before”
// a call to Get returning that same value x.
type Pool[T any] struct {
	mu sync.RWMutex

	values *stack.Stack[T]

	new func() *T
}

func NewPool[T any](ttl time.Duration, New func() *T) *Pool[T] {
	return &Pool[T]{new: New, values: stack.New[T](ttl)}
}

// Put adds x to the pool.
func (p *Pool[T]) Put(ctx context.Context, x *T) {
	putCounter.Add(ctx, 1)

	p.mu.Lock()
	defer p.mu.Unlock()
	p.values.Push(ctx, x)
}

// Get selects an arbitrary item from the Pool, removes it from the
// Pool, and returns it to the caller.
// Get may choose to ignore the pool and treat it as empty.
// Callers should not assume any relation between values passed to Put and
// the values returned by Get.
//
// If Get would otherwise return nil and p.New is non-nil, Get returns
// the result of calling p.New. If p.New is nil, Get returns nil.
func (p *Pool[T]) Get(ctx context.Context) *T {
	getCounter.Add(ctx, 1)

	p.mu.RLock()
	defer p.mu.RUnlock()

	if v := p.values.Pop(ctx); v == nil {
		if p.new != nil {
			result := p.new()
			createCounter.Add(ctx, 1)
			return result
		} else {
			return nil
		}
	} else {
		return v
	}
}
