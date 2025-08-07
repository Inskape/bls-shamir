package atomic

import "sync"

type Value[T any] struct {
	mu    sync.RWMutex
	value T
}

func NewValue[T any](val T) Value[T] {
	return Value[T]{value: val}
}

func (v *Value[T]) Load() (val T) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.value
}

func (v *Value[T]) Store(val T) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.value = val
}
