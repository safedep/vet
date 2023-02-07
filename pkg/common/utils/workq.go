package utils

import (
	"sync"

	"github.com/safedep/vet/pkg/common/logger"
)

type WorkQueueItem interface {
	Id() string
}

type WorkQueueFn[T WorkQueueItem] func(q *WorkQueue[T], item T) error

type WorkQueueCallbackOnItemFn[T WorkQueueItem] func(q *WorkQueue[T], item T)

type WorkQueueCallbacks[T WorkQueueItem] struct {
	OnAdd  WorkQueueCallbackOnItemFn[T]
	OnDone WorkQueueCallbackOnItemFn[T]
}

type WorkQueue[T WorkQueueItem] struct {
	done        chan bool
	m           sync.Mutex
	concurrency int
	wg          sync.WaitGroup
	handler     WorkQueueFn[T]
	status      sync.Map
	items       chan T
	callbacks   WorkQueueCallbacks[T]
}

func NewWorkQueue[T WorkQueueItem](bufferSize int, concurrency int,
	handler WorkQueueFn[T]) *WorkQueue[T] {
	return &WorkQueue[T]{
		handler:     handler,
		concurrency: concurrency,
		items:       make(chan T, bufferSize),
		done:        make(chan bool),
	}
}

func (q *WorkQueue[T]) WithCallbacks(callbacks WorkQueueCallbacks[T]) {
	q.callbacks = callbacks
}

func (q *WorkQueue[T]) Start() {
	for i := 0; i < q.concurrency; i++ {
		go func() {
			for {
				select {
				case <-q.done:
					return
				case item := <-q.items:
					err := q.handler(q, item)
					if err != nil {
						logger.Errorf("Handler fn failed with %v", err)
					}

					q.wg.Done()
					q.dispatchOnDone(item)
				}
			}
		}()
	}
}

func (q *WorkQueue[T]) Wait() {
	q.wg.Wait()
}

func (q *WorkQueue[T]) Stop() {
	close(q.done)
}

func (q *WorkQueue[T]) Add(item T) bool {
	if _, ok := q.status.Load(item.Id()); ok {
		return false
	}

	q.status.Store(item.Id(), true)
	q.wg.Add(1)

	q.items <- item
	q.dispatchOnAdd(item)

	return true
}

func (q *WorkQueue[T]) dispatchOnAdd(item T) {
	if q.callbacks.OnAdd != nil {
		q.callbacks.OnAdd(q, item)
	}
}

func (q *WorkQueue[T]) dispatchOnDone(item T) {
	if q.callbacks.OnDone != nil {
		q.callbacks.OnDone(q, item)
	}
}
