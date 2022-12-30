package utils

import (
	"sync"

	"github.com/safedep/vet/pkg/common/logger"
)

type WorkQueueItem interface {
	Id() string
}

type WorkQueueFn[T WorkQueueItem] func(q *WorkQueue[T], item T) error

type WorkQueue[T WorkQueueItem] struct {
	done        chan bool
	m           sync.Mutex
	concurrency int
	wg          sync.WaitGroup
	handler     WorkQueueFn[T]
	status      sync.Map
	items       chan T
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

func (q *WorkQueue[T]) Add(item T) {
	if _, ok := q.status.Load(item.Id()); ok {
		return
	}

	q.status.Store(item.Id(), true)
	q.wg.Add(1)

	q.items <- item
}
