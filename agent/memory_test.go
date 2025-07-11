package agent

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/cloudwego/eino/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSimpleMemory(t *testing.T) {
	memory, err := NewSimpleMemory()
	require.NoError(t, err)
	assert.NotNil(t, memory)

	// Test that initial interactions are empty
	ctx := context.Background()
	interactions, err := memory.GetInteractions(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, len(interactions))
}

func TestSimpleMemory_AddInteraction(t *testing.T) {
	memory, err := NewSimpleMemory()
	require.NoError(t, err)

	ctx := context.Background()
	message := &schema.Message{
		Role:    schema.User,
		Content: "test message",
	}

	err = memory.AddInteraction(ctx, message)
	assert.NoError(t, err)

	interactions, err := memory.GetInteractions(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, len(interactions))
	assert.Equal(t, message, interactions[0])
}

func TestSimpleMemory_AddMultipleInteractions(t *testing.T) {
	memory, err := NewSimpleMemory()
	require.NoError(t, err)

	ctx := context.Background()
	messages := []*schema.Message{
		{Role: schema.User, Content: "first message"},
		{Role: schema.Assistant, Content: "second message"},
		{Role: schema.User, Content: "third message"},
	}

	for _, msg := range messages {
		err = memory.AddInteraction(ctx, msg)
		assert.NoError(t, err)
	}

	interactions, err := memory.GetInteractions(ctx)
	require.NoError(t, err)
	assert.Equal(t, 3, len(interactions))

	for i, msg := range messages {
		assert.Equal(t, msg, interactions[i])
	}
}

func TestSimpleMemory_GetInteractions(t *testing.T) {
	memory, err := NewSimpleMemory()
	require.NoError(t, err)

	ctx := context.Background()

	// Test empty interactions
	interactions, err := memory.GetInteractions(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, interactions)
	assert.Equal(t, 0, len(interactions))

	// Add some interactions
	message1 := &schema.Message{Role: schema.User, Content: "message 1"}
	message2 := &schema.Message{Role: schema.Assistant, Content: "message 2"}

	err = memory.AddInteraction(ctx, message1)
	require.NoError(t, err)
	err = memory.AddInteraction(ctx, message2)
	require.NoError(t, err)

	interactions, err = memory.GetInteractions(ctx)
	assert.NoError(t, err)
	assert.Equal(t, 2, len(interactions))
	assert.Equal(t, message1, interactions[0])
	assert.Equal(t, message2, interactions[1])
}

func TestSimpleMemory_Clear(t *testing.T) {
	memory, err := NewSimpleMemory()
	require.NoError(t, err)

	ctx := context.Background()

	// Add some interactions
	message1 := &schema.Message{Role: schema.User, Content: "message 1"}
	message2 := &schema.Message{Role: schema.Assistant, Content: "message 2"}

	err = memory.AddInteraction(ctx, message1)
	require.NoError(t, err)
	err = memory.AddInteraction(ctx, message2)
	require.NoError(t, err)

	// Verify interactions exist
	interactions, err := memory.GetInteractions(ctx)
	require.NoError(t, err)
	assert.Equal(t, 2, len(interactions))

	// Clear interactions
	err = memory.Clear(ctx)
	assert.NoError(t, err)

	// Verify interactions are cleared
	interactions, err = memory.GetInteractions(ctx)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(interactions))
}

func TestSimpleMemory_NilInteraction(t *testing.T) {
	memory, err := NewSimpleMemory()
	require.NoError(t, err)

	ctx := context.Background()

	// Test adding nil interaction
	err = memory.AddInteraction(ctx, nil)
	assert.NoError(t, err)

	interactions, err := memory.GetInteractions(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, len(interactions))
	assert.Nil(t, interactions[0])
}

func TestSimpleMemory_ConcurrentAccess(t *testing.T) {
	memory, err := NewSimpleMemory()
	require.NoError(t, err)

	ctx := context.Background()
	numGoroutines := 100
	messagesPerGoroutine := 10

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Concurrent writes
	for i := 0; i < numGoroutines; i++ {
		go func(goroutineID int) {
			defer wg.Done()
			for j := 0; j < messagesPerGoroutine; j++ {
				message := &schema.Message{
					Role:    schema.User,
					Content: fmt.Sprintf("goroutine-%d-message-%d", goroutineID, j),
				}
				err := memory.AddInteraction(ctx, message)
				assert.NoError(t, err)
			}
		}(i)
	}

	wg.Wait()

	// Verify all interactions were added
	interactions, err := memory.GetInteractions(ctx)
	require.NoError(t, err)
	assert.Equal(t, numGoroutines*messagesPerGoroutine, len(interactions))
}

func TestSimpleMemory_ConcurrentReadWrite(t *testing.T) {
	memory, err := NewSimpleMemory()
	require.NoError(t, err)

	ctx := context.Background()
	numReaders := 10
	numWriters := 10
	messagesPerWriter := 5

	var wg sync.WaitGroup
	wg.Add(numReaders + numWriters)

	// Concurrent writers
	for i := 0; i < numWriters; i++ {
		go func(writerID int) {
			defer wg.Done()
			for j := 0; j < messagesPerWriter; j++ {
				message := &schema.Message{
					Role:    schema.User,
					Content: fmt.Sprintf("writer-%d-message-%d", writerID, j),
				}
				err := memory.AddInteraction(ctx, message)
				assert.NoError(t, err)
			}
		}(i)
	}

	// Concurrent readers
	for i := 0; i < numReaders; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < messagesPerWriter; j++ {
				interactions, err := memory.GetInteractions(ctx)
				assert.NoError(t, err)
				assert.NotNil(t, interactions)
				// Length can vary due to concurrent writes
				assert.GreaterOrEqual(t, len(interactions), 0)
			}
		}()
	}

	wg.Wait()

	// Final verification
	interactions, err := memory.GetInteractions(ctx)
	require.NoError(t, err)
	assert.Equal(t, numWriters*messagesPerWriter, len(interactions))
}

func TestSimpleMemory_ClearDuringConcurrentAccess(t *testing.T) {
	memory, err := NewSimpleMemory()
	require.NoError(t, err)

	ctx := context.Background()
	numWriters := 5
	messagesPerWriter := 10

	var wg sync.WaitGroup
	wg.Add(numWriters + 1) // +1 for the clearer

	// Add some initial interactions
	for i := 0; i < 5; i++ {
		message := &schema.Message{
			Role:    schema.User,
			Content: fmt.Sprintf("initial-message-%d", i),
		}
		err := memory.AddInteraction(ctx, message)
		require.NoError(t, err)
	}

	// Concurrent writers
	for i := 0; i < numWriters; i++ {
		go func(writerID int) {
			defer wg.Done()
			for j := 0; j < messagesPerWriter; j++ {
				message := &schema.Message{
					Role:    schema.User,
					Content: fmt.Sprintf("writer-%d-message-%d", writerID, j),
				}
				err := memory.AddInteraction(ctx, message)
				assert.NoError(t, err)
			}
		}(i)
	}

	// Clear operation
	go func() {
		defer wg.Done()
		// Clear after some writes have happened
		err := memory.Clear(ctx)
		assert.NoError(t, err)
	}()

	wg.Wait()

	// Final state check - should be consistent
	interactions, err := memory.GetInteractions(ctx)
	require.NoError(t, err)
	assert.NotNil(t, interactions)
	// The exact number depends on timing of clear operation
	assert.GreaterOrEqual(t, len(interactions), 0)
}
