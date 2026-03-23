package soc

import (
	"log/slog"
	"sync"
)

// EventBus implements a pub-sub event bus for real-time event streaming (SSE/WebSocket).
// Subscribers receive events as they are ingested via IngestEvent pipeline.
type EventBus struct {
	mu          sync.RWMutex
	subscribers map[string]chan SOCEvent
	bufSize     int
}

// NewEventBus creates a new event bus with the given channel buffer size.
func NewEventBus(bufSize int) *EventBus {
	if bufSize <= 0 {
		bufSize = 100
	}
	return &EventBus{
		subscribers: make(map[string]chan SOCEvent),
		bufSize:     bufSize,
	}
}

// Subscribe creates a new subscriber channel. Returns channel and subscriber ID.
func (eb *EventBus) Subscribe(id string) <-chan SOCEvent {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	ch := make(chan SOCEvent, eb.bufSize)
	eb.subscribers[id] = ch
	return ch
}

// Unsubscribe removes a subscriber and closes its channel.
func (eb *EventBus) Unsubscribe(id string) {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	if ch, ok := eb.subscribers[id]; ok {
		close(ch)
		delete(eb.subscribers, id)
	}
}

// Publish sends an event to all subscribers. Non-blocking — drops if subscriber is full.
func (eb *EventBus) Publish(event SOCEvent) {
	eb.mu.RLock()
	defer eb.mu.RUnlock()

	slog.Info("eventbus: publish", "event_id", event.ID, "severity", event.Severity, "subscribers", len(eb.subscribers))
	for id, ch := range eb.subscribers {
		select {
		case ch <- event:
			slog.Info("eventbus: delivered", "subscriber", id, "event_id", event.ID)
		default:
			slog.Warn("eventbus: dropped (slow subscriber)", "subscriber", id, "event_id", event.ID)
		}
	}
}

// SubscriberCount returns the number of active subscribers.
func (eb *EventBus) SubscriberCount() int {
	eb.mu.RLock()
	defer eb.mu.RUnlock()
	return len(eb.subscribers)
}
