package proxy

import (
	"context"
	"sync"
	"time"
)

type SessionStore struct {
	mu          sync.Mutex
	ttl         time.Duration
	maxSessions int
	now         func() time.Time
	sessions    map[string]SessionState
}

func NewSessionStore(ttl time.Duration, maxSessions int, now func() time.Time) *SessionStore {
	if now == nil {
		now = time.Now
	}
	return &SessionStore{
		ttl:         ttl,
		maxSessions: maxSessions,
		now:         now,
		sessions:    make(map[string]SessionState),
	}
}

func (store *SessionStore) BuildMessages(_ context.Context, sessionID string, incoming []Message) ([]Message, error) {
	if sessionID == "" {
		return cloneMessages(incoming), nil
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	store.sweepExpiredLocked()

	existing := store.sessions[sessionID]
	return mergeMessages(existing.Messages, incoming), nil
}

func (store *SessionStore) SaveResponse(_ context.Context, sessionID string, requestMessages []Message, assistant Message) error {
	if sessionID == "" {
		return nil
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	store.sweepExpiredLocked()
	store.ensureCapacityLocked(sessionID)

	saved := mergeMessages(nil, requestMessages)
	saved = append(saved, assistant)
	store.sessions[sessionID] = SessionState{
		ID:           sessionID,
		Messages:     saved,
		MessageCount: len(saved),
		UpdatedAt:    store.now(),
	}
	return nil
}

func (store *SessionStore) Delete(_ context.Context, sessionID string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	delete(store.sessions, sessionID)
	return nil
}

func (store *SessionStore) List(_ context.Context) ([]SessionState, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.sweepExpiredLocked()

	result := make([]SessionState, 0, len(store.sessions))
	for _, session := range store.sessions {
		cloned := session
		cloned.Messages = cloneMessages(session.Messages)
		result = append(result, cloned)
	}
	return result, nil
}

func (store *SessionStore) SweepExpired(_ context.Context) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.sweepExpiredLocked()
	return nil
}

func (store *SessionStore) sweepExpiredLocked() {
	if store.ttl <= 0 {
		return
	}
	now := store.now()
	for id, session := range store.sessions {
		if now.Sub(session.UpdatedAt) > store.ttl {
			delete(store.sessions, id)
		}
	}
}

func (store *SessionStore) ensureCapacityLocked(currentID string) {
	if store.maxSessions <= 0 || len(store.sessions) < store.maxSessions {
		return
	}
	if _, exists := store.sessions[currentID]; exists {
		return
	}

	oldestID := ""
	var oldestTime time.Time
	for id, session := range store.sessions {
		if oldestID == "" || session.UpdatedAt.Before(oldestTime) {
			oldestID = id
			oldestTime = session.UpdatedAt
		}
	}
	if oldestID != "" {
		delete(store.sessions, oldestID)
	}
}

func mergeMessages(existing, incoming []Message) []Message {
	if len(existing) == 0 {
		return cloneMessages(incoming)
	}
	if len(incoming) == 0 {
		return cloneMessages(existing)
	}
	if hasMessagePrefix(incoming, existing) {
		return cloneMessages(incoming)
	}

	merged := cloneMessages(existing)
	merged = append(merged, incoming...)
	return merged
}

func hasMessagePrefix(candidate, prefix []Message) bool {
	if len(candidate) < len(prefix) {
		return false
	}
	for index := range prefix {
		if !messageEqual(candidate[index], prefix[index]) {
			return false
		}
	}
	return true
}

func messageEqual(a, b Message) bool {
	if a.Role != b.Role || a.Content != b.Content || a.Name != b.Name || a.ToolCallID != b.ToolCallID {
		return false
	}
	if len(a.ToolCalls) != len(b.ToolCalls) {
		return false
	}
	for i := range a.ToolCalls {
		if a.ToolCalls[i] != b.ToolCalls[i] {
			return false
		}
	}
	return true
}
