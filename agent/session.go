package agent

import "github.com/google/uuid"

type session struct {
	sessionID string
	memory    Memory
}

var _ Session = (*session)(nil)

func NewSession(memory Memory) (*session, error) {
	return newSessionWithID(uuid.New().String(), memory), nil
}

func newSessionWithID(id string, memory Memory) *session {
	return &session{
		sessionID: id,
		memory:    memory,
	}
}

func (s *session) ID() string {
	return s.sessionID
}

func (s *session) Memory() Memory {
	return s.memory
}
