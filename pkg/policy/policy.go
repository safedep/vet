package policy

type PolicyEvent struct {
}

type PolicyEventHandler func(event *PolicyEvent) error
