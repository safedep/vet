package stub

import (
	"context"
	"encoding/json"

	controltowerv1grpc "buf.build/gen/go/safedep/api/grpc/go/safedep/services/controltower/v1/controltowerv1grpc"
	controltowerv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/controltower/v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/encoding/protojson"
)

// EndpointSync counts the SyncEvents calls of the endpoint service.
const EndpointSync = "endpointsync"

type endpointService struct {
	controltowerv1grpc.UnimplementedEndpointServiceServer
	s *Server
}

// SyncEvents records the events of a batch and confirms each one.
func (e *endpointService) SyncEvents(ctx context.Context, req *controltowerv1.SyncEventsRequest) (*controltowerv1.SyncEventsResponse, error) {
	if err := e.s.begin(ctx, EndpointSync); err != nil {
		return nil, err
	}
	tenant := ""
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if v := md.Get("x-tenant-id"); len(v) > 0 {
			tenant = v[0]
		}
	}
	e.s.mu.Lock()
	defer e.s.mu.Unlock()
	ids := make([]string, 0, len(req.GetEvents()))
	for _, ev := range req.GetEvents() {
		ids = append(ids, ev.GetEventId())
		b, err := stableJSON(ev)
		if err != nil {
			return nil, err
		}
		e.s.events = append(e.s.events, SyncedEvent{Tenant: tenant, Endpoint: req.GetEndpoint().GetIdentifier(), JSON: string(b)})
	}
	return controltowerv1.SyncEventsResponse_builder{ConfirmedEventIds: ids}.Build(), nil
}

// SyncedEvent is one event that the stub received.
type SyncedEvent struct {
	Tenant   string
	Endpoint string
	// JSON is the event in compact protojson with the proto field names.
	JSON string
}

// Events returns the events that the stub received, in order.
func (s *Server) Events() []SyncedEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]SyncedEvent(nil), s.events...)
}

// stableJSON returns the compact JSON of an event. protojson varies its
// white space on purpose, so the stub encodes the value again, and a
// script can match a fixed text.
func stableJSON(ev *controltowerv1.ToolEvent) ([]byte, error) {
	b, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(ev)
	if err != nil {
		return nil, err
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	return json.Marshal(v)
}
