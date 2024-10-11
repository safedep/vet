package cloud

import (
	"context"
	"time"

	"buf.build/gen/go/safedep/api/grpc/go/safedep/services/controltower/v1/controltowerv1grpc"
	controltowerv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/controltower/v1"
	"github.com/oklog/ulid/v2"
	"google.golang.org/grpc"
)

type pingService struct {
	conn *grpc.ClientConn
}

type PingResponse struct {
	StartedAt  time.Time
	FinishedAt time.Time
}

func NewPingService(conn *grpc.ClientConn) (*pingService, error) {
	return &pingService{conn: conn}, nil
}

func (p *pingService) Ping() (*PingResponse, error) {
	pr := PingResponse{
		StartedAt: time.Now(),
	}

	pingService := controltowerv1grpc.NewPingServiceClient(p.conn)
	_, err := pingService.Ping(context.Background(), &controltowerv1.PingRequest{
		Id: ulid.MustNew(ulid.Now(), nil).String(),
	})

	if err != nil {
		return nil, err
	}

	pr.FinishedAt = time.Now()
	return &pr, nil
}
