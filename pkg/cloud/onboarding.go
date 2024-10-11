package cloud

import (
	"context"

	"buf.build/gen/go/safedep/api/grpc/go/safedep/services/controltower/v1/controltowerv1grpc"
	controltowerv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/controltower/v1"
	"google.golang.org/grpc"
)

type onboardingService struct {
	conn *grpc.ClientConn
}

type RegisterRequest struct {
	Email     string
	Name      string
	OrgName   string
	OrgDomain string
}

type RegisterResponse struct {
	TenantDomain string
}

func NewOnboardingService(conn *grpc.ClientConn) (*onboardingService, error) {
	return &onboardingService{conn}, nil
}

func (s *onboardingService) Register(req *RegisterRequest) (*RegisterResponse, error) {
	onbService := controltowerv1grpc.NewOnboardingServiceClient(s.conn)
	res, err := onbService.OnboardUser(context.Background(), &controltowerv1.OnboardUserRequest{
		Email:              req.Email,
		Name:               req.Name,
		OrganizationName:   req.OrgName,
		OrganizationDomain: req.OrgDomain,
	})

	if err != nil {
		return nil, err
	}

	return &RegisterResponse{
		TenantDomain: res.GetTenant().GetDomain(),
	}, nil
}
