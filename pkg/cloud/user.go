package cloud

import (
	"context"

	"buf.build/gen/go/safedep/api/grpc/go/safedep/services/controltower/v1/controltowerv1grpc"
	controltowerv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/controltower/v1"
	"google.golang.org/grpc"
)

type userService struct {
	conn *grpc.ClientConn
}

func NewUserService(conn *grpc.ClientConn) (*userService, error) {
	return &userService{conn: conn}, nil
}

func (s *userService) CurrentUserInfo() (*controltowerv1.GetUserInfoResponse, error) {
	userService := controltowerv1grpc.NewUserServiceClient(s.conn)
	res, err := userService.GetUserInfo(context.Background(), &controltowerv1.GetUserInfoRequest{})
	if err != nil {
		return nil, err
	}

	return res, nil
}
