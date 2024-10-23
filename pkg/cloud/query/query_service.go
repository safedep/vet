package query

import (
	"context"

	"buf.build/gen/go/safedep/api/grpc/go/safedep/services/controltower/v1/controltowerv1grpc"
	controltowerv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/controltower/v1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/structpb"
)

type queryService struct {
	client *grpc.ClientConn
}

func NewQueryService(client *grpc.ClientConn) (*queryService, error) {
	return &queryService{client: client}, nil
}

func (q *queryService) GetSchema() (*controltowerv1.GetSqlSchemaResponse, error) {
	queryServiceClient := controltowerv1grpc.NewQueryServiceClient(q.client)

	res, err := queryServiceClient.GetSqlSchema(context.Background(),
		&controltowerv1.GetSqlSchemaRequest{})
	if err != nil {
		return nil, err
	}

	return res, nil
}

func (q *queryService) ExecuteSql(sql string, pageSize int) (*QueryResponse, error) {
	queryServiceClient := controltowerv1grpc.NewQueryServiceClient(q.client)

	res, err := queryServiceClient.QueryBySql(context.Background(), &controltowerv1.QueryBySqlRequest{
		Query:    sql,
		PageSize: int32(pageSize),
	})

	if err != nil {
		return nil, err
	}

	var response QueryResponse
	for _, row := range res.Rows {
		rowMap := make(map[string]interface{})
		for key, val := range row.Fields {
			switch val.GetKind().(type) {
			case *structpb.Value_StringValue:
				rowMap[key] = val.GetStringValue()
			case *structpb.Value_NumberValue:
				rowMap[key] = val.GetNumberValue()
			case *structpb.Value_BoolValue:
				rowMap[key] = val.GetBoolValue()
			default:
				rowMap[key] = ""
			}
		}

		response = append(response, rowMap)
	}

	return &response, nil
}
