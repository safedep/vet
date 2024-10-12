package query

import (
	"context"

	"buf.build/gen/go/safedep/api/grpc/go/safedep/services/controltower/v1/controltowerv1grpc"
	controltowerv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/controltower/v1"
	"google.golang.org/grpc"
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

func (q *queryService) ExecuteSql(sql string) (*QueryResponse, error) {
	queryServiceClient := controltowerv1grpc.NewQueryServiceClient(q.client)

	res, err := queryServiceClient.QueryBySql(context.Background(), &controltowerv1.QueryBySqlRequest{
		Query:    sql,
		PageSize: 100,
	})

	if err != nil {
		return nil, err
	}

	var response QueryResponse
	for _, row := range res.Rows {
		rowMap := make(map[string]interface{})
		for key, val := range row.Fields {
			rowMap[key] = val.GetStringValue()
		}

		response = append(response, rowMap)
	}

	return &response, nil
}
