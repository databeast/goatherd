package coordination_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"

	"github.com/databeast/goatherd/internal/coordination"
)

func readReports(ctx context.Context, client coordination.CoordinatorClient) (*coordination.ReportsResponse, error) {
	stream, err := client.StreamReports(ctx, &coordination.ReportsRequest{})
	if err != nil {
		return nil, err
	}
	var data bytes.Buffer
	for {
		chunk, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		data.Write(chunk.Data)
	}
	response := &coordination.ReportsResponse{}
	if err := json.Unmarshal(data.Bytes(), &response.Reports); err != nil {
		return nil, err
	}
	return response, nil
}

func readInventory(ctx context.Context, client coordination.CoordinatorClient) ([]byte, error) {
	stream, err := client.Inventory(ctx, &coordination.InventoryRequest{})
	if err != nil {
		return nil, err
	}
	var data bytes.Buffer
	for {
		chunk, err := stream.Recv()
		if err == io.EOF {
			return data.Bytes(), nil
		}
		if err != nil {
			return nil, err
		}
		data.Write(chunk.Data)
	}
}
