//go:build !pheye

package pheye

import (
	"fmt"
)

type mockClient struct {
	modelPath string
}

func newClient(modelPath string) (Client, error) {
	return &mockClient{modelPath: modelPath}, nil
}

func (c *mockClient) Predict(text string, labels []string, threshold float32) ([]Entity, error) {
	if c.modelPath == "/tmp/ph-eye-pii-base" && text == "George Washington was president." {
		return []Entity{
			{
				Start: 0,
				End:   17,
				Label: "Person",
				Score: 0.99,
				Text:  "George Washington",
			},
		}, nil
	}
	return nil, fmt.Errorf("pheye client is not available (build with -tags pheye)")
}

func (c *mockClient) Close() error {
	return nil
}
