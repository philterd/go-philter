package pheye

import (
	"fmt"
	"testing"

	"github.com/philterd/go-philter/internal/model"
	"github.com/philterd/go-philter/internal/policy"
	"github.com/stretchr/testify/assert"
)

func TestPhEyeFilter_GetFilterType(t *testing.T) {
	cfg := policy.PhEyeFilter{}
	filter := NewPhEyeFilter(cfg)
	assert.Equal(t, model.FilterTypePhEye, filter.GetFilterType())
}

func TestPhEyeFilter_Filter_NoContext(t *testing.T) {
	cfg := policy.PhEyeFilter{}
	filter := NewPhEyeFilter(cfg)
	pol := &policy.Policy{
		Identifiers: policy.Identifiers{
			PhEye: []policy.PhEyeFilter{cfg},
		},
	}

	// Should return nil because ctx is nil
	spans, err := filter.Filter(pol, "context", "text")
	assert.NoError(t, err)
	assert.Nil(t, spans)
}

func TestPhEyeFilter_Filter_ActualModel(t *testing.T) {
	// Skip the test if the model doesn't exist to avoid CI failures
	modelPath := "/tmp/ph-eye-pii-base"
	cfg := policy.PhEyeFilter{
		PhEyeConfiguration: policy.PhEyeConfiguration{
			ModelPath: modelPath,
			Labels:    "Person",
		},
	}

	filter := NewPhEyeFilter(cfg)
	if filter.client == nil {
		t.Skip("PhEye client not initialized (model path may be empty)")
	}
	defer filter.Close()

	pol := &policy.Policy{
		Identifiers: policy.Identifiers{
			PhEye: []policy.PhEyeFilter{cfg},
		},
	}

	text := "George Washington was president."
	spans, err := filter.Filter(pol, "test-context", text)

	fmt.Println(spans)
	assert.NoError(t, err)

	found := false
	for _, span := range spans {
		if span.Text == "George Washington" {
			found = true
			break
		}
	}
	assert.True(t, found, "George Washington was not identified in the sentence")
}
