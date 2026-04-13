//go:build pheye

package pheye

/*
#cgo LDFLAGS: -lgliner -lstdc++
#include <stdlib.h>

typedef struct {
    int start;
    int end;
    char* label;
    float score;
    char* text;
} gliner_span_t;

void* gliner_init(const char* model_path);
void gliner_free(void* ctx);
int gliner_predict(void* ctx, const char* text, const char** labels, int num_labels, float threshold, gliner_span_t* spans, int max_spans);
void gliner_free_spans(gliner_span_t* spans, int num_spans);
*/
import "C"

import (
	"fmt"
	"unsafe"
)

const maxSpans = 1024

type cgoClient struct {
	ctx unsafe.Pointer
}

func newClient(modelPath string) (Client, error) {
	cModelPath := C.CString(modelPath)
	defer C.free(unsafe.Pointer(cModelPath))

	ctx := C.gliner_init(cModelPath)
	if ctx == nil {
		return nil, fmt.Errorf("failed to initialize PhEye model at %s", modelPath)
	}

	return &cgoClient{ctx: ctx}, nil
}

func (c *cgoClient) Predict(text string, labels []string, threshold float32) ([]Entity, error) {
	cText := C.CString(text)
	defer C.free(unsafe.Pointer(cText))

	cLabels := make([]*C.char, len(labels))
	for i, l := range labels {
		cLabels[i] = C.CString(l)
		defer C.free(unsafe.Pointer(cLabels[i]))
	}

	var cSpans [maxSpans]C.gliner_span_t
	numSpans := C.gliner_predict(
		c.ctx,
		cText,
		(**C.char)(unsafe.Pointer(&cLabels[0])),
		C.int(len(labels)),
		C.float(threshold),
		&cSpans[0],
		C.int(maxSpans),
	)

	if numSpans < 0 {
		return nil, fmt.Errorf("pheye prediction failed")
	}

	entities := make([]Entity, 0, int(numSpans))
	for i := 0; i < int(numSpans); i++ {
		cSpan := cSpans[i]
		entities = append(entities, Entity{
			Start: int(cSpan.start),
			End:   int(cSpan.end),
			Label: C.GoString(cSpan.label),
			Score: float64(cSpan.score),
			Text:  C.GoString(cSpan.text),
		})
	}

	C.gliner_free_spans(&cSpans[0], numSpans)

	return entities, nil
}

func (c *cgoClient) Close() error {
	if c.ctx != nil {
		C.gliner_free(c.ctx)
		c.ctx = nil
	}
	return nil
}
