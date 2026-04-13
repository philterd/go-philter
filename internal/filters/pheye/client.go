package pheye

// Entity is a single entity returned by the PhEye model.
type Entity struct {
	Start int     `json:"start"`
	End   int     `json:"end"`
	Label string  `json:"label"`
	Score float64 `json:"score"`
	Text  string  `json:"text"`
}

// Client defines the interface for a PhEye model client.
type Client interface {
	Predict(text string, labels []string, threshold float32) ([]Entity, error)
	Close() error
}
