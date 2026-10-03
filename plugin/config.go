package plugin

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// MapConfig is a Config over a decoded options map. Option structs use json
// tags.
type MapConfig map[string]any

// Decode decodes the options into v. An unknown key is an error.
func (c MapConfig) Decode(v any) error {
	if c == nil {
		return nil
	}
	b, err := json.Marshal(map[string]any(c))
	if err != nil {
		return fmt.Errorf("encode plugin options: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("decode plugin options: %w", err)
	}
	return nil
}
