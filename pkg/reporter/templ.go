package reporter

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
)

// WriteTemplToFile renders a templ component to a file
func WriteTemplToFile(component interface {
	Render(ctx context.Context, w io.Writer) error
}, path string,
) error {
	// Create a buffer to hold the rendered template
	buf := new(bytes.Buffer)

	// Render the template to the buffer
	if err := component.Render(context.Background(), buf); err != nil {
		return fmt.Errorf("failed to render template: %w", err)
	}

	// Write the buffer contents to the file
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		return fmt.Errorf("failed to write to file %s: %w", path, err)
	}

	return nil
}
