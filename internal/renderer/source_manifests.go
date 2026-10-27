package renderer

import (
	"context"
	"errors"

	"github.com/7K-Inari/inari-server/internal/types"
)

// manifestsHandler materializes plain (optionally parameterized) YAML into
// <path>/manifests/ plus an Application sourced at that directory.
type manifestsHandler struct{}

func (manifestsHandler) Render(context.Context, types.SourceDescriptor, RenderParams) ([]RenderedFile, error) {
	return nil, errors.New("renderer: manifests handler not implemented")
}
