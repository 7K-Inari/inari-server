package renderer

import (
	"context"
	"errors"

	"github.com/7K-Inari/inari-server/internal/types"
)

// kroHandler renders stacked composites: the KRO instance manifest is
// materialized into the repo and the Application source is the git path
// (today's orchestrator render.go behavior, generalized).
type kroHandler struct {
	resolve ResolveRGDFunc
}

func (*kroHandler) Render(context.Context, types.SourceDescriptor, RenderParams) ([]RenderedFile, error) {
	return nil, errors.New("renderer: kro handler not implemented")
}
