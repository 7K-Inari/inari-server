package renderer

import (
	"context"
	"fmt"

	"github.com/7K-Inari/inari-server/internal/types"
)

// stubHandler is the registered placeholder for source kinds that are not
// yet implemented (crossplane, kustomize). Registration keeps the dispatch
// table complete so enabling a kind later is purely additive.
type stubHandler struct{ kind types.SourceKind }

func (s stubHandler) Render(context.Context, types.SourceDescriptor, RenderParams) ([]RenderedFile, error) {
	return nil, fmt.Errorf("renderer: source kind %q: %w", s.kind, ErrNotSupported)
}
