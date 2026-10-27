package renderer

import (
	"context"
	"errors"

	"github.com/7K-Inari/inari-server/internal/types"
)

// helmHandler renders a direct upstream chart (platform addons like
// cert-manager): the Application's spec.sources pair the upstream helm
// repo/chart/version with a git-managed values file (multi-source, the
// ArgoCD-idiomatic pattern with clean diff history).
type helmHandler struct{}

func (helmHandler) Render(context.Context, types.SourceDescriptor, RenderParams) ([]RenderedFile, error) {
	return nil, errors.New("renderer: helm handler not implemented")
}
