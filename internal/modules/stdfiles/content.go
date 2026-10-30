package stdfiles

import (
	"fmt"

	"github.com/claymod/claymod/internal/modules"
	"github.com/claymod/claymod/internal/playbook"
	"github.com/claymod/claymod/internal/proto"
)

// ContentResource mirrors the std.files.Content PKL class.
type ContentResource struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	Dest    string `json:"dest"`
	Mode    string `json:"mode"`
	Owner   string `json:"owner"`
	Group   string `json:"group"`
	Backup  bool   `json:"backup"`
}

// compileContent emits a File op with the inline content (empty content
// creates an empty file — the agent compares full contents).
func compileContent(res playbook.Resource, ctx playbook.RenderContext) ([]proto.Op, error) {
	var r ContentResource
	if err := modules.DecodeResource(res, &r); err != nil {
		return nil, err
	}
	if r.Dest == "" {
		return nil, fmt.Errorf("dest is required")
	}
	if err := playbook.ValidatePath(r.Dest); err != nil {
		return nil, err
	}
	return []proto.Op{{
		OpType: proto.OpTypeFile,
		File: &proto.FileOp{
			Path:    r.Dest,
			Content: r.Content,
			Mode:    r.Mode,
			Owner:   r.Owner,
			Group:   r.Group,
			Ensure:  proto.EnsureFile,
			Backup:  r.Backup,
		},
	}}, nil
}

// init registers the std.files.Content compiler (the other std.files
// compilers register in stdfiles.go and the files below).
func init() {
	modules.Register("std.files.Content", modules.CompilerFunc(compileContent))
}
