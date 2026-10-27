package agent

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"

	"github.com/claymod/claymod/internal/proto"
	"github.com/claymod/claymod/internal/util"
)

// getFile reads a file for the control server (debug/backup use).
func (a *Agent) getFile(params proto.FileParams) (*proto.FileInfo, *proto.Error) {
	if !filepath.IsAbs(params.Path) {
		return nil, &proto.Error{Code: proto.CodeBadRequest, Message: "path must be absolute"}
	}
	data, err := os.ReadFile(params.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, &proto.Error{Code: proto.CodeNotFound, Message: "no such file: " + params.Path}
		}
		return nil, &proto.Error{Code: proto.CodeInternal, Message: err.Error()}
	}
	info, err := os.Stat(params.Path)
	if err != nil {
		return nil, &proto.Error{Code: proto.CodeInternal, Message: err.Error()}
	}
	return &proto.FileInfo{
		Path:    params.Path,
		Content: data,
		Mode:    fmt.Sprintf("%04o", info.Mode().Perm()),
	}, nil
}

// putFile writes a file pushed by the control server.
func (a *Agent) putFile(params proto.FileParams) *proto.Error {
	if !filepath.IsAbs(params.Path) {
		return &proto.Error{Code: proto.CodeBadRequest, Message: "path must be absolute"}
	}
	mode := fs.FileMode(0o644)
	if params.Mode != "" {
		parsed, err := strconv.ParseUint(params.Mode, 8, 32)
		if err != nil {
			return &proto.Error{Code: proto.CodeBadRequest, Message: "invalid mode: " + params.Mode}
		}
		mode = fs.FileMode(parsed)
	}
	if err := util.WriteFileAtomic(params.Path, params.Content, mode); err != nil {
		return &proto.Error{Code: proto.CodeInternal, Message: err.Error()}
	}
	return nil
}
