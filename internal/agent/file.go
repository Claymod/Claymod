package agent

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/claymod/claymod/internal/proto"
	"github.com/claymod/claymod/internal/util"
)

// apply runs ops in order, streaming one response per op and finishing
// with a summary. It never aborts on a failing op — all ops run and the
// summary reports the counts (the runner decides host policy).
func (a *Agent) apply(ctx context.Context, conn *proto.Conn, id string, params proto.ApplyParams) error {
	timeout := a.opLimit
	if params.Timeout > 0 {
		timeout = time.Duration(params.Timeout) * time.Millisecond
	}
	var ok, changes, failures int
	for idx, op := range params.Ops {
		if ctx.Err() != nil {
			return replyErr(conn, id, proto.CodeTimeout, "agent shutting down")
		}
		res := a.runOp(ctx, op, params.Check, timeout)
		res.Index = idx
		switch {
		case res.Failed:
			failures++
		case res.Changed:
			changes++
			ok++
		default:
			ok++
		}
		raw, err := marshal(res)
		if err != nil {
			return err
		}
		if err := conn.Send(proto.Response{ID: id, Result: raw}); err != nil {
			return err
		}
	}
	summary := proto.ApplyResult{
		Summary:  true,
		OK:       ok,
		Changes:  changes,
		Failures: failures,
	}
	raw, err := marshal(summary)
	if err != nil {
		return err
	}
	return conn.Send(proto.Response{ID: id, Result: raw})
}

// runOp dispatches one primitive op to its applier.
func (a *Agent) runOp(ctx context.Context, op proto.Op, check bool, timeout time.Duration) proto.ApplyResult {
	opType := op.OpType
	switch {
	case opType == proto.OpTypeFile && op.File != nil:
		return a.applyFile(*op.File, check)
	case opType == proto.OpTypeCommand && op.Command != nil:
		return a.applyCommand(ctx, *op.Command, check, timeout)
	case opType == proto.OpTypeService && op.Service != nil:
		return a.applyService(ctx, *op.Service, check)
	default:
		return proto.ApplyResult{
			OpType: opType,
			Failed: true,
			Message: fmt.Sprintf("op %d: malformed or unsupported op type %q",
				-1, opType),
		}
	}
}

// applyFile implements the File op with check-mode support.
func (a *Agent) applyFile(op proto.FileOp, check bool) proto.ApplyResult {
	res := proto.ApplyResult{OpType: proto.OpTypeFile}
	if !filepath.IsAbs(op.Path) {
		res.Failed = true
		res.Message = "file path must be absolute: " + op.Path
		return res
	}
	ensure := op.Ensure
	if ensure == "" {
		ensure = proto.EnsureFile
	}
	mode := os.FileMode(0o644)
	if op.Mode != "" {
		parsed, err := strconv.ParseUint(op.Mode, 8, 32)
		if err != nil {
			res.Failed = true
			res.Message = fmt.Sprintf("invalid mode %q: %v", op.Mode, err)
			return res
		}
		mode = os.FileMode(parsed)
	}

	info, statErr := os.Stat(op.Path)
	exists := statErr == nil

	switch ensure {
	case proto.EnsureAbsent:
		if !exists {
			res.Message = "already absent"
			return res
		}
		if check {
			res.Changed = true
			res.Message = "would remove " + op.Path
			return res
		}
		if err := os.RemoveAll(op.Path); err != nil {
			res.Failed = true
			res.Message = "remove: " + err.Error()
			return res
		}
		res.Changed = true
		res.Message = "removed " + op.Path
		return res

	case proto.EnsureDirectory:
		if exists && !info.IsDir() {
			res.Failed = true
			res.Message = op.Path + " exists and is not a directory"
			return res
		}
		if !exists {
			if check {
				res.Changed = true
				res.Message = "would create directory " + op.Path
				return res
			}
			if err := os.MkdirAll(op.Path, mode); err != nil {
				res.Failed = true
				res.Message = "mkdir: " + err.Error()
				return res
			}
			res.Changed = true
			res.Message = "created directory " + op.Path
			return res
		}
		// Exists: check mode bits.
		if info.Mode().Perm() != mode.Perm() {
			if check {
				res.Changed = true
				res.Message = fmt.Sprintf("would chmod %s to %04o", op.Path, mode.Perm())
				return res
			}
			if err := os.Chmod(op.Path, mode); err != nil {
				res.Failed = true
				res.Message = "chmod: " + err.Error()
				return res
			}
			res.Changed = true
			res.Message = fmt.Sprintf("chmod %s to %04o", op.Path, mode.Perm())
			return res
		}
		res.Message = "already a directory"
		return res

	default: // proto.EnsureFile
		content := []byte(op.Content)
		if exists {
			if info.IsDir() {
				res.Failed = true
				res.Message = op.Path + " exists and is a directory"
				return res
			}
			current, err := os.ReadFile(op.Path)
			if err != nil {
				res.Failed = true
				res.Message = "read: " + err.Error()
				return res
			}
			modeDiffers := info.Mode().Perm() != mode.Perm()
			if string(current) == string(content) && !modeDiffers && !ownershipDiffers(info, op) {
				res.Message = "already up to date"
				return res
			}
			if check {
				res.Changed = true
				res.Message = "would update " + op.Path
				return res
			}
			if op.Backup {
				backupPath := op.Path + ".bak"
				if err := util.CopyFile(op.Path, backupPath); err != nil {
					res.Failed = true
					res.Message = "backup: " + err.Error()
					return res
				}
			}
		} else if check {
			res.Changed = true
			res.Message = "would create " + op.Path
			return res
		}

		if check {
			// Unreachable in practice (handled above); kept for clarity.
			res.Changed = true
			return res
		}
		if err := util.WriteFileAtomic(op.Path, content, mode); err != nil {
			res.Failed = true
			res.Message = "write: " + err.Error()
			return res
		}
		if rpcErr := applyOwnership(op); rpcErr != nil {
			res.Failed = true
			res.Message = "ownership: " + rpcErr.Error()
			return res
		}
		res.Changed = true
		res.Message = "wrote " + op.Path
		return res
	}
}

// ownershipDiffers reports whether the file's uid/gid differ from what the
// op requests. When the op names no owner/group, ownership is ignored.
func ownershipDiffers(info fs.FileInfo, op proto.FileOp) bool {
	if op.Owner == "" && op.Group == "" {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	if op.Owner != "" {
		uid, err := lookupUID(op.Owner)
		if err != nil || int(stat.Uid) != uid {
			return true
		}
	}
	if op.Group != "" {
		gid, err := lookupGID(op.Group)
		if err != nil || int(stat.Gid) != gid {
			return true
		}
	}
	return false
}

// applyOwnership sets uid/gid after a write. It is a no-op when the op
// names no owner or group.
func applyOwnership(op proto.FileOp) error {
	if op.Owner == "" && op.Group == "" {
		return nil
	}
	uid := -1
	gid := -1
	if op.Owner != "" {
		parsed, err := lookupUID(op.Owner)
		if err != nil {
			return err
		}
		uid = parsed
	}
	if op.Group != "" {
		parsed, err := lookupGID(op.Group)
		if err != nil {
			return err
		}
		gid = parsed
	}
	if err := os.Chown(op.Path, uid, gid); err != nil {
		return err
	}
	return nil
}

// lookupUID resolves a numeric uid or a user name via /etc/passwd.
// Parsing /etc/passwd directly avoids cgo and cross-compilation issues.
func lookupUID(user string) (int, error) {
	if uid, err := strconv.Atoi(user); err == nil {
		return uid, nil
	}
	entry, err := lookupPasswdEntry(user)
	if err != nil {
		return 0, fmt.Errorf("user %q: %w", user, err)
	}
	uid, err := strconv.Atoi(entry)
	if err != nil {
		return 0, fmt.Errorf("user %q has invalid uid %q", user, entry)
	}
	return uid, nil
}

// lookupGID resolves a numeric gid or a group name via /etc/group.
func lookupGID(group string) (int, error) {
	if gid, err := strconv.Atoi(group); err == nil {
		return gid, nil
	}
	entry, err := lookupGroupEntry(group)
	if err != nil {
		return 0, fmt.Errorf("group %q: %w", group, err)
	}
	gid, err := strconv.Atoi(entry)
	if err != nil {
		return 0, fmt.Errorf("group %q has invalid gid %q", group, entry)
	}
	return gid, nil
}

// lookupPasswdEntry returns the uid field for a user in /etc/passwd.
func lookupPasswdEntry(user string) (string, error) {
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) >= 3 && fields[0] == user {
			return fields[2], nil
		}
	}
	return "", errors.New("not found in /etc/passwd")
}

// lookupGroupEntry returns the gid field for a group in /etc/group.
func lookupGroupEntry(group string) (string, error) {
	data, err := os.ReadFile("/etc/group")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) >= 3 && fields[0] == group {
			return fields[2], nil
		}
	}
	return "", errors.New("not found in /etc/group")
}
