package stdfiles

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/claymod/claymod/internal/modules"
	"github.com/claymod/claymod/internal/playbook"
	"github.com/claymod/claymod/internal/proto"
)

// Fetch bounds: the control server downloads the body at compile time,
// so a runaway URL burns control-server resources, not the agent's.
const fetchTimeout = 60 * time.Second

// fetchMaxSize bounds one compile-time download (64 MiB); a var so
// tests can shrink it.
var fetchMaxSize = int64(64 << 20)

// FetchResource mirrors the std.files.Fetch PKL class.
type FetchResource struct {
	Type   string `json:"type"`
	Name   string `json:"name"`
	URL    string `json:"url"`
	Dest   string `json:"dest"`
	Sha256 string `json:"sha256"`
	Mode   string `json:"mode"`
	Owner  string `json:"owner"`
	Group  string `json:"group"`
	Backup bool   `json:"backup"`
}

// fetchClient is the HTTP client used for compile-time downloads
// (timeout-bounded; redirects are followed, like curl's default).
var fetchClient = &http.Client{Timeout: fetchTimeout}

// fetchContent downloads url and returns the body, enforcing the size
// cap and, when set, the sha256 (lowercase hex) digest.
func fetchContent(url, wantSha string) ([]byte, error) {
	resp, err := fetchClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, fetchMaxSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > fetchMaxSize {
		return nil, fmt.Errorf("body exceeds the %d MiB limit", fetchMaxSize>>20)
	}
	if wantSha != "" {
		digest := sha256.Sum256(body)
		sum := hex.EncodeToString(digest[:])
		if sum != strings.ToLower(wantSha) {
			return nil, fmt.Errorf("sha256 mismatch: got %s, want %s", sum, strings.ToLower(wantSha))
		}
	}
	return body, nil
}

// compileFetch downloads the body server-side and emits a File op —
// agents see nothing new: the content ships like Copy's.
func compileFetch(res playbook.Resource, ctx playbook.RenderContext) ([]proto.Op, error) {
	var r FetchResource
	if err := modules.DecodeResource(res, &r); err != nil {
		return nil, err
	}
	if r.URL == "" {
		return nil, fmt.Errorf("url is required")
	}
	if r.Dest == "" {
		return nil, fmt.Errorf("dest is required")
	}
	if err := playbook.ValidatePath(r.Dest); err != nil {
		return nil, err
	}
	if r.Sha256 != "" {
		if len(r.Sha256) != 64 {
			return nil, fmt.Errorf("sha256 must be 64 hex chars")
		}
		if _, err := hex.DecodeString(r.Sha256); err != nil {
			return nil, fmt.Errorf("sha256 must be hex: %v", err)
		}
	}
	body, err := fetchContent(r.URL, r.Sha256)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", r.URL, err)
	}
	return []proto.Op{{
		OpType: proto.OpTypeFile,
		File: &proto.FileOp{
			Path:    r.Dest,
			Content: string(body),
			Mode:    r.Mode,
			Owner:   r.Owner,
			Group:   r.Group,
			Ensure:  proto.EnsureFile,
			Backup:  r.Backup,
		},
	}}, nil
}

// init registers the std.files.Fetch compiler.
func init() {
	modules.Register("std.files.Fetch", modules.CompilerFunc(compileFetch))
}
