package proto

import "encoding/json"

// Method names spoken on the wire.
const (
	MethodPing    = "Ping"
	MethodFacts   = "Facts"
	MethodApply   = "Apply"
	MethodExec    = "Exec"
	MethodGetFile = "GetFile"
	MethodPutFile = "PutFile"
)

// Request is sent by the control server to an agent.
type Request struct {
	ID     string          `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

// Response is sent by the agent to the control server. Exactly one of
// Result and Error is set for a normal completion.
type Response struct {
	ID     string          `json:"id"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *Error          `json:"error,omitempty"`
}

// Error is a structured RPC error.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	return e.Code + ": " + e.Message
}

// Error codes used on the wire.
const (
	CodeBadRequest   = "bad_request"
	CodeNotFound     = "not_found"
	CodeInternal     = "internal"
	CodeTimeout      = "timeout"
	CodeUnsupported  = "unsupported_method"
	CodeUnauthorized = "unauthorized"
)

// ApplyParams is the parameter block for MethodApply.
type ApplyParams struct {
	Ops     []Op  `json:"ops"`
	Check   bool  `json:"check,omitempty"`
	Timeout int64 `json:"timeout_ms,omitempty"`
}

// ApplyResult streams one entry per op followed by a summary; the summary
// is the last ApplyResult with Summary=true.
type ApplyResult struct {
	Index   int    `json:"index"`
	OpType  string `json:"op_type,omitempty"`
	Changed bool   `json:"changed"`
	Failed  bool   `json:"failed"`
	Message string `json:"message,omitempty"`
	Stdout  string `json:"stdout,omitempty"`
	Stderr  string `json:"stderr,omitempty"`

	// Summary marks the final aggregate result of an Apply run.
	Summary bool `json:"summary,omitempty"`
	OK      int  `json:"ok,omitempty"`
	// Changes and Failures count the per-op results when Summary is set.
	Changes  int `json:"changes,omitempty"`
	Failures int `json:"failures,omitempty"`
}

// FactsResult is the response to MethodFacts.
type FactsResult struct {
	Hostname string            `json:"hostname"`
	OS       string            `json:"os"`
	Arch     string            `json:"arch"`
	Kernel   string            `json:"kernel,omitempty"`
	Extra    map[string]string `json:"extra,omitempty"`
}

// ExecParams is the parameter block for MethodExec (ad-hoc command).
type ExecParams struct {
	Argv    []string          `json:"argv,omitempty"`
	Shell   string            `json:"shell,omitempty"`
	Cwd     string            `json:"cwd,omitempty"`
	Env     map[string]string `json:"env,omitempty"`
	Timeout int64             `json:"timeout_ms,omitempty"`
}

// ExecResult is the response to MethodExec.
type ExecResult struct {
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
}

// FileParams addresses a file for GetFile/PutFile.
type FileParams struct {
	Path    string `json:"path"`
	Content []byte `json:"content,omitempty"`
	Mode    string `json:"mode,omitempty"`
}

// FileInfo describes a file returned by GetFile.
type FileInfo struct {
	Path    string `json:"path"`
	Content []byte `json:"content"`
	Mode    string `json:"mode"`
}

// PingResult is the response to MethodPing.
type PingResult struct {
	Version uint8  `json:"version"`
	Agent   string `json:"agent,omitempty"`
}

// Op is one primitive operation. Exactly one of File, Command or Service
// is set; OpType is a convenience discriminator that agents and the runner
// use for reporting. Ops may only reference absolute paths.
type Op struct {
	OpType  string     `json:"op_type"`
	File    *FileOp    `json:"file,omitempty"`
	Command *CommandOp `json:"command,omitempty"`
	Service *ServiceOp `json:"service,omitempty"`
}

// OpType values for Op.OpType.
const (
	OpTypeFile    = "file"
	OpTypeCommand = "command"
	OpTypeService = "service"
)

// FileOp manages a file or directory. Content is rendered server-side.
type FileOp struct {
	Path    string `json:"path"`
	Content string `json:"content,omitempty"`
	Mode    string `json:"mode,omitempty"`
	Owner   string `json:"owner,omitempty"`
	Group   string `json:"group,omitempty"`
	Ensure  string `json:"ensure,omitempty"` // file|directory|absent (default file)
	Backup  bool   `json:"backup,omitempty"`
}

// Ensure values for FileOp.
const (
	EnsureFile      = "file"
	EnsureDirectory = "directory"
	EnsureAbsent    = "absent"
)

// CommandOp runs a command. Exactly one of Argv and Shell is set. onlyIf /
// unlessIf are shell commands deciding whether to run at all; creates /
// removes are paths whose existence skips or forces the run.
type CommandOp struct {
	Argv     []string          `json:"argv,omitempty"`
	Shell    string            `json:"shell,omitempty"`
	Cwd      string            `json:"cwd,omitempty"`
	Env      map[string]string `json:"env,omitempty"`
	User     string            `json:"user,omitempty"`
	OnlyIf   string            `json:"only_if,omitempty"`
	UnlessIf string            `json:"unless_if,omitempty"`
	Creates  string            `json:"creates,omitempty"`
	Removes  string            `json:"removes,omitempty"`
	Timeout  int64             `json:"timeout_ms,omitempty"`
}

// ServiceOp manages a systemd unit. State is started|stopped|restarted|reloaded
// (empty means leave running state alone).
type ServiceOp struct {
	Unit    string `json:"unit"`
	State   string `json:"state,omitempty"`
	Enabled *bool  `json:"enabled,omitempty"`
}

// State values for ServiceOp.
const (
	StateStarted   = "started"
	StateStopped   = "stopped"
	StateRestarted = "restarted"
	StateReloaded  = "reloaded"
)
