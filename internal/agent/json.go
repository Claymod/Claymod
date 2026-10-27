package agent

import (
	"encoding/json"
	"fmt"
)

func marshal(v any) (json.RawMessage, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("agent: marshal result: %w", err)
	}
	return raw, nil
}

func unmarshal(raw json.RawMessage, v any) error {
	if len(raw) == 0 {
		return fmt.Errorf("agent: missing params")
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("agent: parse params: %w", err)
	}
	return nil
}
