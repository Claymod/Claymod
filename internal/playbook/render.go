package playbook

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"
)

// RenderContext supplies per-host data to template rendering.
type RenderContext struct {
	// Host is the hostname being rendered for.
	Host string
	// Vars are the playbook's per-host variables (merged with each
	// Template resource's own vars).
	Vars map[string]string
}

// RenderTemplate renders a template file for one host. The template
// receives the merged variables as `.Vars` and the host as `.Host`.
func RenderTemplate(templatePath string, ctx RenderContext) (string, error) {
	data, err := os.ReadFile(templatePath)
	if err != nil {
		return "", fmt.Errorf("read template %s: %w", templatePath, err)
	}
	return RenderTemplateString(string(data), ctx)
}

// RenderTemplateString renders template text for one host.
func RenderTemplateString(text string, ctx RenderContext) (string, error) {
	vars := map[string]string{}
	for k, v := range ctx.Vars {
		vars[k] = v
	}
	data := struct {
		Host string
		Vars map[string]string
	}{Host: ctx.Host, Vars: vars}

	tmpl, err := template.New("claymod").Option("missingkey=error").Parse(text)
	if err != nil {
		return "", fmt.Errorf("parse template: %w", err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("execute template: %w", err)
	}
	return buf.String(), nil
}

// MergedVars merges the playbook's per-host vars with a resource's own
// template vars (resource vars win on conflicts).
func MergedVars(playbookVars map[string]string, resourceVars map[string]string) map[string]string {
	merged := make(map[string]string, len(playbookVars)+len(resourceVars))
	for k, v := range playbookVars {
		merged[k] = v
	}
	for k, v := range resourceVars {
		merged[k] = v
	}
	return merged
}

// ResolveSource resolves a source path relative to the playbook's
// directory, returning an absolute path.
func ResolveSource(playbookDir, source string) string {
	if filepath.IsAbs(source) {
		return source
	}
	return filepath.Join(playbookDir, source)
}

// ValidatePath rejects non-absolute destination paths.
func ValidatePath(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("path must be absolute: %s", path)
	}
	return nil
}

// ValidateHosts checks the host selection against the available hosts
// and returns the matched subset. Exact names only in v1.
func ValidateHosts(playbookHosts []string, available []string) ([]string, error) {
	if len(playbookHosts) == 0 {
		return available, nil
	}
	avail := make(map[string]bool, len(available))
	for _, h := range available {
		avail[h] = true
	}
	var matched []string
	var missing []string
	for _, want := range playbookHosts {
		if avail[want] {
			matched = append(matched, want)
		} else {
			missing = append(missing, want)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("playbook targets unknown host(s): %s", strings.Join(missing, ", "))
	}
	return matched, nil
}
