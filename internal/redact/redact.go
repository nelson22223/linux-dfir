package redact

import (
	"regexp"
	"strings"
)

const placeholder = "[redacted]"

var (
	urlCredentialPattern = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.-]*://)([^/?#\s@]+@)`)
	querySecretPattern   = regexp.MustCompile(`(?i)([?&](?:[^=&\s]*)(?:password|passwd|token|secret|credential|private[_-]?key|pre[_-]?shared[_-]?key|presharedkey|psk|api[_-]?key|auth[_-]?key)(?:[^=&\s]*)=)([^&#\s]+)`)
	quotedAssignPattern  = regexp.MustCompile(`(?i)(\b[A-Za-z0-9_.-]*(?:password|passwd|token|secret|credential|private[_-]?key|pre[_-]?shared[_-]?key|presharedkey|psk|api[_-]?key|auth[_-]?key)[A-Za-z0-9_.-]*\s*=\s*)(["'` + "`" + `])([^"'` + "`" + `]+)(["'` + "`" + `])`)
	assignmentPattern    = regexp.MustCompile(`(?i)(\b[A-Za-z0-9_.-]*(?:password|passwd|token|secret|credential|private[_-]?key|pre[_-]?shared[_-]?key|presharedkey|psk|api[_-]?key|auth[_-]?key)[A-Za-z0-9_.-]*\s*=\s*)([^\s"'` + "`" + `]+)`)
	quotedOptionPattern  = regexp.MustCompile(`(?i)(--?[A-Za-z0-9_.-]*(?:password|passwd|token|secret|credential|private[_-]?key|pre[_-]?shared[_-]?key|presharedkey|psk|api[_-]?key|auth[_-]?key)[A-Za-z0-9_.-]*(?:=|\s+))(["'` + "`" + `])([^"'` + "`" + `]+)(["'` + "`" + `])`)
	optionPattern        = regexp.MustCompile(`(?i)(--?[A-Za-z0-9_.-]*(?:password|passwd|token|secret|credential|private[_-]?key|pre[_-]?shared[_-]?key|presharedkey|psk|api[_-]?key|auth[_-]?key)[A-Za-z0-9_.-]*(?:=|\s+))([^\s"'` + "`" + `]+)`)
	privateKeyBlock      = regexp.MustCompile(`(?is)-+BEGIN [A-Z0-9 ]*PRIVATE KEY-+.*?-+END [A-Z0-9 ]*PRIVATE KEY-+`)
	privateKeyMarker     = regexp.MustCompile(`(?i)-*BEGIN [A-Z0-9 ]*PRIVATE KEY-*|-*END [A-Z0-9 ]*PRIVATE KEY-*`)
)

func Placeholder() string {
	return placeholder
}

func SensitiveKey(key string) bool {
	key = strings.ToLower(key)
	replacer := strings.NewReplacer("-", "_", ".", "_", " ", "_")
	key = replacer.Replace(key)
	for _, token := range []string{"password", "passwd", "token", "secret", "credential", "privatekey", "private_key", "presharedkey", "pre_shared_key", "psk", "api_key", "apikey", "authkey", "auth_key"} {
		if strings.Contains(key, token) {
			return true
		}
	}
	return false
}

func Value(key, value string) string {
	if SensitiveKey(key) {
		return placeholder
	}
	return Text(value)
}

func Text(value string) string {
	value = privateKeyBlock.ReplaceAllString(value, placeholder)
	value = urlCredentialPattern.ReplaceAllString(value, `${1}`+placeholder+"@")
	value = querySecretPattern.ReplaceAllString(value, `${1}`+placeholder)
	value = quotedAssignPattern.ReplaceAllString(value, `${1}${2}`+placeholder+`${4}`)
	value = assignmentPattern.ReplaceAllString(value, `${1}`+placeholder)
	value = quotedOptionPattern.ReplaceAllString(value, `${1}${2}`+placeholder+`${4}`)
	value = optionPattern.ReplaceAllString(value, `${1}`+placeholder)
	value = privateKeyMarker.ReplaceAllString(value, placeholder)
	return value
}

func Values(key string, values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, Value(key, value))
	}
	return out
}

func Texts(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, Text(value))
	}
	return out
}

func Args(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	redactNext := false
	for _, value := range values {
		if redactNext {
			out = append(out, placeholder)
			redactNext = false
			continue
		}
		out = append(out, Text(value))
		option := strings.TrimLeft(value, "-")
		option, _, _ = strings.Cut(option, "=")
		if strings.HasPrefix(value, "-") && SensitiveKey(option) && !strings.Contains(value, "=") {
			redactNext = true
		}
	}
	return out
}

func MapValues(values map[string][]string) map[string][]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string][]string, len(values))
	for key, vals := range values {
		out[key] = Values(key, vals)
	}
	return out
}

func StringMapValues(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = Value(key, value)
	}
	return out
}
