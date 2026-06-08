package logs

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"linux-dfir/internal/collectors/common"
	"linux-dfir/internal/evidence"
	"linux-dfir/internal/output"
	"linux-dfir/internal/redact"
)

const (
	collector              = "logs"
	logEventsRel           = "facts/log_events.jsonl"
	authEventsRel          = "facts/auth_events.jsonl"
	loginEventsRel         = "facts/login_events.jsonl"
	sessionObsRel          = "facts/session_observations.jsonl"
	auditRel               = "facts/audit_events.jsonl"
	journalRel             = "facts/journal_events.jsonl"
	maxCopyBytes           = 64 * 1024 * 1024
	maxParseLines          = 20000
	defaultJournalMaxLines = 5000
)

var (
	filesystemRoot   = "/"
	journalTimeout   = 5 * time.Second
	journalMaxLines  = defaultJournalMaxLines
	journalRunner    = common.RunCommand
	syslogPattern    = regexp.MustCompile(`^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:]+):\s?(.*)$`)
	isoSyslogPattern = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\S+)\s+(\S+)\s+([^:]+):\s?(.*)$`)
	auditKVPattern   = regexp.MustCompile(`(\w+)=("[^"]*"|[^\s\x1d]+)`)
)

type Options struct {
	JournalMaxLines int
}

func Configure(options Options) {
	journalMaxLines = defaultJournalMaxLines
	if options.JournalMaxLines > 0 {
		journalMaxLines = options.JournalMaxLines
	}
}

type LogEvent struct {
	evidence.RecordMeta
	Exists        bool              `json:"exists"`
	AbsentReason  string            `json:"absent_reason,omitempty"`
	LogType       string            `json:"log_type,omitempty"`
	EventType     string            `json:"event_type,omitempty"`
	RecordSubtype string            `json:"record_subtype,omitempty"`
	SourceFile    string            `json:"source_file,omitempty"`
	LineNumber    int               `json:"line_number,omitempty"`
	Timestamp     *time.Time        `json:"timestamp,omitempty"`
	TimeInferred  bool              `json:"time_inferred,omitempty"`
	Hostname      string            `json:"hostname,omitempty"`
	Service       string            `json:"service,omitempty"`
	PID           int               `json:"pid,omitempty"`
	SessionID     int               `json:"login_session_id,omitempty"`
	User          string            `json:"user,omitempty"`
	RemoteAddr    string            `json:"remote_addr,omitempty"`
	Command       string            `json:"command,omitempty"`
	Message       string            `json:"message,omitempty"`
	Fields        map[string]string `json:"fields,omitempty"`
	RawCopyRef    string            `json:"raw_copy_ref,omitempty"`
	Sensitive     bool              `json:"sensitive"`
}

type LoginEvent struct {
	evidence.RecordMeta
	Exists          bool       `json:"exists"`
	AbsentReason    string     `json:"absent_reason,omitempty"`
	LogType         string     `json:"log_type,omitempty"`
	EventType       string     `json:"event_type,omitempty"`
	SourceFile      string     `json:"source_file,omitempty"`
	RecordIndex     int        `json:"record_index,omitempty"`
	Timestamp       *time.Time `json:"timestamp,omitempty"`
	TimeInferred    bool       `json:"time_inferred,omitempty"`
	EndTimestamp    *time.Time `json:"end_timestamp,omitempty"`
	DurationSeconds int64      `json:"duration_seconds,omitempty"`
	User            string     `json:"user,omitempty"`
	UID             int        `json:"uid,omitempty"`
	TTY             string     `json:"tty,omitempty"`
	ID              string     `json:"id,omitempty"`
	RemoteHost      string     `json:"remote_host,omitempty"`
	RemoteAddr      string     `json:"remote_addr,omitempty"`
	PID             int        `json:"pid,omitempty"`
	SessionID       int        `json:"login_session_id,omitempty"`
	ExitTermination int        `json:"exit_termination,omitempty"`
	ExitStatus      int        `json:"exit_status,omitempty"`
	RawCopyRef      string     `json:"raw_copy_ref,omitempty"`
	Sensitive       bool       `json:"sensitive"`
}

type SessionObservation struct {
	evidence.RecordMeta
	Exists          bool       `json:"exists"`
	ObservationType string     `json:"observation_type"`
	EventType       string     `json:"event_type,omitempty"`
	LogType         string     `json:"log_type,omitempty"`
	SourceFile      string     `json:"source_file,omitempty"`
	LineNumber      int        `json:"line_number,omitempty"`
	RecordIndex     int        `json:"record_index,omitempty"`
	Timestamp       *time.Time `json:"timestamp,omitempty"`
	TimeInferred    bool       `json:"time_inferred,omitempty"`
	SessionKey      string     `json:"session_key,omitempty"`
	User            string     `json:"user,omitempty"`
	UID             int        `json:"uid,omitempty"`
	ActorUser       string     `json:"actor_user,omitempty"`
	TargetUser      string     `json:"target_user,omitempty"`
	TTY             string     `json:"tty,omitempty"`
	PID             int        `json:"pid,omitempty"`
	SessionID       int        `json:"login_session_id,omitempty"`
	RemoteHost      string     `json:"remote_host,omitempty"`
	RemoteAddr      string     `json:"remote_addr,omitempty"`
	Service         string     `json:"service,omitempty"`
	Command         string     `json:"command,omitempty"`
	CWD             string     `json:"cwd,omitempty"`
	RawCopyRef      string     `json:"raw_copy_ref,omitempty"`
	Sensitive       bool       `json:"sensitive"`
}

type JournalEvent struct {
	evidence.RecordMeta
	Exists             bool       `json:"exists"`
	AbsentReason       string     `json:"absent_reason,omitempty"`
	RecordSubtype      string     `json:"record_subtype,omitempty"`
	Status             string     `json:"status,omitempty"`
	Error              string     `json:"error,omitempty"`
	Command            string     `json:"command,omitempty"`
	LineNumber         int        `json:"line_number,omitempty"`
	Timestamp          *time.Time `json:"timestamp,omitempty"`
	Message            string     `json:"message,omitempty"`
	Unit               string     `json:"unit,omitempty"`
	SyslogIdentifier   string     `json:"syslog_identifier,omitempty"`
	PID                *int       `json:"pid,omitempty"`
	UID                *int       `json:"uid,omitempty"`
	GID                *int       `json:"gid,omitempty"`
	BootID             string     `json:"boot_id,omitempty"`
	Priority           *int       `json:"priority,omitempty"`
	Transport          string     `json:"transport,omitempty"`
	Cursor             string     `json:"cursor,omitempty"`
	MonotonicTimestamp string     `json:"monotonic_timestamp,omitempty"`
	RawCopyRef         string     `json:"raw_copy_ref,omitempty"`
	Sensitive          bool       `json:"sensitive"`
}

type rawLog struct {
	SourcePath string
	ActualPath string
	LogType    string
	Parse      bool
}

type copiedLog struct {
	rawLog
	RawCopyRef string
	RawAbsPath string
	LegacyRef  string
}

type utmpLayout struct {
	Size       int
	TimeOffset int
	TimeSize   int
	AddrOffset int
}

func Collect(ctx context.Context, out *output.Manager) error {
	logs := discoverLogs()
	if len(logs) == 0 {
		if err := writeAbsent(out, "no log files found"); err != nil {
			return err
		}
	} else {
		for _, log := range logs {
			if err := ctx.Err(); err != nil {
				return err
			}
			copied, err := copyLog(out, log)
			if err != nil {
				if !os.IsNotExist(err) {
					recordError(out, log.SourcePath, "file", relByLogType(log.LogType), err)
				}
				if err := writeAbsentForSource(out, log, err.Error()); err != nil {
					return err
				}
				continue
			}
			if !log.Parse {
				if err := writeRawCopyRecord(out, copied); err != nil {
					return err
				}
				if isLoginAccountingLog(log.LogType) {
					if err := parseLoginAccountingLog(out, copied); err != nil {
						recordError(out, log.SourcePath, "file", loginEventsRel, err)
					}
				}
				continue
			}
			if err := parseCopiedLog(out, copied); err != nil {
				recordError(out, log.SourcePath, "file", relByLogType(log.LogType), err)
			}
		}
	}
	return collectJournal(ctx, out)
}

func discoverLogs() []rawLog {
	var logs []rawLog
	for _, spec := range primaryLogSpecs() {
		spec.ActualPath = actualPath(spec.SourcePath)
		logs = append(logs, spec)
	}
	for _, spec := range []rawLog{
		{SourcePath: "/var/log/cron", LogType: "cron", Parse: true},
		{SourcePath: "/etc/audit/audit.rules", LogType: "audit_rules", Parse: false},
	} {
		addIfExists(&logs, spec)
	}
	for _, pattern := range []string{
		"/var/log/auth.log.*",
		"/var/log/secure.*",
		"/var/log/syslog.*",
		"/var/log/messages.*",
		"/var/log/audit/audit.log.*",
		"/var/log/cron.*",
		"/etc/audit/rules.d/*",
	} {
		for _, actual := range globActual(pattern) {
			source := displayPath(actual)
			addIfExists(&logs, rawLog{SourcePath: source, LogType: classifyLog(source), Parse: shouldParse(source)})
		}
	}
	sort.Slice(logs, func(i, j int) bool { return logs[i].SourcePath < logs[j].SourcePath })
	return dedupeLogs(logs)
}

func primaryLogSpecs() []rawLog {
	return []rawLog{
		{SourcePath: "/var/log/auth.log", LogType: "auth", Parse: true},
		{SourcePath: "/var/log/secure", LogType: "auth", Parse: true},
		{SourcePath: "/var/log/syslog", LogType: "syslog", Parse: true},
		{SourcePath: "/var/log/messages", LogType: "syslog", Parse: true},
		{SourcePath: "/var/log/audit/audit.log", LogType: "audit", Parse: true},
		{SourcePath: "/var/log/wtmp", LogType: "wtmp", Parse: false},
		{SourcePath: "/var/log/btmp", LogType: "btmp", Parse: false},
		{SourcePath: "/var/log/lastlog", LogType: "lastlog", Parse: false},
		{SourcePath: "/var/run/utmp", LogType: "utmp", Parse: false},
	}
}

func addIfExists(logs *[]rawLog, spec rawLog) {
	actual := actualPath(spec.SourcePath)
	if fileExists(actual) {
		spec.ActualPath = actual
		*logs = append(*logs, spec)
	}
}

func copyLog(out *output.Manager, log rawLog) (copiedLog, error) {
	data, err := readBounded(log.ActualPath, maxCopyBytes)
	if err != nil {
		return copiedLog{}, err
	}
	rawRel := filepath.Join("raw", "logs", sanitize(strings.TrimPrefix(log.SourcePath, "/")))
	legacyRel := filepath.Join("logs", sanitize(strings.TrimPrefix(log.SourcePath, "/")))
	if err := out.WriteAIFromSource(rawRel, data, collector, log.SourcePath, "file", "high"); err != nil {
		return copiedLog{}, err
	}
	if err := out.WriteLegacyFromSource(legacyRel, data, collector, log.SourcePath, "file", "high"); err != nil {
		return copiedLog{}, err
	}
	rawAbs, err := output.SafeJoin(out.Root(), filepath.Join("ai", rawRel))
	if err != nil {
		return copiedLog{}, err
	}
	return copiedLog{
		rawLog:     log,
		RawCopyRef: filepath.Join("ai", rawRel),
		RawAbsPath: rawAbs,
		LegacyRef:  filepath.Join("legacy", legacyRel),
	}, nil
}

func parseCopiedLog(out *output.Manager, log copiedLog) error {
	reader, err := readerFor(log.RawAbsPath)
	if err != nil {
		return err
	}
	defer reader.Close()
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		if lineNumber > maxParseLines {
			recordError(out, log.SourcePath, "file", relByLogType(log.LogType), fmt.Errorf("parse line limit reached: %d", maxParseLines))
			break
		}
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		var events []LogEvent
		if log.LogType == "audit" {
			events = append(events, ParseAuditLine(line)...)
		} else {
			if event, ok := ParseSyslogLine(line, time.Now().UTC().Year()); ok {
				events = append(events, event)
			}
		}
		for _, event := range events {
			event.RecordMeta = out.Meta(collector, relFor(event), log.SourcePath, "file", "high")
			event.Exists = true
			event.SourceFile = log.SourcePath
			event.LineNumber = lineNumber
			event.RawCopyRef = log.RawCopyRef
			event.Sensitive = true
			if event.LogType == "" {
				event.LogType = log.LogType
			}
			if event.EventType == "" {
				event.EventType = classifyEvent(event.Service, event.Message)
			}
			event = sanitizeLogEvent(event)
			if err := out.AppendAIJSONL(relFor(event), event, collector, log.SourcePath, "file", "high"); err != nil {
				return err
			}
			if observation, ok := sessionObservationFromLogEvent(event); ok {
				observation.RecordMeta = out.Meta(collector, sessionObsRel, log.SourcePath, "file", "high")
				if err := out.AppendAIJSONL(sessionObsRel, observation, collector, log.SourcePath, "file", "high"); err != nil {
					return err
				}
			}
			if event.Timestamp != nil {
				if err := out.Timeline(evidence.TimelineEvent{
					Collector:      collector,
					EventType:      event.EventType,
					Timestamp:      *event.Timestamp,
					SourcePath:     log.SourcePath,
					SourceType:     "file",
					SourceTrust:    "high",
					RawArtifactRef: log.RawCopyRef,
					Summary:        event.Message,
				}); err != nil {
					return err
				}
			}
		}
	}
	return scanner.Err()
}

func sanitizeLogEvent(event LogEvent) LogEvent {
	event.Command = redact.Text(event.Command)
	event.Message = redact.Text(event.Message)
	if len(event.Fields) > 0 {
		fields := make(map[string]string, len(event.Fields))
		for key, value := range event.Fields {
			fields[key] = redact.Value(key, value)
		}
		event.Fields = fields
	}
	return event
}

func collectJournal(ctx context.Context, out *output.Manager) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	limit := effectiveJournalMaxLines()
	args := []string{"-o", "json", "--no-pager", "-n", strconv.Itoa(limit)}
	runCtx, cancel := context.WithTimeout(ctx, journalTimeout)
	defer cancel()
	result := journalRunner(runCtx, "journalctl", args...)
	command := journalCommandLine(args)
	if result.Missing() {
		return writeJournalStatus(out, "absent", command, "journalctl not found", result.Err, 0)
	}
	if result.Err != nil {
		status := "error"
		if runCtx.Err() == context.DeadlineExceeded {
			status = "timeout"
		}
		errText := result.Err.Error()
		if len(result.Output) > 0 {
			errText = errText + ": " + strings.TrimSpace(string(result.Output))
		}
		return writeJournalStatus(out, status, command, errText, result.Err, 0)
	}
	rawRef, err := writeJournalRawOutput(out, command, result.Output)
	if err != nil {
		return err
	}
	return parseJournalOutput(out, command, rawRef, result.Output, limit)
}

func writeJournalRawOutput(out *output.Manager, command string, data []byte) (string, error) {
	rawRel := filepath.Join("raw", "logs", "journalctl_json.out")
	legacyRel := filepath.Join("logs", "journalctl_json.out")
	if err := out.WriteAIFromSource(rawRel, data, collector, command, "native_command", "medium"); err != nil {
		return "", err
	}
	if err := out.WriteLegacyFromSource(legacyRel, data, collector, command, "native_command", "medium"); err != nil {
		return "", err
	}
	return filepath.Join("ai", rawRel), nil
}

func parseJournalOutput(out *output.Manager, command, rawRef string, data []byte, limit int) error {
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	lineNumber := 0
	sawLine := false
	wroteEvent := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		sawLine = true
		lineNumber++
		if lineNumber > limit {
			return writeJournalStatus(out, "line_limit_reached", command, fmt.Sprintf("journal line limit reached: %d", limit), nil, lineNumber)
		}
		event, err := ParseJournalJSONLine(line)
		if err != nil {
			if err := writeJournalStatus(out, "parse_error", command, err.Error(), err, lineNumber); err != nil {
				return err
			}
			continue
		}
		event.RecordMeta = out.Meta(collector, journalRel, command, "native_command", "medium")
		event.Exists = true
		event.Command = redact.Text(command)
		event.LineNumber = lineNumber
		event.RawCopyRef = rawRef
		event.Sensitive = true
		if err := out.AppendAIJSONL(journalRel, event, collector, command, "native_command", "medium"); err != nil {
			return err
		}
		wroteEvent = true
	}
	if err := scanner.Err(); err != nil {
		return writeJournalStatus(out, "parse_error", command, err.Error(), err, lineNumber)
	}
	if sawLine && !wroteEvent {
		return nil
	}
	if !wroteEvent {
		return writeJournalStatus(out, "empty", command, "journalctl returned no events", nil, 0)
	}
	return nil
}

func effectiveJournalMaxLines() int {
	if journalMaxLines <= 0 {
		return defaultJournalMaxLines
	}
	return journalMaxLines
}

func ParseJournalJSONLine(line string) (JournalEvent, error) {
	var fields map[string]any
	if err := json.Unmarshal([]byte(line), &fields); err != nil {
		return JournalEvent{}, err
	}
	event := JournalEvent{
		Timestamp:          parseJournalTimestamp(firstJournalString(fields, "__REALTIME_TIMESTAMP", "_SOURCE_REALTIME_TIMESTAMP")),
		Message:            redact.Text(firstJournalString(fields, "MESSAGE")),
		Unit:               redact.Text(firstJournalString(fields, "_SYSTEMD_UNIT", "UNIT")),
		SyslogIdentifier:   redact.Text(firstJournalString(fields, "SYSLOG_IDENTIFIER")),
		PID:                journalIntPtr(firstJournalString(fields, "_PID", "SYSLOG_PID")),
		UID:                journalIntPtr(firstJournalString(fields, "_UID")),
		GID:                journalIntPtr(firstJournalString(fields, "_GID")),
		BootID:             firstJournalString(fields, "_BOOT_ID"),
		Priority:           journalIntPtr(firstJournalString(fields, "PRIORITY")),
		Transport:          firstJournalString(fields, "_TRANSPORT"),
		Cursor:             firstJournalString(fields, "__CURSOR"),
		MonotonicTimestamp: firstJournalString(fields, "__MONOTONIC_TIMESTAMP"),
		Sensitive:          true,
	}
	return event, nil
}

func writeJournalStatus(out *output.Manager, status, command, reason string, err error, lineNumber int) error {
	record := JournalEvent{
		RecordMeta:    out.Meta(collector, journalRel, command, "native_command", "medium"),
		Exists:        false,
		AbsentReason:  redact.Text(reason),
		RecordSubtype: "status",
		Status:        status,
		Command:       redact.Text(command),
		LineNumber:    lineNumber,
		Sensitive:     true,
	}
	if err != nil {
		record.Error = redact.Text(err.Error())
	}
	return out.AppendAIJSONL(journalRel, record, collector, command, "native_command", "medium")
}

func journalCommandLine(args []string) string {
	parts := append([]string{"journalctl"}, args...)
	return strings.Join(parts, " ")
}

func firstJournalString(fields map[string]any, names ...string) string {
	for _, name := range names {
		value := journalString(fields[name])
		if value != "" {
			return value
		}
	}
	return ""
}

func journalString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case float64:
		return strconv.FormatInt(int64(typed), 10)
	case []any:
		for _, item := range typed {
			if value := journalString(item); value != "" {
				return value
			}
		}
	}
	return ""
}

func journalIntPtr(value string) *int {
	if value == "" {
		return nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return nil
	}
	return &parsed
}

func parseJournalTimestamp(value string) *time.Time {
	if value == "" {
		return nil
	}
	usec, err := strconv.ParseInt(value, 10, 64)
	if err != nil || usec <= 0 {
		return parseISOTime(value)
	}
	t := time.Unix(usec/1_000_000, (usec%1_000_000)*1_000).UTC()
	return &t
}

func parseLoginAccountingLog(out *output.Manager, log copiedLog) error {
	data, err := readBounded(log.RawAbsPath, maxCopyBytes)
	if err != nil {
		return err
	}
	var events []LoginEvent
	switch log.LogType {
	case "wtmp", "btmp", "utmp":
		events = parseUtmpRecords(data, log.LogType)
	case "lastlog":
		events = parseLastlogRecords(data)
	default:
		return nil
	}
	for _, event := range events {
		event.RecordMeta = out.Meta(collector, loginEventsRel, log.SourcePath, "file", "high")
		event.Exists = true
		event.SourceFile = log.SourcePath
		event.RawCopyRef = log.RawCopyRef
		event.Sensitive = true
		if err := out.AppendAIJSONL(loginEventsRel, event, collector, log.SourcePath, "file", "high"); err != nil {
			return err
		}
		if observation, ok := sessionObservationFromLoginEvent(event); ok {
			observation.RecordMeta = out.Meta(collector, sessionObsRel, log.SourcePath, "file", "high")
			if err := out.AppendAIJSONL(sessionObsRel, observation, collector, log.SourcePath, "file", "high"); err != nil {
				return err
			}
		}
		if event.Timestamp != nil {
			if err := out.Timeline(evidence.TimelineEvent{
				Collector:      collector,
				EventType:      event.EventType,
				Timestamp:      *event.Timestamp,
				SourcePath:     log.SourcePath,
				SourceType:     "file",
				SourceTrust:    "high",
				RawArtifactRef: log.RawCopyRef,
				Summary:        loginTimelineSummary(event),
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

func parseUtmpRecords(data []byte, logType string) []LoginEvent {
	layout := chooseUtmpLayout(data)
	if layout.Size == 0 {
		return nil
	}
	events := make([]LoginEvent, 0, len(data)/layout.Size)
	for offset, index := 0, 0; offset+layout.Size <= len(data); offset, index = offset+layout.Size, index+1 {
		record := data[offset : offset+layout.Size]
		utType := int(int16(binary.LittleEndian.Uint16(record[0:2])))
		if utType < 1 || utType > 9 {
			continue
		}
		remoteHost := cString(record[76:332])
		remoteAddr := ""
		if ip := net.ParseIP(remoteHost); ip != nil {
			remoteAddr = ip.String()
		} else if logType == "btmp" || utType == 7 {
			remoteAddr = parseUtmpAddr(record[layout.AddrOffset : layout.AddrOffset+16])
		}
		event := LoginEvent{
			LogType:         logType,
			EventType:       utmpEventType(logType, utType),
			RecordIndex:     index,
			PID:             int(int32(binary.LittleEndian.Uint32(record[4:8]))),
			TTY:             cString(record[8:40]),
			ID:              cString(record[40:44]),
			User:            cString(record[44:76]),
			RemoteHost:      remoteHost,
			ExitTermination: int(int16(binary.LittleEndian.Uint16(record[332:334]))),
			ExitStatus:      int(int16(binary.LittleEndian.Uint16(record[334:336]))),
			SessionID:       int(int32(binary.LittleEndian.Uint32(record[336:340]))),
			RemoteAddr:      remoteAddr,
			Sensitive:       true,
		}
		if ts := parseUtmpTime(record, layout); ts != nil {
			event.Timestamp = ts
		}
		if shouldKeepUtmpEvent(event) {
			events = append(events, event)
		}
	}
	return events
}

func chooseUtmpLayout(data []byte) utmpLayout {
	candidates := []utmpLayout{
		{Size: 400, TimeOffset: 344, TimeSize: 8, AddrOffset: 360},
		{Size: 384, TimeOffset: 340, TimeSize: 4, AddrOffset: 348},
	}
	best := utmpLayout{}
	bestScore := -1
	for _, candidate := range candidates {
		if len(data) < candidate.Size {
			continue
		}
		score := plausibleUtmpCount(data, candidate)
		if score > bestScore {
			bestScore = score
			best = candidate
		}
	}
	return best
}

func plausibleUtmpCount(data []byte, layout utmpLayout) int {
	score := 0
	for offset := 0; offset+layout.Size <= len(data); offset += layout.Size {
		record := data[offset : offset+layout.Size]
		utType := int(int16(binary.LittleEndian.Uint16(record[0:2])))
		if utType < 1 || utType > 9 {
			continue
		}
		tty := cString(record[8:40])
		user := cString(record[44:76])
		host := cString(record[76:332])
		ts := parseUtmpTime(record, layout)
		if tty != "" || user != "" || host != "" || ts != nil {
			score++
		}
	}
	return score
}

func parseUtmpTime(record []byte, layout utmpLayout) *time.Time {
	if layout.TimeOffset+layout.TimeSize > len(record) {
		return nil
	}
	if layout.TimeSize == 8 {
		return parseUnixTime64(record[layout.TimeOffset : layout.TimeOffset+8])
	}
	return parseUnixTime32(record[layout.TimeOffset : layout.TimeOffset+4])
}

func parseLastlogRecords(data []byte) []LoginEvent {
	size := chooseLastlogRecordSize(data)
	if size == 0 {
		return nil
	}
	events := make([]LoginEvent, 0)
	for offset, uid := 0, 0; offset+size <= len(data); offset, uid = offset+size, uid+1 {
		record := data[offset : offset+size]
		ts, lineOffset := parseLastlogTimestamp(record, size)
		if ts == nil {
			continue
		}
		tty := cString(record[lineOffset : lineOffset+32])
		host := cString(record[lineOffset+32 : lineOffset+32+256])
		if tty == "" && host == "" {
			continue
		}
		event := LoginEvent{
			LogType:     "lastlog",
			EventType:   "last_login",
			RecordIndex: uid,
			UID:         uid,
			Timestamp:   ts,
			TTY:         tty,
			RemoteHost:  host,
			Sensitive:   true,
		}
		if ip := net.ParseIP(host); ip != nil {
			event.RemoteAddr = ip.String()
		}
		events = append(events, event)
	}
	return events
}

func ParseSyslogLine(line string, year int) (LogEvent, bool) {
	match := syslogPattern.FindStringSubmatch(line)
	if len(match) == 5 {
		ts := parseSyslogTime(match[1], year)
		return buildSyslogEvent(match[2], match[3], match[4], ts, ts != nil), true
	}
	match = isoSyslogPattern.FindStringSubmatch(line)
	if len(match) == 5 {
		ts := parseISOTime(match[1])
		return buildSyslogEvent(match[2], match[3], match[4], ts, false), true
	}
	return LogEvent{LogType: "syslog", EventType: "log_line", Message: line, Sensitive: true}, true
}

func buildSyslogEvent(hostname, rawService, message string, timestamp *time.Time, timeInferred bool) LogEvent {
	service, pid := splitService(rawService)
	fields := extractAuthFields(message, service)
	user := extractUser(message, service)
	if actor := fields["actor_user"]; actor != "" {
		user = actor
	} else if target := fields["target_user"]; user == "" && target != "" {
		user = target
	}
	event := LogEvent{
		LogType:      "syslog",
		EventType:    classifyEvent(service, message),
		Timestamp:    timestamp,
		TimeInferred: timeInferred,
		Hostname:     hostname,
		Service:      service,
		PID:          pid,
		Message:      message,
		User:         user,
		RemoteAddr:   extractRemoteAddr(message),
		Command:      extractCommand(message),
		Fields:       fields,
		Sensitive:    true,
	}
	if isAuthService(service) || event.EventType == "sudo_command" || event.EventType == "su_session" {
		event.LogType = "auth"
	}
	return event
}

func ParseAuditLine(line string) []LogEvent {
	fields := parseAuditFields(line)
	ts := parseAuditTime(fields["msg"])
	return []LogEvent{{
		LogType:    "audit",
		EventType:  auditEventType(fields),
		Timestamp:  ts,
		Service:    "auditd",
		PID:        parsePositiveInt(fields["pid"]),
		SessionID:  parsePositiveInt(fields["ses"]),
		User:       firstNonEmpty(fields["acct"], fields["auid"], fields["uid"]),
		RemoteAddr: auditRemoteAddr(fields["addr"]),
		Command:    trimQuotes(fields["comm"]),
		Message:    line,
		Fields:     fields,
		Sensitive:  true,
	}}
}

func parseSyslogTime(value string, year int) *time.Time {
	t, err := time.ParseInLocation("Jan 2 15:04:05 2006", value+" "+strconv.Itoa(year), time.Local)
	if err != nil {
		return nil
	}
	utc := t.UTC()
	return &utc
}

func parseISOTime(value string) *time.Time {
	t, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return nil
	}
	utc := t.UTC()
	return &utc
}

func parseUnixTime32(data []byte) *time.Time {
	if len(data) < 4 {
		return nil
	}
	sec := int64(int32(binary.LittleEndian.Uint32(data[:4])))
	if sec <= 0 {
		return nil
	}
	t := time.Unix(sec, 0).UTC()
	return &t
}

func parseUnixTime64(data []byte) *time.Time {
	if len(data) < 8 {
		return nil
	}
	sec := int64(binary.LittleEndian.Uint64(data[:8]))
	if sec <= 0 {
		return nil
	}
	t := time.Unix(sec, 0).UTC()
	return &t
}

func parseAuditTime(msg string) *time.Time {
	start := strings.IndexByte(msg, '(')
	end := strings.IndexByte(msg, ':')
	if start < 0 || end <= start {
		return nil
	}
	seconds, err := strconv.ParseFloat(msg[start+1:end], 64)
	if err != nil {
		return nil
	}
	sec := int64(seconds)
	nsec := int64((seconds - float64(sec)) * 1e9)
	t := time.Unix(sec, nsec).UTC()
	return &t
}

func chooseLastlogRecordSize(data []byte) int {
	candidates := []int{296, 292}
	bestSize := 0
	bestScore := -1
	for _, size := range candidates {
		if len(data) < size {
			continue
		}
		score := plausibleLastlogCount(data, size)
		if score > bestScore {
			bestScore = score
			bestSize = size
		}
	}
	return bestSize
}

func plausibleLastlogCount(data []byte, size int) int {
	score := 0
	for offset := 0; offset+size <= len(data); offset += size {
		ts, lineOffset := parseLastlogTimestamp(data[offset:offset+size], size)
		if ts == nil {
			continue
		}
		year := ts.Year()
		if year < 1990 || year > time.Now().UTC().Year()+1 {
			continue
		}
		tty := cString(data[offset+lineOffset : offset+lineOffset+32])
		host := cString(data[offset+lineOffset+32 : offset+lineOffset+32+256])
		if tty != "" || host != "" {
			score++
		}
	}
	return score
}

func parseLastlogTimestamp(record []byte, size int) (*time.Time, int) {
	switch size {
	case 296:
		return parseUnixTime64(record[0:8]), 8
	case 292:
		return parseUnixTime32(record[0:4]), 4
	default:
		return nil, 0
	}
}

func utmpEventType(logType string, utType int) string {
	if logType == "btmp" {
		return "login_failed"
	}
	switch utType {
	case 1:
		return "runlevel_change"
	case 2:
		return "system_boot"
	case 3:
		return "system_time_new"
	case 4:
		return "system_time_old"
	case 5:
		return "init_process"
	case 6:
		return "login_prompt"
	case 7:
		return "login_success"
	case 8:
		return "logout"
	case 9:
		return "accounting"
	default:
		return "login_accounting"
	}
}

func shouldKeepUtmpEvent(event LoginEvent) bool {
	return event.Timestamp != nil ||
		event.User != "" ||
		event.TTY != "" ||
		event.RemoteHost != "" ||
		event.RemoteAddr != "" ||
		event.PID != 0
}

func sessionObservationFromLogEvent(event LogEvent) (SessionObservation, bool) {
	if !isSessionRelevantLogEvent(event) {
		return SessionObservation{}, false
	}
	actor := ""
	target := ""
	tty := ""
	cwd := ""
	if event.Fields != nil {
		actor = event.Fields["actor_user"]
		target = event.Fields["target_user"]
		tty = event.Fields["tty"]
		cwd = event.Fields["pwd"]
	}
	user := firstNonEmpty(event.User, actor, target)
	observation := SessionObservation{
		Exists:          true,
		ObservationType: "auth_log",
		EventType:       event.EventType,
		LogType:         event.LogType,
		SourceFile:      event.SourceFile,
		LineNumber:      event.LineNumber,
		Timestamp:       event.Timestamp,
		TimeInferred:    event.TimeInferred,
		User:            user,
		ActorUser:       actor,
		TargetUser:      target,
		TTY:             tty,
		PID:             event.PID,
		SessionID:       event.SessionID,
		RemoteAddr:      event.RemoteAddr,
		Service:         event.Service,
		Command:         event.Command,
		CWD:             cwd,
		RawCopyRef:      event.RawCopyRef,
		Sensitive:       true,
	}
	observation.SessionKey = buildSessionKey(observation.User, observation.RemoteAddr, observation.RemoteHost, observation.TTY, observation.SessionID, observation.PID)
	return observation, true
}

func sessionObservationFromLoginEvent(event LoginEvent) (SessionObservation, bool) {
	if event.User == "" && event.UID == 0 && event.TTY == "" && event.RemoteAddr == "" && event.RemoteHost == "" && event.PID == 0 && event.SessionID == 0 {
		return SessionObservation{}, false
	}
	observation := SessionObservation{
		Exists:          true,
		ObservationType: "login_accounting",
		EventType:       event.EventType,
		LogType:         event.LogType,
		SourceFile:      event.SourceFile,
		RecordIndex:     event.RecordIndex,
		Timestamp:       event.Timestamp,
		TimeInferred:    event.TimeInferred,
		User:            event.User,
		UID:             event.UID,
		TTY:             event.TTY,
		PID:             event.PID,
		SessionID:       event.SessionID,
		RemoteHost:      event.RemoteHost,
		RemoteAddr:      event.RemoteAddr,
		RawCopyRef:      event.RawCopyRef,
		Sensitive:       true,
	}
	observation.SessionKey = buildSessionKey(observation.User, observation.RemoteAddr, observation.RemoteHost, observation.TTY, observation.SessionID, observation.PID)
	return observation, true
}

func isSessionRelevantLogEvent(event LogEvent) bool {
	switch event.EventType {
	case "ssh_accepted", "ssh_failed", "sudo_command", "su_session", "audit_auth":
		return true
	default:
		return event.LogType == "auth" && (event.User != "" || event.RemoteAddr != "" || event.Command != "")
	}
}

func buildSessionKey(user, remoteAddr, remoteHost, tty string, sessionID, pid int) string {
	parts := []string{}
	if user != "" {
		parts = append(parts, "user="+user)
	}
	if remoteAddr != "" {
		parts = append(parts, "remote="+remoteAddr)
	} else if remoteHost != "" {
		parts = append(parts, "remote="+remoteHost)
	}
	if tty != "" {
		parts = append(parts, "tty="+tty)
	}
	if sessionID != 0 {
		parts = append(parts, "session="+strconv.Itoa(sessionID))
	}
	if pid != 0 {
		parts = append(parts, "pid="+strconv.Itoa(pid))
	}
	return strings.Join(parts, "|")
}

func parseUtmpAddr(data []byte) string {
	if len(data) < 16 || allBytesZero(data[:16]) {
		return ""
	}
	if !allBytesZero(data[4:16]) {
		return net.IP(data[:16]).String()
	}
	return net.IPv4(data[0], data[1], data[2], data[3]).String()
}

func allBytesZero(data []byte) bool {
	for _, b := range data {
		if b != 0 {
			return false
		}
	}
	return true
}

func cString(data []byte) string {
	if idx := bytesIndexByte(data, 0); idx >= 0 {
		data = data[:idx]
	}
	return strings.TrimSpace(string(data))
}

func bytesIndexByte(data []byte, value byte) int {
	for i, b := range data {
		if b == value {
			return i
		}
	}
	return -1
}

func isLoginAccountingLog(logType string) bool {
	return logType == "wtmp" || logType == "btmp" || logType == "lastlog" || logType == "utmp"
}

func loginTimelineSummary(event LoginEvent) string {
	parts := []string{event.EventType}
	if event.User != "" {
		parts = append(parts, "user="+event.User)
	}
	if event.UID > 0 {
		parts = append(parts, "uid="+strconv.Itoa(event.UID))
	}
	if event.RemoteAddr != "" {
		parts = append(parts, "remote="+event.RemoteAddr)
	} else if event.RemoteHost != "" {
		parts = append(parts, "remote="+event.RemoteHost)
	}
	if event.TTY != "" {
		parts = append(parts, "tty="+event.TTY)
	}
	return strings.Join(parts, " ")
}

func parseAuditFields(line string) map[string]string {
	fields := map[string]string{}
	for _, match := range auditKVPattern.FindAllStringSubmatch(line, -1) {
		if len(match) == 3 {
			fields[match[1]] = trimQuotes(match[2])
		}
	}
	if strings.HasPrefix(line, "type=") {
		parts := strings.SplitN(line, " ", 2)
		fields["type"] = strings.TrimPrefix(parts[0], "type=")
	}
	return fields
}

func auditRemoteAddr(value string) string {
	if value == "" || value == "?" || value == "(none)" || value == "unknown" {
		return ""
	}
	if ip := net.ParseIP(value); ip != nil {
		return ip.String()
	}
	return value
}

func parsePositiveInt(value string) int {
	parsed, err := strconv.ParseInt(value, 10, 32)
	if err != nil || parsed <= 0 {
		return 0
	}
	return int(parsed)
}

func splitService(raw string) (string, int) {
	raw = strings.TrimSpace(raw)
	if idx := strings.LastIndex(raw, "["); idx >= 0 && strings.HasSuffix(raw, "]") {
		pid, _ := strconv.Atoi(strings.TrimSuffix(raw[idx+1:], "]"))
		return raw[:idx], pid
	}
	return raw, 0
}

func classifyEvent(service, message string) string {
	lower := strings.ToLower(message)
	switch {
	case strings.Contains(lower, "accepted password") || strings.Contains(lower, "accepted publickey"):
		return "ssh_accepted"
	case strings.Contains(lower, "failed password") || strings.Contains(lower, "authentication failure"):
		return "ssh_failed"
	case strings.Contains(strings.ToLower(service), "sudo"):
		return "sudo_command"
	case strings.Contains(strings.ToLower(service), "su"):
		return "su_session"
	case strings.Contains(strings.ToLower(service), "cron"):
		return "cron"
	default:
		return "log_line"
	}
}

func auditEventType(fields map[string]string) string {
	switch fields["type"] {
	case "USER_LOGIN", "USER_AUTH", "CRED_ACQ":
		return "audit_auth"
	case "SYSCALL":
		return "audit_syscall"
	default:
		return "audit_" + strings.ToLower(firstNonEmpty(fields["type"], "event"))
	}
}

func relFor(event LogEvent) string {
	switch event.LogType {
	case "audit":
		return auditRel
	case "auth":
		return authEventsRel
	default:
		return logEventsRel
	}
}

func writeAbsent(out *output.Manager, reason string) error {
	for _, item := range []struct {
		rel     string
		logType string
	}{
		{logEventsRel, "logs"},
		{authEventsRel, "auth"},
		{auditRel, "audit"},
	} {
		record := LogEvent{RecordMeta: out.Meta(collector, item.rel, "logs", "generated", "medium"), Exists: false, AbsentReason: reason, LogType: item.logType, RecordSubtype: "status", Sensitive: true}
		if err := out.AppendAIJSONL(item.rel, record, collector, "logs", "generated", "medium"); err != nil {
			return err
		}
	}
	return nil
}

func writeAbsentForSource(out *output.Manager, log rawLog, reason string) error {
	record := LogEvent{RecordMeta: out.Meta(collector, relByLogType(log.LogType), log.SourcePath, "file", "high"), Exists: false, AbsentReason: reason, LogType: log.LogType, RecordSubtype: "status", SourceFile: log.SourcePath, Sensitive: true}
	return out.AppendAIJSONL(relByLogType(log.LogType), record, collector, log.SourcePath, "file", "high")
}

func writeRawCopyRecord(out *output.Manager, log copiedLog) error {
	rel := relByLogType(log.LogType)
	record := LogEvent{
		RecordMeta:    out.Meta(collector, rel, log.SourcePath, "file", "high"),
		Exists:        true,
		LogType:       log.LogType,
		EventType:     "raw_log_copy",
		RecordSubtype: "status",
		SourceFile:    log.SourcePath,
		Message:       "raw log copied; no parser applied",
		RawCopyRef:    log.RawCopyRef,
		Sensitive:     true,
	}
	return out.AppendAIJSONL(rel, record, collector, log.SourcePath, "file", "high")
}

func relByLogType(logType string) string {
	if isLoginAccountingLog(logType) {
		return loginEventsRel
	}
	if logType == "audit" {
		return auditRel
	}
	if logType == "auth" {
		return authEventsRel
	}
	return logEventsRel
}

func readerFor(path string) (io.ReadCloser, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(file)
		if err != nil {
			file.Close()
			return nil, err
		}
		return &compoundReadCloser{Reader: gz, closers: []io.Closer{gz, file}}, nil
	}
	return file, nil
}

type compoundReadCloser struct {
	io.Reader
	closers []io.Closer
}

func (c *compoundReadCloser) Close() error {
	var out error
	for _, closer := range c.closers {
		if err := closer.Close(); err != nil && out == nil {
			out = err
		}
	}
	return out
}

func readBounded(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("log exceeds copy limit: %d bytes", limit)
	}
	return data, nil
}

func globActual(pattern string) []string {
	actualPattern := actualPath(pattern)
	matches, _ := filepath.Glob(actualPattern)
	return matches
}

func dedupeLogs(logs []rawLog) []rawLog {
	seen := map[string]bool{}
	var out []rawLog
	for _, log := range logs {
		if seen[log.SourcePath] {
			continue
		}
		seen[log.SourcePath] = true
		out = append(out, log)
	}
	return out
}

func classifyLog(path string) string {
	switch {
	case strings.Contains(path, "/audit/") || strings.Contains(path, "audit.rules") || strings.Contains(path, "rules.d/"):
		return "audit"
	case strings.Contains(path, "auth.log") || strings.Contains(path, "secure"):
		return "auth"
	case strings.Contains(path, "cron"):
		return "cron"
	default:
		return "syslog"
	}
}

func shouldParse(path string) bool {
	return strings.Contains(path, "auth.log") ||
		strings.Contains(path, "secure") ||
		strings.Contains(path, "syslog") ||
		strings.Contains(path, "messages") ||
		strings.Contains(path, "audit.log") ||
		strings.Contains(path, "cron")
}

func isAuthService(service string) bool {
	service = strings.ToLower(service)
	return strings.Contains(service, "sshd") || strings.Contains(service, "sudo") || service == "su" || strings.Contains(service, "login")
}

func extractUser(message, service string) string {
	if strings.Contains(strings.ToLower(service), "sudo") {
		if idx := strings.Index(message, " : "); idx > 0 {
			if fields := strings.Fields(message[:idx]); len(fields) > 0 {
				return strings.Trim(fields[len(fields)-1], ";,")
			}
		}
	}
	for _, marker := range []string{" for invalid user ", " for user ", " for ", "user=", "USER="} {
		idx := strings.Index(message, marker)
		if idx >= 0 {
			rest := message[idx+len(marker):]
			if fields := strings.Fields(rest); len(fields) > 0 {
				return strings.Trim(fields[0], ";,")
			}
		}
	}
	return ""
}

func extractAuthFields(message, service string) map[string]string {
	fields := map[string]string{}
	lowerService := strings.ToLower(service)
	if strings.Contains(lowerService, "sudo") {
		extractSudoCommandFields(fields, message)
		extractPAMSessionFields(fields, message)
	}
	if lowerService == "su" || strings.Contains(lowerService, "login") {
		extractPAMSessionFields(fields, message)
	}
	if len(fields) == 0 {
		return nil
	}
	return fields
}

func extractSudoCommandFields(fields map[string]string, message string) {
	idx := strings.Index(message, " : ")
	if idx <= 0 {
		return
	}
	if tokens := strings.Fields(message[:idx]); len(tokens) > 0 {
		fields["actor_user"] = strings.Trim(tokens[len(tokens)-1], ";,")
	}
	for _, part := range strings.Split(message[idx+3:], ";") {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(key) {
		case "TTY":
			fields["tty"] = strings.TrimSpace(value)
		case "PWD":
			fields["pwd"] = strings.TrimSpace(value)
		case "USER":
			fields["target_user"] = strings.TrimSpace(value)
		}
	}
}

func extractPAMSessionFields(fields map[string]string, message string) {
	lower := strings.ToLower(message)
	if !strings.Contains(lower, "session opened") && !strings.Contains(lower, "session closed") {
		return
	}
	if strings.Contains(lower, "session opened") {
		fields["session_action"] = "opened"
	} else {
		fields["session_action"] = "closed"
	}
	if target := valueAfterMarker(message, " for user "); target != "" {
		fields["target_user"] = stripUIDSuffix(target)
	}
	if actor := valueAfterMarker(message, " by "); actor != "" {
		fields["actor_user"] = stripUIDSuffix(actor)
	}
}

func valueAfterMarker(message, marker string) string {
	idx := strings.Index(message, marker)
	if idx < 0 {
		return ""
	}
	rest := message[idx+len(marker):]
	if fields := strings.Fields(rest); len(fields) > 0 {
		return strings.Trim(fields[0], ";,")
	}
	return ""
}

func stripUIDSuffix(value string) string {
	if idx := strings.IndexByte(value, '('); idx >= 0 {
		value = value[:idx]
	}
	return strings.Trim(value, ";,")
}

func extractRemoteAddr(message string) string {
	for _, marker := range []string{" from ", "rhost="} {
		idx := strings.Index(message, marker)
		if idx >= 0 {
			rest := message[idx+len(marker):]
			if fields := strings.Fields(rest); len(fields) > 0 {
				return strings.Trim(fields[0], ";,")
			}
		}
	}
	return ""
}

func extractCommand(message string) string {
	idx := strings.Index(message, "COMMAND=")
	if idx < 0 {
		return ""
	}
	return strings.TrimSpace(message[idx+len("COMMAND="):])
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func trimQuotes(value string) string {
	return strings.Trim(value, `"`)
}

func recordError(out *output.Manager, sourcePath, sourceType, rawRel string, err error) {
	_ = out.Error(evidence.ErrorEvent{Collector: collector, Error: err.Error(), SourcePath: sourcePath, SourceType: sourceType, SourceTrust: sourceTrust(sourceType), RawArtifactRef: "ai/" + rawRel})
}

func sourceTrust(sourceType string) string {
	if sourceType == "generated" {
		return "medium"
	}
	return "high"
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func actualPath(path string) string {
	if filesystemRoot == "" || filesystemRoot == "/" {
		return path
	}
	return filepath.Join(filesystemRoot, strings.TrimPrefix(filepath.Clean(path), string(filepath.Separator)))
}

func displayPath(actual string) string {
	if filesystemRoot == "" || filesystemRoot == "/" {
		return actual
	}
	rel, err := filepath.Rel(filesystemRoot, actual)
	if err != nil || strings.HasPrefix(rel, "..") {
		return actual
	}
	return "/" + filepath.ToSlash(rel)
}

func sanitize(value string) string {
	value = strings.TrimSpace(filepath.ToSlash(value))
	if value == "" {
		return "unknown"
	}
	var b strings.Builder
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}
