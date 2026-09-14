package ddeirootkit

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Text renders the same human report for console, log, and archive.
func Text(rep Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "DDEI Rootkit 检测\n主机：%s\n时间：%s\n家族：%s\n", rep.Hostname, rep.Timestamp.Format(time.RFC3339), FamilyName)
	coverage := "已完成请求的检查（仅限检测器覆盖范围，不代表主机整体安全）"
	if !rep.Complete {
		coverage = "检查未完成或覆盖不足，不能据此排除感染"
	}
	fmt.Fprintf(&b, "完成/覆盖：%s\n判定：%s\n摘要：%s\n", coverage, rep.Verdict, rep.Summary)
	fmt.Fprintf(&b, "覆盖记录：root=%t proc=%t 进程=%d 对象=%d 错误=%d 跳过=%d\n",
		rep.Coverage.Root, rep.Coverage.Proc, rep.Coverage.Processes, rep.Coverage.Objects, rep.Coverage.Errors, rep.Coverage.Skipped)
	if len(rep.Findings) == 0 {
		b.WriteString("未发现需标记的指标\n")
	}
	for _, f := range rep.Findings {
		fmt.Fprintf(&b, "[%s] %s\n", f.Level, f.Title)
		if f.Detail != "" {
			fmt.Fprintf(&b, "  %s\n", f.Detail)
		}
	}
	for _, h := range rep.ProcHits {
		fmt.Fprintf(&b, "进程：pid=%d comm=%s exe=%s %s\n", h.PID, h.Comm, h.Exe, h.Note)
	}
	switch rep.Verdict {
	case VerdictInfected:
		b.WriteString("发现感染证据；请隔离主机并保全证据。\n")
	case VerdictClean:
		if rep.Complete {
			b.WriteString("覆盖范围内未发现家族指标。\n")
		}
	default:
		b.WriteString("结论不充分，需要进一步核查；不是 CLEAN。\n")
	}
	return b.String()
}

func Print(rep Report, w io.Writer) { fmt.Fprint(w, Text(rep)) }

// WriteLog exclusively creates a private log, never truncating existing files.
func WriteLog(rep Report, dir string) (string, error) {
	if dir == "" {
		exe, err := os.Executable()
		if err != nil {
			return "", fmt.Errorf("定位可执行文件目录: %w", err)
		}
		dir = filepath.Dir(exe)
	} else if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", err
	}
	base := "ddei_rootkit_check_" + rep.Timestamp.UTC().Format("20060102T150405Z")
	for n := 0; n < 10000; n++ {
		name := base + ".log"
		if n > 0 {
			name = fmt.Sprintf("%s_%d.log", base, n)
		}
		path := filepath.Join(dir, name)
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if os.IsExist(err) {
			continue
		}
		if err != nil {
			return "", err
		}
		_, writeErr := io.WriteString(f, Text(rep))
		if writeErr == nil {
			writeErr = f.Sync()
		}
		closeErr := f.Close()
		if writeErr != nil {
			return "", writeErr
		}
		if closeErr != nil {
			return "", closeErr
		}
		return path, nil
	}
	return "", fmt.Errorf("检测日志文件名冲突过多: %s", dir)
}

// ExitCode maps unknown and legacy REVIEW outcomes conservatively to 2.
func ExitCode(v Verdict) int {
	switch v {
	case VerdictInfected:
		return 3
	case VerdictClean:
		return 0
	default:
		return 2
	}
}
