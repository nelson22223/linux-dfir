package browser

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"linux-dfir/internal/evidence"
	"linux-dfir/internal/output"

	_ "modernc.org/sqlite"
)

const (
	collector    = "browser"
	profilesRel  = "entities/browser_profile.jsonl"
	historyRel   = "facts/browser_history.jsonl"
	downloadsRel = "facts/browser_downloads.jsonl"
	cookiesRel   = "facts/browser_cookies.jsonl"
	bookmarksRel = "facts/browser_bookmarks.jsonl"
	maxCopyBytes = 512 * 1024 * 1024
)

var filesystemRoot = "/"

type ProfileRecord struct {
	evidence.RecordMeta
	Exists       bool      `json:"exists"`
	AbsentReason string    `json:"absent_reason,omitempty"`
	Browser      string    `json:"browser,omitempty"`
	User         string    `json:"user,omitempty"`
	ProfileName  string    `json:"profile_name,omitempty"`
	ProfilePath  string    `json:"profile_path,omitempty"`
	Artifacts    []RawCopy `json:"artifacts,omitempty"`
}

type HistoryRecord struct {
	evidence.RecordMeta
	Exists       bool       `json:"exists"`
	AbsentReason string     `json:"absent_reason,omitempty"`
	Browser      string     `json:"browser,omitempty"`
	User         string     `json:"user,omitempty"`
	ProfileName  string     `json:"profile_name,omitempty"`
	URL          string     `json:"url,omitempty"`
	Title        string     `json:"title,omitempty"`
	VisitCount   int64      `json:"visit_count,omitempty"`
	VisitedAt    *time.Time `json:"visited_at,omitempty"`
	SourceDB     string     `json:"source_db,omitempty"`
	RawCopyRef   string     `json:"raw_copy_ref,omitempty"`
	Sensitive    bool       `json:"sensitive"`
}

type DownloadRecord struct {
	evidence.RecordMeta
	Exists        bool       `json:"exists"`
	AbsentReason  string     `json:"absent_reason,omitempty"`
	Browser       string     `json:"browser,omitempty"`
	User          string     `json:"user,omitempty"`
	ProfileName   string     `json:"profile_name,omitempty"`
	URL           string     `json:"url,omitempty"`
	TargetPath    string     `json:"target_path,omitempty"`
	StartedAt     *time.Time `json:"started_at,omitempty"`
	ReceivedBytes int64      `json:"received_bytes,omitempty"`
	TotalBytes    int64      `json:"total_bytes,omitempty"`
	State         string     `json:"state,omitempty"`
	SourceDB      string     `json:"source_db,omitempty"`
	RawCopyRef    string     `json:"raw_copy_ref,omitempty"`
	Sensitive     bool       `json:"sensitive"`
}

type CookieRecord struct {
	evidence.RecordMeta
	Exists       bool       `json:"exists"`
	AbsentReason string     `json:"absent_reason,omitempty"`
	Browser      string     `json:"browser,omitempty"`
	User         string     `json:"user,omitempty"`
	ProfileName  string     `json:"profile_name,omitempty"`
	Host         string     `json:"host,omitempty"`
	Name         string     `json:"name,omitempty"`
	Path         string     `json:"path,omitempty"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	CreatedAt    *time.Time `json:"created_at,omitempty"`
	LastAccessed *time.Time `json:"last_accessed,omitempty"`
	Secure       bool       `json:"secure,omitempty"`
	HTTPOnly     bool       `json:"http_only,omitempty"`
	SameSite     string     `json:"same_site,omitempty"`
	SourceDB     string     `json:"source_db,omitempty"`
	RawCopyRef   string     `json:"raw_copy_ref,omitempty"`
	Sensitive    bool       `json:"sensitive"`
}

type BookmarkRecord struct {
	evidence.RecordMeta
	Exists       bool       `json:"exists"`
	AbsentReason string     `json:"absent_reason,omitempty"`
	Browser      string     `json:"browser,omitempty"`
	User         string     `json:"user,omitempty"`
	ProfileName  string     `json:"profile_name,omitempty"`
	URL          string     `json:"url,omitempty"`
	Title        string     `json:"title,omitempty"`
	Folder       string     `json:"folder,omitempty"`
	AddedAt      *time.Time `json:"added_at,omitempty"`
	SourceDB     string     `json:"source_db,omitempty"`
	RawCopyRef   string     `json:"raw_copy_ref,omitempty"`
	Sensitive    bool       `json:"sensitive"`
}

type profile struct {
	Browser    string
	User       string
	Name       string
	SourcePath string
	ActualPath string
}

type artifactSpec struct {
	Kind       string
	SourcePath string
	ActualPath string
}

type RawCopy struct {
	Kind           string `json:"kind"`
	SourcePath     string `json:"source_path"`
	RawArtifactRef string `json:"raw_artifact_ref,omitempty"`
	LegacyRef      string `json:"legacy_ref,omitempty"`
	Size           int64  `json:"size,omitempty"`
	Copied         bool   `json:"copied"`
	Error          string `json:"error,omitempty"`

	absPath string
	main    bool
}

func Collect(ctx context.Context, out *output.Manager) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	profiles := DiscoverProfiles()
	if len(profiles) == 0 {
		reason := "no Chrome, Chromium, or Firefox profiles found"
		if err := writeAbsentProfile(out, reason); err != nil {
			return err
		}
		if err := writeAbsentHistory(out, reason); err != nil {
			return err
		}
		if err := writeAbsentDownload(out, reason); err != nil {
			return err
		}
		if err := writeAbsentCookie(out, reason); err != nil {
			return err
		}
		return writeAbsentBookmark(out, reason)
	}
	for _, prof := range profiles {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := collectProfile(out, prof); err != nil {
			return err
		}
	}
	return nil
}

func DiscoverProfiles() []profile {
	var profiles []profile
	seen := map[string]bool{}
	for _, home := range homeDirs() {
		for _, base := range browserBases(home.Source) {
			actualBase := actualPath(base.path)
			if !isDir(actualBase) {
				continue
			}
			for _, prof := range profilesInBase(base.browser, home.User, base.path, actualBase) {
				key := prof.Browser + "\x00" + prof.ActualPath
				if seen[key] {
					continue
				}
				seen[key] = true
				profiles = append(profiles, prof)
			}
		}
	}
	sort.Slice(profiles, func(i, j int) bool {
		return profiles[i].Browser+profiles[i].User+profiles[i].Name < profiles[j].Browser+profiles[j].User+profiles[j].Name
	})
	return profiles
}

type homeDir struct {
	User   string
	Source string
}

func homeDirs() []homeDir {
	var homes []homeDir
	seen := map[string]bool{}
	add := func(user, source string) {
		source = filepath.Clean(source)
		if source == "." || source == "/" || seen[source] {
			return
		}
		seen[source] = true
		if user == "" {
			user = filepath.Base(source)
		}
		homes = append(homes, homeDir{User: user, Source: source})
	}
	if data, err := os.ReadFile(actualPath("/etc/passwd")); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			fields := strings.Split(line, ":")
			if len(fields) >= 6 {
				add(fields[0], fields[5])
			}
		}
	}
	for _, root := range []string{"/home"} {
		entries, err := os.ReadDir(actualPath(root))
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				add(entry.Name(), filepath.Join(root, entry.Name()))
			}
		}
	}
	if isDir(actualPath("/root")) {
		add("root", "/root")
	}
	sort.Slice(homes, func(i, j int) bool { return homes[i].Source < homes[j].Source })
	return homes
}

type browserBase struct {
	browser string
	path    string
}

func browserBases(home string) []browserBase {
	return []browserBase{
		{browser: "chrome", path: filepath.Join(home, ".config", "google-chrome")},
		{browser: "chromium", path: filepath.Join(home, ".config", "chromium")},
		{browser: "firefox", path: filepath.Join(home, ".mozilla", "firefox")},
	}
}

func profilesInBase(browserName, user, sourceBase, actualBase string) []profile {
	var profiles []profile
	entries, err := os.ReadDir(actualBase)
	if err != nil {
		return nil
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		actual := filepath.Join(actualBase, entry.Name())
		source := filepath.Join(sourceBase, entry.Name())
		if browserName == "firefox" {
			if !fileExists(filepath.Join(actual, "places.sqlite")) && !fileExists(filepath.Join(actual, "cookies.sqlite")) {
				continue
			}
		} else if !looksLikeChromiumProfile(actual, entry.Name()) {
			continue
		}
		profiles = append(profiles, profile{
			Browser:    browserName,
			User:       user,
			Name:       entry.Name(),
			SourcePath: source,
			ActualPath: actual,
		})
	}
	return profiles
}

func looksLikeChromiumProfile(actual, name string) bool {
	return fileExists(filepath.Join(actual, "History")) ||
		fileExists(filepath.Join(actual, "Cookies")) ||
		fileExists(filepath.Join(actual, "Network", "Cookies")) ||
		fileExists(filepath.Join(actual, "Bookmarks")) ||
		name == "Default" ||
		strings.HasPrefix(name, "Profile ")
}

func collectProfile(out *output.Manager, prof profile) error {
	copies := copyArtifacts(out, prof)
	public := make([]RawCopy, 0, len(copies))
	for _, copy := range copies {
		copy.absPath = ""
		copy.main = false
		public = append(public, copy)
	}
	record := ProfileRecord{
		RecordMeta:  out.Meta(collector, profilesRel, prof.SourcePath, "browser_profile", "high"),
		Exists:      true,
		Browser:     prof.Browser,
		User:        prof.User,
		ProfileName: prof.Name,
		ProfilePath: prof.SourcePath,
		Artifacts:   public,
	}
	if err := out.AppendAIJSONL(profilesRel, record, collector, prof.SourcePath, "browser_profile", "high"); err != nil {
		return err
	}
	for _, copy := range copies {
		if !copy.Copied || !copy.main {
			continue
		}
		if err := parseRawCopy(out, prof, copy); err != nil {
			return err
		}
	}
	return nil
}

func copyArtifacts(out *output.Manager, prof profile) []RawCopy {
	var copies []RawCopy
	for _, spec := range artifactSpecs(prof) {
		if !fileExists(spec.ActualPath) {
			continue
		}
		main := copyOne(out, prof, spec.Kind, spec.SourcePath, spec.ActualPath, true)
		copies = append(copies, main)
		if !main.Copied || spec.Kind == "bookmarks" {
			continue
		}
		for _, suffix := range []string{"-wal", "-shm"} {
			sidecar := spec.ActualPath + suffix
			if fileExists(sidecar) {
				copies = append(copies, copyOne(out, prof, spec.Kind, spec.SourcePath+suffix, sidecar, false))
			}
		}
	}
	return copies
}

func artifactSpecs(prof profile) []artifactSpec {
	source := func(rel string) string { return filepath.Join(prof.SourcePath, rel) }
	actual := func(rel string) string { return filepath.Join(prof.ActualPath, rel) }
	if prof.Browser == "firefox" {
		return []artifactSpec{
			{Kind: "places", SourcePath: source("places.sqlite"), ActualPath: actual("places.sqlite")},
			{Kind: "cookies", SourcePath: source("cookies.sqlite"), ActualPath: actual("cookies.sqlite")},
		}
	}
	return []artifactSpec{
		{Kind: "history", SourcePath: source("History"), ActualPath: actual("History")},
		{Kind: "cookies", SourcePath: source("Cookies"), ActualPath: actual("Cookies")},
		{Kind: "cookies", SourcePath: source(filepath.Join("Network", "Cookies")), ActualPath: actual(filepath.Join("Network", "Cookies"))},
		{Kind: "bookmarks", SourcePath: source("Bookmarks"), ActualPath: actual("Bookmarks")},
	}
}

func copyOne(out *output.Manager, prof profile, kind, sourcePath, actual string, main bool) RawCopy {
	copy := RawCopy{Kind: kind, SourcePath: sourcePath, main: main}
	data, err := readBounded(actual, maxCopyBytes)
	if err != nil {
		copy.Error = err.Error()
		recordError(out, sourcePath, "file", profilesRel, err)
		return copy
	}
	rawRel := filepath.Join("raw", "browser", sanitize(prof.Browser), sanitize(prof.User), sanitize(prof.Name), rawCopyName(prof, sourcePath))
	legacyRel := filepath.Join("browser", rawRel)
	if err := out.WriteAIFromSource(rawRel, data, collector, sourcePath, "file", "high"); err != nil {
		copy.Error = err.Error()
		recordError(out, sourcePath, "file", profilesRel, err)
		return copy
	}
	if err := out.WriteLegacyFromSource(legacyRel, data, collector, sourcePath, "file", "high"); err != nil {
		copy.Error = err.Error()
		recordError(out, sourcePath, "file", profilesRel, err)
		return copy
	}
	copy.Copied = true
	copy.Size = int64(len(data))
	copy.RawArtifactRef = filepath.Join("ai", rawRel)
	copy.LegacyRef = filepath.Join("legacy", legacyRel)
	for _, rel := range []string{copy.RawArtifactRef, copy.LegacyRef} {
		abs, err := output.SafeJoin(out.Root(), rel)
		if err == nil && fileExists(abs) {
			copy.absPath = abs
			break
		}
	}
	return copy
}

func parseRawCopy(out *output.Manager, prof profile, copy RawCopy) error {
	if copy.Kind != "bookmarks" {
		staged, cleanup, err := stageSQLiteFamily(copy.absPath)
		if err != nil {
			recordError(out, copy.SourcePath, "browser_sqlite_copy", profilesRel, err)
			return nil
		}
		defer cleanup()
		copy.absPath = staged
	}
	switch copy.Kind {
	case "history":
		if err := parseChromiumHistory(out, prof, copy); err != nil {
			return err
		}
		return parseChromiumDownloads(out, prof, copy)
	case "places":
		if err := parseFirefoxHistory(out, prof, copy); err != nil {
			return err
		}
		if err := parseFirefoxDownloads(out, prof, copy); err != nil {
			return err
		}
		return parseFirefoxBookmarks(out, prof, copy)
	case "cookies":
		if prof.Browser == "firefox" {
			return parseFirefoxCookies(out, prof, copy)
		}
		return parseChromiumCookies(out, prof, copy)
	case "bookmarks":
		return parseChromiumBookmarks(out, prof, copy)
	default:
		return nil
	}
}

func stageSQLiteFamily(mainPath string) (string, func(), error) {
	if mainPath == "" {
		return "", func() {}, errors.New("sqlite copy path is empty")
	}
	tmpDir, err := os.MkdirTemp("", "linux-dfir-browser-sqlite-")
	if err != nil {
		return "", func() {}, err
	}
	cleanup := func() { _ = os.RemoveAll(tmpDir) }
	for _, suffix := range []string{"", "-wal", "-shm"} {
		src := mainPath + suffix
		if !fileExists(src) {
			continue
		}
		data, err := readBounded(src, maxCopyBytes)
		if err != nil {
			cleanup()
			return "", func() {}, err
		}
		if err := os.WriteFile(filepath.Join(tmpDir, filepath.Base(mainPath)+suffix), data, 0o640); err != nil {
			cleanup()
			return "", func() {}, err
		}
	}
	return filepath.Join(tmpDir, filepath.Base(mainPath)), cleanup, nil
}

func parseChromiumHistory(out *output.Manager, prof profile, copy RawCopy) error {
	db, err := openSQLiteCopy(copy.absPath)
	if err != nil {
		recordError(out, copy.SourcePath, "browser_sqlite_copy", historyRel, err)
		return nil
	}
	defer db.Close()
	var rows *sql.Rows
	if tableExists(db, "visits") && tableExists(db, "urls") {
		rows, err = db.Query(`SELECT urls.url, IFNULL(urls.title,''), IFNULL(urls.visit_count,0), IFNULL(visits.visit_time,0) FROM visits JOIN urls ON visits.url = urls.id WHERE urls.url IS NOT NULL ORDER BY visits.visit_time DESC LIMIT 5000`)
	} else if tableExists(db, "urls") {
		rows, err = db.Query(`SELECT url, IFNULL(title,''), IFNULL(visit_count,0), IFNULL(last_visit_time,0) FROM urls WHERE url IS NOT NULL ORDER BY last_visit_time DESC LIMIT 5000`)
	} else {
		return nil
	}
	if err != nil {
		recordError(out, copy.SourcePath, "browser_sqlite_copy", historyRel, err)
		return nil
	}
	defer rows.Close()
	return emitHistoryRows(out, prof, copy, rows, "chrome")
}

func parseFirefoxHistory(out *output.Manager, prof profile, copy RawCopy) error {
	db, err := openSQLiteCopy(copy.absPath)
	if err != nil {
		recordError(out, copy.SourcePath, "browser_sqlite_copy", historyRel, err)
		return nil
	}
	defer db.Close()
	if !tableExists(db, "moz_places") {
		return nil
	}
	rows, err := db.Query(`SELECT url, IFNULL(title,''), IFNULL(visit_count,0), IFNULL(last_visit_date,0) FROM moz_places WHERE url IS NOT NULL ORDER BY last_visit_date DESC LIMIT 5000`)
	if err != nil {
		recordError(out, copy.SourcePath, "browser_sqlite_copy", historyRel, err)
		return nil
	}
	defer rows.Close()
	return emitHistoryRows(out, prof, copy, rows, "firefox")
}

func emitHistoryRows(out *output.Manager, prof profile, copy RawCopy, rows *sql.Rows, browserName string) error {
	var legacy strings.Builder
	legacy.WriteString("visited_at\tvisit_count\turl\ttitle\n")
	for rows.Next() {
		var rec HistoryRecord
		var visitedRaw int64
		if err := rows.Scan(&rec.URL, &rec.Title, &rec.VisitCount, &visitedRaw); err != nil {
			recordError(out, copy.SourcePath, "browser_sqlite_copy", historyRel, err)
			continue
		}
		rec.RecordMeta = rawMeta(out, historyRel, copy)
		rec.Exists = true
		rec.Browser = prof.Browser
		rec.User = prof.User
		rec.ProfileName = prof.Name
		rec.VisitedAt = parseTime(browserName, visitedRaw)
		rec.SourceDB = copy.SourcePath
		rec.RawCopyRef = copy.RawArtifactRef
		rec.Sensitive = true
		if err := out.AppendAIJSONL(historyRel, rec, collector, copy.SourcePath, "browser_sqlite_copy", "high"); err != nil {
			return err
		}
		legacy.WriteString(formatTime(rec.VisitedAt))
		legacy.WriteByte('\t')
		legacy.WriteString(strconv.FormatInt(rec.VisitCount, 10))
		legacy.WriteByte('\t')
		legacy.WriteString(strings.ReplaceAll(rec.URL, "\t", " "))
		legacy.WriteByte('\t')
		legacy.WriteString(strings.ReplaceAll(rec.Title, "\t", " "))
		legacy.WriteByte('\n')
	}
	if err := rows.Err(); err != nil {
		recordError(out, copy.SourcePath, "browser_sqlite_copy", historyRel, err)
	}
	return writeLegacyHistory(out, prof, []byte(legacy.String()), copy)
}

func parseChromiumDownloads(out *output.Manager, prof profile, copy RawCopy) error {
	db, err := openSQLiteCopy(copy.absPath)
	if err != nil {
		recordError(out, copy.SourcePath, "browser_sqlite_copy", downloadsRel, err)
		return nil
	}
	defer db.Close()
	if !tableExists(db, "downloads") {
		return nil
	}
	cols := columns(db, "downloads")
	rows, err := db.Query(downloadsSQL(cols))
	if err != nil {
		recordError(out, copy.SourcePath, "browser_sqlite_copy", downloadsRel, err)
		return nil
	}
	defer rows.Close()
	for rows.Next() {
		var rec DownloadRecord
		var startedRaw int64
		if err := rows.Scan(&rec.URL, &rec.TargetPath, &startedRaw, &rec.ReceivedBytes, &rec.TotalBytes, &rec.State); err != nil {
			recordError(out, copy.SourcePath, "browser_sqlite_copy", downloadsRel, err)
			continue
		}
		rec.RecordMeta = rawMeta(out, downloadsRel, copy)
		rec.Exists = true
		rec.Browser = prof.Browser
		rec.User = prof.User
		rec.ProfileName = prof.Name
		rec.StartedAt = ChromeTime(startedRaw)
		rec.SourceDB = copy.SourcePath
		rec.RawCopyRef = copy.RawArtifactRef
		rec.Sensitive = true
		if err := out.AppendAIJSONL(downloadsRel, rec, collector, copy.SourcePath, "browser_sqlite_copy", "high"); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		recordError(out, copy.SourcePath, "browser_sqlite_copy", downloadsRel, err)
	}
	return nil
}

func parseFirefoxDownloads(out *output.Manager, prof profile, copy RawCopy) error {
	db, err := openSQLiteCopy(copy.absPath)
	if err != nil {
		recordError(out, copy.SourcePath, "browser_sqlite_copy", downloadsRel, err)
		return nil
	}
	defer db.Close()
	if !tableExists(db, "moz_annos") || !tableExists(db, "moz_anno_attributes") || !tableExists(db, "moz_places") {
		return nil
	}
	rows, err := db.Query(`SELECT moz_places.url, IFNULL(moz_annos.content,''), IFNULL(moz_places.last_visit_date,0) FROM moz_places JOIN moz_annos ON moz_annos.place_id = moz_places.id JOIN moz_anno_attributes ON moz_anno_attributes.id = moz_annos.anno_attribute_id WHERE moz_anno_attributes.name IN ('downloads/destinationFileURI', 'downloads/destinationFileName') ORDER BY moz_places.last_visit_date DESC LIMIT 2000`)
	if err != nil {
		recordError(out, copy.SourcePath, "browser_sqlite_copy", downloadsRel, err)
		return nil
	}
	defer rows.Close()
	for rows.Next() {
		var rec DownloadRecord
		var startedRaw int64
		if err := rows.Scan(&rec.URL, &rec.TargetPath, &startedRaw); err != nil {
			recordError(out, copy.SourcePath, "browser_sqlite_copy", downloadsRel, err)
			continue
		}
		rec.RecordMeta = rawMeta(out, downloadsRel, copy)
		rec.Exists = true
		rec.Browser = prof.Browser
		rec.User = prof.User
		rec.ProfileName = prof.Name
		rec.StartedAt = FirefoxTime(startedRaw)
		rec.SourceDB = copy.SourcePath
		rec.RawCopyRef = copy.RawArtifactRef
		rec.Sensitive = true
		if err := out.AppendAIJSONL(downloadsRel, rec, collector, copy.SourcePath, "browser_sqlite_copy", "high"); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		recordError(out, copy.SourcePath, "browser_sqlite_copy", downloadsRel, err)
	}
	return nil
}

func parseChromiumCookies(out *output.Manager, prof profile, copy RawCopy) error {
	return parseCookieTable(out, prof, copy, false)
}

func parseFirefoxCookies(out *output.Manager, prof profile, copy RawCopy) error {
	return parseCookieTable(out, prof, copy, true)
}

func parseCookieTable(out *output.Manager, prof profile, copy RawCopy, firefox bool) error {
	db, err := openSQLiteCopy(copy.absPath)
	if err != nil {
		recordError(out, copy.SourcePath, "browser_sqlite_copy", cookiesRel, err)
		return nil
	}
	defer db.Close()
	table := "cookies"
	if firefox {
		table = "moz_cookies"
	}
	if !tableExists(db, table) {
		return nil
	}
	rows, err := db.Query(cookiesSQL(columns(db, table), firefox))
	if err != nil {
		recordError(out, copy.SourcePath, "browser_sqlite_copy", cookiesRel, err)
		return nil
	}
	defer rows.Close()
	for rows.Next() {
		var rec CookieRecord
		var expiresRaw, createdRaw, accessedRaw int64
		var secure, httpOnly int64
		if err := rows.Scan(&rec.Host, &rec.Name, &rec.Path, &expiresRaw, &createdRaw, &accessedRaw, &secure, &httpOnly, &rec.SameSite); err != nil {
			recordError(out, copy.SourcePath, "browser_sqlite_copy", cookiesRel, err)
			continue
		}
		rec.RecordMeta = rawMeta(out, cookiesRel, copy)
		rec.Exists = true
		rec.Browser = prof.Browser
		rec.User = prof.User
		rec.ProfileName = prof.Name
		rec.SourceDB = copy.SourcePath
		rec.RawCopyRef = copy.RawArtifactRef
		rec.Sensitive = true
		rec.Secure = secure != 0
		rec.HTTPOnly = httpOnly != 0
		if firefox {
			rec.ExpiresAt = unixSecondsTime(expiresRaw)
			rec.CreatedAt = FirefoxTime(createdRaw)
			rec.LastAccessed = FirefoxTime(accessedRaw)
			rec.SameSite = sameSite(rec.SameSite)
		} else {
			rec.ExpiresAt = ChromeTime(expiresRaw)
			rec.CreatedAt = ChromeTime(createdRaw)
			rec.LastAccessed = ChromeTime(accessedRaw)
			rec.SameSite = sameSite(rec.SameSite)
		}
		if err := out.AppendAIJSONL(cookiesRel, rec, collector, copy.SourcePath, "browser_sqlite_copy", "high"); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		recordError(out, copy.SourcePath, "browser_sqlite_copy", cookiesRel, err)
	}
	return nil
}

func parseChromiumBookmarks(out *output.Manager, prof profile, copy RawCopy) error {
	data, err := os.ReadFile(copy.absPath)
	if err != nil {
		recordError(out, copy.SourcePath, "browser_json_copy", bookmarksRel, err)
		return nil
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		recordError(out, copy.SourcePath, "browser_json_copy", bookmarksRel, err)
		return nil
	}
	roots, _ := doc["roots"].(map[string]any)
	for name, node := range roots {
		if err := walkChromiumBookmark(out, prof, copy, name, node); err != nil {
			return err
		}
	}
	return nil
}

func walkChromiumBookmark(out *output.Manager, prof profile, copy RawCopy, folder string, node any) error {
	obj, ok := node.(map[string]any)
	if !ok {
		return nil
	}
	if stringValue(obj["type"]) == "url" {
		rec := BookmarkRecord{
			RecordMeta:  rawMeta(out, bookmarksRel, copy),
			Exists:      true,
			Browser:     prof.Browser,
			User:        prof.User,
			ProfileName: prof.Name,
			URL:         stringValue(obj["url"]),
			Title:       stringValue(obj["name"]),
			Folder:      folder,
			AddedAt:     ChromeTime(parseIntString(obj["date_added"])),
			SourceDB:    copy.SourcePath,
			RawCopyRef:  copy.RawArtifactRef,
			Sensitive:   true,
		}
		return out.AppendAIJSONL(bookmarksRel, rec, collector, copy.SourcePath, "browser_json_copy", "high")
	}
	if name := stringValue(obj["name"]); name != "" {
		if folder == "" {
			folder = name
		} else {
			folder += "/" + name
		}
	}
	children, _ := obj["children"].([]any)
	for _, child := range children {
		if err := walkChromiumBookmark(out, prof, copy, folder, child); err != nil {
			return err
		}
	}
	return nil
}

func parseFirefoxBookmarks(out *output.Manager, prof profile, copy RawCopy) error {
	db, err := openSQLiteCopy(copy.absPath)
	if err != nil {
		recordError(out, copy.SourcePath, "browser_sqlite_copy", bookmarksRel, err)
		return nil
	}
	defer db.Close()
	if !tableExists(db, "moz_bookmarks") || !tableExists(db, "moz_places") {
		return nil
	}
	rows, err := db.Query(`SELECT moz_places.url, IFNULL(moz_bookmarks.title, IFNULL(moz_places.title,'')), IFNULL(moz_bookmarks.dateAdded,0) FROM moz_bookmarks JOIN moz_places ON moz_bookmarks.fk = moz_places.id WHERE moz_places.url IS NOT NULL ORDER BY moz_bookmarks.id LIMIT 5000`)
	if err != nil {
		recordError(out, copy.SourcePath, "browser_sqlite_copy", bookmarksRel, err)
		return nil
	}
	defer rows.Close()
	for rows.Next() {
		var rec BookmarkRecord
		var addedRaw int64
		if err := rows.Scan(&rec.URL, &rec.Title, &addedRaw); err != nil {
			recordError(out, copy.SourcePath, "browser_sqlite_copy", bookmarksRel, err)
			continue
		}
		rec.RecordMeta = rawMeta(out, bookmarksRel, copy)
		rec.Exists = true
		rec.Browser = prof.Browser
		rec.User = prof.User
		rec.ProfileName = prof.Name
		rec.AddedAt = FirefoxTime(addedRaw)
		rec.SourceDB = copy.SourcePath
		rec.RawCopyRef = copy.RawArtifactRef
		rec.Sensitive = true
		if err := out.AppendAIJSONL(bookmarksRel, rec, collector, copy.SourcePath, "browser_sqlite_copy", "high"); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		recordError(out, copy.SourcePath, "browser_sqlite_copy", bookmarksRel, err)
	}
	return nil
}

func openSQLiteCopy(path string) (*sql.DB, error) {
	if path == "" {
		return nil, errors.New("sqlite copy path is empty")
	}
	u := url.URL{Scheme: "file", Path: path}
	q := u.Query()
	q.Set("mode", "ro")
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func tableExists(db *sql.DB, table string) bool {
	var name string
	err := db.QueryRow(`SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&name)
	return err == nil
}

func columns(db *sql.DB, table string) map[string]bool {
	rows, err := db.Query(`PRAGMA table_info(` + quoteIdent(table) + `)`)
	if err != nil {
		return map[string]bool{}
	}
	defer rows.Close()
	cols := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, typ string
		var notnull int
		var dflt any
		var pk int
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err == nil {
			cols[name] = true
		}
	}
	return cols
}

func downloadsSQL(cols map[string]bool) string {
	expr := func(col, fallback string) string {
		if cols[col] {
			return col
		}
		return fallback + " AS " + col
	}
	target := "'' AS target_path"
	if cols["target_path"] && cols["current_path"] {
		target = "IFNULL(NULLIF(target_path,''), current_path) AS target_path"
	} else if cols["target_path"] {
		target = "target_path"
	} else if cols["current_path"] {
		target = "current_path AS target_path"
	}
	return "SELECT " + strings.Join([]string{
		expr("tab_url", "''"),
		target,
		expr("start_time", "0"),
		expr("received_bytes", "0"),
		expr("total_bytes", "0"),
		expr("state", "0"),
	}, ", ") + " FROM downloads ORDER BY start_time DESC LIMIT 2000"
}

func cookiesSQL(cols map[string]bool, firefox bool) string {
	expr := func(col, fallback string) string {
		if cols[col] {
			return col
		}
		return fallback + " AS " + col
	}
	if firefox {
		return "SELECT " + strings.Join([]string{
			expr("host", "''"),
			expr("name", "''"),
			expr("path", "''"),
			expr("expiry", "0"),
			expr("creationTime", "0"),
			expr("lastAccessed", "0"),
			expr("isSecure", "0"),
			expr("isHttpOnly", "0"),
			expr("sameSite", "0"),
		}, ", ") + " FROM moz_cookies ORDER BY host, name, path LIMIT 10000"
	}
	return "SELECT " + strings.Join([]string{
		expr("host_key", "''"),
		expr("name", "''"),
		expr("path", "''"),
		expr("expires_utc", "0"),
		expr("creation_utc", "0"),
		expr("last_access_utc", "0"),
		expr("is_secure", "0"),
		expr("is_httponly", "0"),
		expr("samesite", "0"),
	}, ", ") + " FROM cookies ORDER BY host_key, name, path LIMIT 10000"
}

func ChromeTime(value int64) *time.Time {
	if value <= 0 {
		return nil
	}
	const windowsToUnixMicroseconds = 11644473600000000
	t := time.UnixMicro(value - windowsToUnixMicroseconds).UTC()
	return &t
}

func FirefoxTime(value int64) *time.Time {
	if value <= 0 {
		return nil
	}
	t := time.UnixMicro(value).UTC()
	return &t
}

func RedactURLQuery(rawURL string) string {
	idx := strings.IndexByte(rawURL, '?')
	if idx < 0 {
		return rawURL
	}
	return rawURL[:idx] + "?<redacted>"
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
		return nil, fmt.Errorf("database exceeds copy limit: %d bytes", limit)
	}
	return data, nil
}

func rawMeta(out *output.Manager, rel string, copy RawCopy) evidence.RecordMeta {
	meta := out.Meta(collector, rel, copy.SourcePath, "browser_sqlite_copy", "high")
	if copy.RawArtifactRef != "" {
		meta.RawArtifactRef = copy.RawArtifactRef
	} else if copy.LegacyRef != "" {
		meta.RawArtifactRef = copy.LegacyRef
	}
	return meta
}

func writeLegacyHistory(out *output.Manager, prof profile, data []byte, copy RawCopy) error {
	name := fmt.Sprintf("%s_%s_history.out", sanitize(prof.User), sanitize(prof.Name))
	return out.WriteLegacyFromSource(filepath.Join("browser", sanitize(prof.Browser), name), data, collector, copy.SourcePath, "browser_sqlite_copy", "high")
}

func writeAbsentProfile(out *output.Manager, reason string) error {
	record := ProfileRecord{RecordMeta: out.Meta(collector, profilesRel, "browser profiles", "generated", "medium"), Exists: false, AbsentReason: reason}
	return out.AppendAIJSONL(profilesRel, record, collector, "browser profiles", "generated", "medium")
}

func writeAbsentHistory(out *output.Manager, reason string) error {
	record := HistoryRecord{RecordMeta: out.Meta(collector, historyRel, "browser history", "generated", "medium"), Exists: false, AbsentReason: reason, Sensitive: true}
	return out.AppendAIJSONL(historyRel, record, collector, "browser history", "generated", "medium")
}

func writeAbsentDownload(out *output.Manager, reason string) error {
	record := DownloadRecord{RecordMeta: out.Meta(collector, downloadsRel, "browser downloads", "generated", "medium"), Exists: false, AbsentReason: reason, Sensitive: true}
	return out.AppendAIJSONL(downloadsRel, record, collector, "browser downloads", "generated", "medium")
}

func writeAbsentCookie(out *output.Manager, reason string) error {
	record := CookieRecord{RecordMeta: out.Meta(collector, cookiesRel, "browser cookies", "generated", "medium"), Exists: false, AbsentReason: reason, Sensitive: true}
	return out.AppendAIJSONL(cookiesRel, record, collector, "browser cookies", "generated", "medium")
}

func writeAbsentBookmark(out *output.Manager, reason string) error {
	record := BookmarkRecord{RecordMeta: out.Meta(collector, bookmarksRel, "browser bookmarks", "generated", "medium"), Exists: false, AbsentReason: reason, Sensitive: true}
	return out.AppendAIJSONL(bookmarksRel, record, collector, "browser bookmarks", "generated", "medium")
}

func recordError(out *output.Manager, sourcePath, sourceType, rawRel string, err error) {
	_ = out.Error(evidence.ErrorEvent{Collector: collector, Error: err.Error(), SourcePath: sourcePath, SourceType: sourceType, SourceTrust: sourceTrust(sourceType), RawArtifactRef: "ai/" + rawRel})
}

func parseTime(browser string, value int64) *time.Time {
	if browser == "firefox" {
		return FirefoxTime(value)
	}
	return ChromeTime(value)
}

func unixSecondsTime(seconds int64) *time.Time {
	if seconds <= 0 {
		return nil
	}
	t := time.Unix(seconds, 0).UTC()
	return &t
}

func sameSite(value string) string {
	switch value {
	case "-1":
		return "unspecified"
	case "0":
		return "no_restriction"
	case "1":
		return "lax"
	case "2":
		return "strict"
	default:
		return value
	}
}

func formatTime(value *time.Time) string {
	if value == nil {
		return ""
	}
	return value.Format(time.RFC3339)
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func actualPath(path string) string {
	if filesystemRoot == "" || filesystemRoot == "/" {
		return path
	}
	return filepath.Join(filesystemRoot, strings.TrimPrefix(filepath.Clean(path), string(filepath.Separator)))
}

func sourceTrust(sourceType string) string {
	if sourceType == "generated" {
		return "medium"
	}
	return "high"
}

func sanitize(value string) string {
	value = strings.TrimSpace(value)
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

func rawCopyName(prof profile, sourcePath string) string {
	rel, err := filepath.Rel(filepath.Clean(prof.SourcePath), filepath.Clean(sourcePath))
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		rel = filepath.Base(sourcePath)
	}
	return sanitize(filepath.ToSlash(rel))
}

func quoteIdent(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `""`) + `"`
}

func stringValue(value any) string {
	if s, ok := value.(string); ok {
		return s
	}
	return ""
}

func parseIntString(value any) int64 {
	switch v := value.(type) {
	case string:
		out, _ := strconv.ParseInt(v, 10, 64)
		return out
	case float64:
		return int64(v)
	default:
		return 0
	}
}
