package browser

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"linux-dfir/internal/evidence"
	"linux-dfir/internal/output"

	_ "modernc.org/sqlite"
)

func TestBrowserTimeParsersAndURLRedaction(t *testing.T) {
	chrome := ChromeTime(11644473600000000)
	if chrome == nil || !chrome.Equal(time.Unix(0, 0).UTC()) {
		t.Fatalf("unexpected chrome epoch: %v", chrome)
	}
	firefox := FirefoxTime(1700000000123456)
	if firefox == nil || firefox.UnixMicro() != 1700000000123456 {
		t.Fatalf("unexpected firefox time: %v", firefox)
	}
	if RedactURLQuery("https://example.test/a?token=secret") != "https://example.test/a?<redacted>" {
		t.Fatal("query redaction failed")
	}
}

func TestDiscoverProfiles(t *testing.T) {
	root := t.TempDir()
	restore := setBrowserTestHooks(root)
	defer restore()

	writeFixtureFile(t, rootPath(root, "/etc/passwd"), "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n", 0o640)
	writeFixtureFile(t, rootPath(root, "/home/alice/.config/google-chrome/Default/History"), "history", 0o640)
	writeFixtureFile(t, rootPath(root, "/home/alice/.config/google-chrome/Default/Network/Cookies"), "cookies", 0o640)
	writeFixtureFile(t, rootPath(root, "/home/alice/.mozilla/firefox/abcd.default-release/places.sqlite"), "places", 0o640)

	profiles := DiscoverProfiles()
	if len(profiles) != 2 {
		t.Fatalf("expected 2 profiles, got %d: %#v", len(profiles), profiles)
	}
	assertProfile(t, profiles, "chrome", "alice", "Default")
	assertProfile(t, profiles, "firefox", "alice", "abcd.default-release")
}

func TestCollectWithFixtureBrowserProfiles(t *testing.T) {
	root := t.TempDir()
	restore := setBrowserTestHooks(root)
	defer restore()

	writeFixtureFile(t, rootPath(root, "/etc/passwd"), "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n", 0o640)
	chromeDir := rootPath(root, "/home/alice/.config/google-chrome/Default")
	firefoxDir := rootPath(root, "/home/alice/.mozilla/firefox/abcd.default-release")
	createChromeHistoryDB(t, filepath.Join(chromeDir, "History"))
	createChromeCookiesDB(t, filepath.Join(chromeDir, "Network", "Cookies"))
	writeFixtureFile(t, filepath.Join(chromeDir, "History-wal"), "wal", 0o640)
	writeFixtureFile(t, filepath.Join(chromeDir, "History-shm"), "shm", 0o640)
	writeFixtureFile(t, filepath.Join(chromeDir, "Bookmarks"), `{"roots":{"bookmark_bar":{"type":"folder","name":"Bookmarks Bar","children":[{"type":"url","name":"Saved","url":"https://bookmark.test/","date_added":"11644473600000000"}]}}}`, 0o640)
	createFirefoxPlacesDB(t, filepath.Join(firefoxDir, "places.sqlite"))
	createFirefoxCookiesDB(t, filepath.Join(firefoxDir, "cookies.sqlite"))

	out, outDir := newOutput(t)
	if err := Collect(context.Background(), out); err != nil {
		t.Fatal(err)
	}

	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"browser":"chrome"`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"browser":"firefox"`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"raw_artifact_ref":"ai/raw/browser/chrome/alice/Default/History"`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "https://chrome.test/page")
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "https://firefox.test/page")
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"source_type":"browser_sqlite_copy"`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "/home/alice/Downloads/file")
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"name":"sid"`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"http_only":true`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "https://bookmark.test/")
	assertFileNotContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "cookie-value")
	assertFileNotContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "encrypted_value")
	assertFileContains(t, filepath.Join(outDir, "legacy/browser/chrome/alice_Default_history.out"), "https://chrome.test/page")
	assertFileContains(t, filepath.Join(outDir, "legacy/browser/firefox/alice_abcd.default-release_history.out"), "https://firefox.test/page")
	assertFileContains(t, filepath.Join(outDir, "ai/raw/browser/chrome/alice/Default/History"), "SQLite format 3")
	assertFileContains(t, filepath.Join(outDir, "ai/raw/browser/chrome/alice/Default/History-wal"), "wal")
	assertFileExists(t, filepath.Join(outDir, "ai/raw/browser/chrome/alice/Default/History-shm"))
	assertFileContains(t, filepath.Join(outDir, "ai/raw/browser/chrome/alice/Default/Network_Cookies"), "SQLite format 3")
	assertFileContains(t, filepath.Join(outDir, "legacy/browser/raw/browser/chrome/alice/Default/History"), "SQLite format 3")
}

func TestCollectDamagedSQLiteRecordsError(t *testing.T) {
	root := t.TempDir()
	restore := setBrowserTestHooks(root)
	defer restore()

	writeFixtureFile(t, rootPath(root, "/etc/passwd"), "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n", 0o640)
	writeFixtureFile(t, rootPath(root, "/home/alice/.config/google-chrome/Default/History"), "not sqlite", 0o640)

	out, outDir := newOutput(t)
	if err := Collect(context.Background(), out); err != nil {
		t.Fatal(err)
	}
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "History")
	assertFileContains(t, filepath.Join(outDir, "ai/raw/browser/chrome/alice/Default/History"), "not sqlite")
}

func TestCollectNoProfilesWritesAbsent(t *testing.T) {
	root := t.TempDir()
	restore := setBrowserTestHooks(root)
	defer restore()

	out, outDir := newOutput(t)
	if err := Collect(context.Background(), out); err != nil {
		t.Fatal(err)
	}
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"exists":false`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"exists":false`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"exists":false`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"exists":false`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"exists":false`)
}

func createChromeHistoryDB(t *testing.T, path string) {
	t.Helper()
	db := createSQLite(t, path)
	defer db.Close()
	execSQL(t, db, `CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_time INTEGER)`)
	execSQL(t, db, `CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER)`)
	execSQL(t, db, `CREATE TABLE downloads(id INTEGER PRIMARY KEY, tab_url TEXT, current_path TEXT, target_path TEXT, start_time INTEGER, received_bytes INTEGER, total_bytes INTEGER, state TEXT)`)
	execSQL(t, db, `INSERT INTO urls(id, url, title, visit_count, last_visit_time) VALUES(1, 'https://chrome.test/page', 'Chrome Page', 2, 11644473600000000)`)
	execSQL(t, db, `INSERT INTO visits(id, url, visit_time) VALUES(1, 1, 11644473600000000)`)
	execSQL(t, db, `INSERT INTO downloads(id, tab_url, current_path, target_path, start_time, received_bytes, total_bytes, state) VALUES(1, 'https://chrome.test/file', '/tmp/file', '/home/alice/Downloads/file', 11644473600000000, 100, 200, '1')`)
}

func createChromeCookiesDB(t *testing.T, path string) {
	t.Helper()
	db := createSQLite(t, path)
	defer db.Close()
	execSQL(t, db, `CREATE TABLE cookies(host_key TEXT, name TEXT, value TEXT, encrypted_value BLOB, path TEXT, expires_utc INTEGER, creation_utc INTEGER, last_access_utc INTEGER, is_secure INTEGER, is_httponly INTEGER, samesite INTEGER)`)
	execSQL(t, db, `INSERT INTO cookies(host_key, name, value, encrypted_value, path, expires_utc, creation_utc, last_access_utc, is_secure, is_httponly, samesite) VALUES('.chrome.test', 'sid', 'cookie-value', x'0102', '/', 11644473600000000, 11644473600000000, 11644473600000000, 1, 1, 2)`)
}

func createFirefoxPlacesDB(t *testing.T, path string) {
	t.Helper()
	db := createSQLite(t, path)
	defer db.Close()
	execSQL(t, db, `CREATE TABLE moz_places(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_date INTEGER)`)
	execSQL(t, db, `CREATE TABLE moz_bookmarks(id INTEGER PRIMARY KEY, fk INTEGER, title TEXT, dateAdded INTEGER)`)
	execSQL(t, db, `INSERT INTO moz_places(id, url, title, visit_count, last_visit_date) VALUES(1, 'https://firefox.test/page', 'Firefox Page', 4, 1700000000123456)`)
	execSQL(t, db, `INSERT INTO moz_bookmarks(id, fk, title, dateAdded) VALUES(1, 1, 'FF Saved', 1700000000123456)`)
}

func createFirefoxCookiesDB(t *testing.T, path string) {
	t.Helper()
	db := createSQLite(t, path)
	defer db.Close()
	execSQL(t, db, `CREATE TABLE moz_cookies(host TEXT, name TEXT, value TEXT, path TEXT, expiry INTEGER, creationTime INTEGER, lastAccessed INTEGER, isSecure INTEGER, isHttpOnly INTEGER, sameSite INTEGER)`)
	execSQL(t, db, `INSERT INTO moz_cookies(host, name, value, path, expiry, creationTime, lastAccessed, isSecure, isHttpOnly, sameSite) VALUES('.firefox.test', 'ffsid', 'cookie-value', '/', 1700000000, 1700000000123456, 1700000000123456, 1, 0, 1)`)
}

func createSQLite(t *testing.T, path string) *sql.DB {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func execSQL(t *testing.T, db *sql.DB, stmt string) {
	t.Helper()
	if _, err := db.Exec(stmt); err != nil {
		t.Fatal(err)
	}
}

func setBrowserTestHooks(root string) func() {
	oldFilesystemRoot := filesystemRoot
	filesystemRoot = root
	return func() {
		filesystemRoot = oldFilesystemRoot
	}
}

func assertProfile(t *testing.T, profiles []profile, browserName, user, name string) {
	t.Helper()
	for _, prof := range profiles {
		if prof.Browser == browserName && prof.User == user && prof.Name == name {
			return
		}
	}
	t.Fatalf("missing profile %s/%s/%s: %#v", browserName, user, name, profiles)
}

func newOutput(t *testing.T) (*output.Manager, string) {
	t.Helper()
	outDir := filepath.Join(t.TempDir(), "out")
	out, err := output.New(outDir, "dual", evidence.Session{
		CaseID:    "case-test",
		HostID:    "host-test",
		SessionID: "session-test",
		CreatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return out, outDir
}

func writeFixtureFile(t *testing.T, path, data string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func rootPath(root, sourcePath string) string {
	return filepath.Join(root, strings.TrimPrefix(filepath.Clean(sourcePath), string(filepath.Separator)))
}

func assertFileContains(t *testing.T, path, fragment string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), fragment) {
		t.Fatalf("%s does not contain %q: %s", path, fragment, string(data))
	}
}

func assertFileNotContains(t *testing.T, path, fragment string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), fragment) {
		t.Fatalf("%s unexpectedly contains %q: %s", path, fragment, string(data))
	}
}

func assertFileExists(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}
