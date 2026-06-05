package container

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"linux-dfir/internal/evidence"
	"linux-dfir/internal/output"
)

const dockerID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestContainerHintFromCgroupPaths(t *testing.T) {
	docker := ContainerHintFromPath("/docker/" + dockerID)
	if docker.ID != dockerID || docker.Runtime != "docker" || docker.Confidence != "high" {
		t.Fatalf("unexpected docker hint: %#v", docker)
	}
	kube := ContainerHintFromPath("/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podabc_def.slice/cri-containerd-" + dockerID + ".scope")
	if kube.ID != dockerID || kube.Runtime != "containerd" || kube.PodUID != "abc-def" {
		t.Fatalf("unexpected kube hint: %#v", kube)
	}
	ordinary := ContainerHintFromPath("/user.slice/user-501.slice/session-2.scope")
	if ordinary.ID != "" || ordinary.Runtime != "" {
		t.Fatalf("ordinary cgroup should not be a container: %#v", ordinary)
	}
}

func TestReadCgroupFile(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "cgroup")
	writeFixtureFile(t, path, "12:memory,cpu:/docker/"+dockerID+"\n0::/user.slice\n", 0o640)
	entries, err := ReadCgroupFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Controllers[0] != "memory" || entries[1].Path != "/user.slice" {
		t.Fatalf("unexpected cgroups: %#v", entries)
	}
}

func TestCollectWithFixtureContainer(t *testing.T) {
	root := t.TempDir()
	proc := filepath.Join(root, "proc")
	restore := SetRootsForTest(root, proc)
	defer restore()

	writeProc(t, proc, 123, "worker", "122", "1000", "1000", []string{"/app/worker", "--serve"}, "12:memory,cpu:/docker/"+dockerID+"\n")
	if err := os.MkdirAll(filepath.Join(proc, "123", "ns"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("pid:[4026532444]", filepath.Join(proc, "123", "ns", "pid")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("mnt:[4026532445]", filepath.Join(proc, "123", "ns", "mnt")); err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, rootPath(root, "/var/lib/docker/containers/"+dockerID+"/config.v2.json"), `{"ID":"`+dockerID+`","Name":"/demo","Image":"sha256:abc"}`, 0o640)

	out, outDir := newOutput(t)
	if err := Collect(context.Background(), out); err != nil {
		t.Fatal(err)
	}

	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"container_id":"`+dockerID+`"`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"stream":"entities/container"`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"stream":"facts/process_containers"`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"stream":"facts/cgroups"`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"stream":"facts/namespaces"`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"stream":"artifacts/runtime_metadata"`)
	assertFileNotContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"stream":"parsed/`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"name":"demo"`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"container_id":"`+dockerID+`"`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"pid":123`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"runtime":"docker"`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"pid":123`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "docker overlay mount present")
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "/docker/"+dockerID)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"inode":"4026532444"`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"image":"sha256:abc"`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"raw_copy_ref":"ai/raw/container/runtime_metadata/docker/`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"entity_type":"container"`)
	assertFileContains(t, filepath.Join(outDir, "legacy/container/container_processes.out"), "worker")
	assertFileContains(t, filepath.Join(outDir, "legacy/container/namespaces.out"), "4026532444")
	assertFileContains(t, filepath.Join(outDir, "legacy/container/container_context.out"), "Linux DFIR container context")
	assertFileContains(t, filepath.Join(outDir, "legacy/container/cgroups.out"), "stream facts/cgroups in ai/evidence.jsonl")
}

func TestCollectMissingProcWritesAbsent(t *testing.T) {
	root := t.TempDir()
	restore := SetRootsForTest(root, filepath.Join(root, "missing-proc"))
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
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"exists":false`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"exists":false`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "missing-proc")
}

func TestCollectMissingProcDoesNotReadRuntimeMetadata(t *testing.T) {
	root := t.TempDir()
	restore := SetRootsForTest(root, filepath.Join(root, "missing-proc"))
	defer restore()

	writeFixtureFile(t, rootPath(root, "/var/lib/docker/containers/"+dockerID+"/config.v2.json"), `{"ID":"`+dockerID+`","Name":"/demo","Image":"sha256:abc"}`, 0o640)

	out, outDir := newOutput(t)
	if err := Collect(context.Background(), out); err != nil {
		t.Fatal(err)
	}
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"exists":false`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"exists":false`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"exists":false`)
	if _, err := os.Stat(filepath.Join(outDir, "ai/raw/container/runtime_metadata")); !os.IsNotExist(err) {
		t.Fatalf("runtime metadata raw copy should not exist without procfs, err=%v", err)
	}
	data, err := os.ReadFile(filepath.Join(outDir, "ai/evidence.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), dockerID) {
		t.Fatalf("containers output should not include runtime metadata without procfs: %s", string(data))
	}
}

func SetRootsForTest(fsRoot, proc string) func() {
	oldFS := filesystemRoot
	oldProc := procRoot
	filesystemRoot = fsRoot
	procRoot = proc
	return func() {
		filesystemRoot = oldFS
		procRoot = oldProc
	}
}

func writeProc(t *testing.T, procRoot string, pid int, name, ppid, uid, gid string, cmdline []string, cgroup string) {
	t.Helper()
	base := filepath.Join(procRoot, stringPID(pid))
	status := "Name:\t" + name + "\nPPid:\t" + ppid + "\nUid:\t" + uid + "\t" + uid + "\t" + uid + "\t" + uid + "\nGid:\t" + gid + "\t" + gid + "\t" + gid + "\t" + gid + "\nState:\tS (sleeping)\n"
	writeFixtureFile(t, filepath.Join(base, "status"), status, 0o640)
	writeFixtureFile(t, filepath.Join(base, "cmdline"), strings.Join(cmdline, "\x00")+"\x00", 0o640)
	writeFixtureFile(t, filepath.Join(base, "environ"), "", 0o640)
	writeFixtureFile(t, filepath.Join(base, "maps"), "", 0o640)
	writeFixtureFile(t, filepath.Join(base, "cgroup"), cgroup, 0o640)
	writeFixtureFile(t, filepath.Join(base, "mountinfo"), "36 25 0:32 / / rw,relatime - overlay overlay rw,upperdir=/var/lib/docker/overlay2/upper\n", 0o640)
	if err := os.MkdirAll(filepath.Join(base, "fd"), 0o750); err != nil {
		t.Fatal(err)
	}
}

func stringPID(pid int) string {
	return strconv.Itoa(pid)
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
