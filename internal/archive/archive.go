package archive

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"linux-dfir/internal/evidence"
	"linux-dfir/internal/integrity"
)

type Options struct {
	Prefix string
}

type Summary struct {
	SchemaVersion   string         `json:"schema_version"`
	SourceDir       string         `json:"source_dir"`
	Archive         ArchiveInfo    `json:"archive"`
	ArtifactCount   int            `json:"artifact_count"`
	FileCount       int            `json:"file_count"`
	DirectoryCount  int            `json:"directory_count"`
	SymlinkCount    int            `json:"symlink_count"`
	SkippedCount    int            `json:"skipped_count"`
	Skipped         []SkippedEntry `json:"skipped,omitempty"`
	CreatedAt       time.Time      `json:"created_at"`
	ManifestPath    string         `json:"manifest_path"`
	SummaryLocation string         `json:"summary_location"`
}

type ArchiveInfo struct {
	Format      string    `json:"format"`
	Path        string    `json:"path"`
	Name        string    `json:"name"`
	Size        int64     `json:"size"`
	SHA256      string    `json:"sha256"`
	MD5         string    `json:"md5"`
	GeneratedAt time.Time `json:"generated_at"`
}

type SkippedEntry struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

func CreateTarGz(sourceDir, archivePath string, opts Options) (Summary, error) {
	sourceAbs, err := filepath.Abs(sourceDir)
	if err != nil {
		return Summary{}, err
	}
	archiveAbs, err := filepath.Abs(archivePath)
	if err != nil {
		return Summary{}, err
	}
	info, err := os.Lstat(sourceAbs)
	if err != nil {
		return Summary{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return Summary{}, fmt.Errorf("source directory must not be a symlink: %s", sourceAbs)
	}
	if !info.IsDir() {
		return Summary{}, fmt.Errorf("source is not a directory: %s", sourceAbs)
	}
	sourceReal, err := filepath.EvalSymlinks(sourceAbs)
	if err != nil {
		return Summary{}, err
	}
	archiveParent := filepath.Dir(archiveAbs)
	if err := os.MkdirAll(archiveParent, 0o750); err != nil {
		return Summary{}, err
	}
	archiveParentReal, err := filepath.EvalSymlinks(archiveParent)
	if err != nil {
		return Summary{}, err
	}
	archiveReal := filepath.Join(archiveParentReal, filepath.Base(archiveAbs))
	if pathInside(sourceReal, archiveReal) {
		return Summary{}, fmt.Errorf("archive path must be outside source directory: %s", archiveAbs)
	}
	prefix := sanitizePrefix(opts.Prefix)
	if prefix == "" {
		prefix = sanitizePrefix(filepath.Base(sourceAbs))
	}
	if prefix == "" {
		prefix = "evidence"
	}
	if err := rejectSymlink(archiveAbs); err != nil {
		return Summary{}, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(archiveAbs), ".tmp-"+filepath.Base(archiveAbs)+"-")
	if err != nil {
		return Summary{}, err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()

	gz := gzip.NewWriter(tmp)
	tw := tar.NewWriter(gz)
	summary := Summary{
		SchemaVersion:   evidence.SchemaVersion,
		SourceDir:       sourceAbs,
		CreatedAt:       time.Now().UTC(),
		ManifestPath:    filepath.ToSlash(filepath.Join(prefix, "ai", "manifest.json")),
		SummaryLocation: "external: ai/archive_summary.json",
	}
	if err := addTree(tw, sourceAbs, prefix, &summary); err != nil {
		_ = tw.Close()
		_ = gz.Close()
		_ = tmp.Close()
		return Summary{}, err
	}
	if err := tw.Close(); err != nil {
		_ = gz.Close()
		_ = tmp.Close()
		return Summary{}, err
	}
	if err := gz.Close(); err != nil {
		_ = tmp.Close()
		return Summary{}, err
	}
	if err := tmp.Chmod(0o640); err != nil {
		_ = tmp.Close()
		return Summary{}, err
	}
	if err := tmp.Close(); err != nil {
		return Summary{}, err
	}
	if err := os.Rename(tmpName, archiveAbs); err != nil {
		return Summary{}, err
	}
	cleanup = false

	hash, err := integrity.HashFile(archiveAbs)
	if err != nil {
		return Summary{}, err
	}
	summary.Archive = ArchiveInfo{
		Format:      "tar.gz",
		Path:        archiveAbs,
		Name:        filepath.Base(archiveAbs),
		Size:        hash.Size,
		SHA256:      hash.SHA256,
		MD5:         hash.MD5,
		GeneratedAt: time.Now().UTC(),
	}
	summary.ArtifactCount = manifestArtifactCount(filepath.Join(sourceAbs, "ai", "manifest.json"))
	sort.Slice(summary.Skipped, func(i, j int) bool { return summary.Skipped[i].Path < summary.Skipped[j].Path })
	summary.SkippedCount = len(summary.Skipped)
	return summary, nil
}

func WriteSummary(path string, summary Summary) error {
	if err := rejectSymlink(path); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-"+filepath.Base(path)+"-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Chmod(0o640); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}

func addTree(tw *tar.Writer, sourceAbs, prefix string, summary *Summary) error {
	return filepath.WalkDir(sourceAbs, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			skip(summary, path, err.Error())
			if entry != nil && entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(sourceAbs, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		name := filepath.ToSlash(filepath.Join(prefix, rel))
		if err := validateEntryName(name); err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			skip(summary, name, err.Error())
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				skip(summary, name, err.Error())
				return nil
			}
			if unsafeSymlinkTarget(target) {
				skip(summary, name, "symlink target escapes archive root")
				return nil
			}
			header, err := tar.FileInfoHeader(info, target)
			if err != nil {
				return err
			}
			header.Name = name
			if err := tw.WriteHeader(header); err != nil {
				return err
			}
			summary.SymlinkCount++
			return nil
		}
		if info.IsDir() {
			header, err := tar.FileInfoHeader(info, "")
			if err != nil {
				return err
			}
			header.Name = strings.TrimSuffix(name, "/") + "/"
			if err := tw.WriteHeader(header); err != nil {
				return err
			}
			summary.DirectoryCount++
			return nil
		}
		if !info.Mode().IsRegular() {
			skip(summary, name, "unsupported special file")
			return nil
		}
		file, err := os.Open(path)
		if err != nil {
			skip(summary, name, err.Error())
			return nil
		}
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			_ = file.Close()
			return err
		}
		header.Name = name
		if err := tw.WriteHeader(header); err != nil {
			_ = file.Close()
			return err
		}
		_, copyErr := io.Copy(tw, file)
		closeErr := file.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		summary.FileCount++
		return nil
	})
}

func manifestArtifactCount(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	var manifest evidence.Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return 0
	}
	return manifest.ArtifactCount
}

func validateEntryName(name string) error {
	if name == "" || filepath.IsAbs(name) {
		return fmt.Errorf("invalid archive entry path: %s", name)
	}
	clean := filepath.Clean(name)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || strings.Contains(clean, string(filepath.Separator)+".."+string(filepath.Separator)) {
		return fmt.Errorf("archive entry path escapes root: %s", name)
	}
	return nil
}

func pathInside(root, path string) bool {
	root = filepath.Clean(root)
	path = filepath.Clean(path)
	return path == root || strings.HasPrefix(path, root+string(filepath.Separator))
}

func unsafeSymlinkTarget(target string) bool {
	if target == "" {
		return true
	}
	if filepath.IsAbs(target) {
		return true
	}
	clean := filepath.Clean(target)
	return clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator))
}

func sanitizePrefix(prefix string) string {
	prefix = strings.TrimSpace(prefix)
	prefix = strings.Trim(prefix, `/\`)
	if prefix == "" {
		return ""
	}
	prefix = filepath.ToSlash(filepath.Clean(prefix))
	if prefix == "." || strings.HasPrefix(prefix, "../") || strings.Contains(prefix, "/../") || strings.HasPrefix(prefix, "/") {
		return ""
	}
	return prefix
}

func rejectSymlink(path string) error {
	info, err := os.Lstat(path)
	if err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("archive output must not be a symlink: %s", path)
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func skip(summary *Summary, path, reason string) {
	summary.Skipped = append(summary.Skipped, SkippedEntry{Path: filepath.ToSlash(path), Reason: reason})
}
