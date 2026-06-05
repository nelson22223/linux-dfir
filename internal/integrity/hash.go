package integrity

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

type FileHash struct {
	SHA256 string
	MD5    string
	Size   int64
}

func HashFile(path string) (FileHash, error) {
	f, err := os.Open(path)
	if err != nil {
		return FileHash{}, err
	}
	defer f.Close()

	sha := sha256.New()
	md5h := md5.New()
	size, err := io.Copy(io.MultiWriter(sha, md5h), f)
	if err != nil {
		return FileHash{}, fmt.Errorf("hash %s: %w", path, err)
	}
	return FileHash{
		SHA256: hex.EncodeToString(sha.Sum(nil)),
		MD5:    hex.EncodeToString(md5h.Sum(nil)),
		Size:   size,
	}, nil
}
