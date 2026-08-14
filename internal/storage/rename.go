package storage

import (
	"os"
	"path/filepath"
)

// atomicRename moves src to dst. On modern Go (1.21+), os.Rename uses
// MoveFileEx with MOVEFILE_REPLACE_EXISTING on Windows, so it handles
// overwriting the destination atomically on all platforms.
func atomicRename(src, dst string) error {
	if err := os.Rename(src, dst); err != nil {
		return err
	}
	// Best-effort: fsync the containing directory so the rename's directory
	// entry update is durable across a hard crash/power loss, not just the
	// file content itself (which the caller already fsync'd before this
	// rename). Errors are ignored — this is a POSIX concept that doesn't
	// translate cleanly to Windows (opening a directory handle this way
	// isn't reliably syncable there), and the rename itself has already
	// succeeded regardless of whether this extra durability step works.
	if dir, err := os.Open(filepath.Dir(dst)); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}
