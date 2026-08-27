package selfupdate

import (
	"os"
	"path/filepath"
)

// atomicInstall replaces the binary at path with data as atomically as the
// OS permits: it writes a sibling temp file, backs up the original, renames
// the new file into place, and restores the backup on failure. It never
// leaves a partial install.
func atomicInstall(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".shaka-update-*")
	if err != nil {
		return upErr(KindPermission, "creating staging file: "+err.Error(), err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return upErr(KindInstall, "writing staged binary", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return upErr(KindInstall, "syncing staged binary", err)
	}
	if err := tmp.Close(); err != nil {
		return upErr(KindInstall, "closing staged binary", err)
	}
	if err := os.Chmod(tmpName, 0o755); err != nil {
		return upErr(KindInstall, "setting permissions", err)
	}

	// Back up the current binary if present.
	backup := path + ".bak"
	haveBackup := false
	if _, err := os.Stat(path); err == nil {
		if err := copyFile(path, backup); err != nil {
			return upErr(KindInstall, "backing up current binary", err)
		}
		haveBackup = true
	}

	if err := os.Rename(tmpName, path); err != nil {
		if haveBackup {
			_ = os.Rename(backup, path)
		}
		return upErr(KindPermission, "replacing binary: "+err.Error(), err)
	}

	if haveBackup {
		_ = os.Remove(backup)
	}
	return nil
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o755)
}
