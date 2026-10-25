package app

import (
	"archive/zip"
	"bytes"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
	"github.com/steiale/wireguide/internal/config"
	"github.com/steiale/wireguide/internal/domain"
	"github.com/steiale/wireguide/internal/ovpn"
	"github.com/steiale/wireguide/internal/storage"
)

// ZipImportResult holds the outcome of importing one .conf entry from a zip.
type ZipImportResult struct {
	Name  string `json:"name"`
	Error string `json:"error,omitempty"`
}

// zipUniqueName returns a tunnel name that doesn't conflict with existing ones.
func (s *TunnelService) zipUniqueName(base string) string {
	if !s.tunnelStore.Exists(base) {
		return base
	}
	for i := 1; i < 1000; i++ {
		candidate := fmt.Sprintf("%s-%d", base, i)
		if !s.tunnelStore.Exists(candidate) {
			return candidate
		}
	}
	return fmt.Sprintf("%s-%d", base, time.Now().UnixMilli())
}

// ImportZip extracts all .conf and .ovpn files from a zip archive and imports
// each one. Returns per-file results; an error is only returned for zip-level
// failures.
func (s *TunnelService) ImportZip(path string) ([]ZipImportResult, error) {
	if err := s.consumePath(path); err != nil {
		return nil, err
	}
	r, err := zip.OpenReader(path)
	if err != nil {
		return nil, fmt.Errorf("opening zip: %w", err)
	}
	defer r.Close()
	return s.importZipReader(&r.Reader)
}

// ImportZipData imports a zip supplied as raw bytes (used by the file picker,
// which provides a File object rather than a filesystem path).
func (s *TunnelService) ImportZipData(data []byte) ([]ZipImportResult, error) {
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("reading zip: %w", err)
	}
	return s.importZipReader(r)
}

// stripKnownTunnelExt case-insensitively strips a trailing ".conf" or
// ".ovpn" from name and reports which one (lowercased) matched. Plain
// strings.TrimSuffix(name, ".conf") only matches an exact-case suffix, so an
// entry like "Foo.CONF" would pass a case-insensitive HasSuffix check
// elsewhere but come back through TrimSuffix unchanged — leaving the dot
// and extension in the "base name", which then fails tunnel name
// validation. Every caller that both detects and strips one of these two
// extensions should go through this single function so the two checks
// can't disagree with each other again.
func stripKnownTunnelExt(name string) (base, ext string) {
	lower := strings.ToLower(name)
	switch {
	case strings.HasSuffix(lower, ".conf"):
		return name[:len(name)-len(".conf")], ".conf"
	case strings.HasSuffix(lower, ".ovpn"):
		return name[:len(name)-len(".ovpn")], ".ovpn"
	default:
		return name, ""
	}
}

// maxZipEntries caps how many .conf/.ovpn entries one zip import processes.
const maxZipEntries = 500

// importZipReader is the shared implementation for ImportZip and ImportZipData.
// Each entry is imported independently — one failure doesn't abort the rest,
// and each result is keyed to its own filename.
func (s *TunnelService) importZipReader(r *zip.Reader) ([]ZipImportResult, error) {
	var results []ZipImportResult
	seen, skipped := 0, 0
	for _, f := range r.File {
		baseName, ext := stripKnownTunnelExt(filepath.Base(f.Name))
		if ext == "" {
			continue
		}
		// Bound the work (and the number of tunnels created) per archive.
		if seen >= maxZipEntries {
			skipped++
			continue
		}
		seen++
		rc, err := f.Open()
		if err != nil {
			results = append(results, ZipImportResult{Name: filepath.Base(f.Name), Error: err.Error()})
			continue
		}
		// Cap each entry's DECOMPRESSED size, same bound as ReadFile — a
		// .conf/.ovpn is always a few KB, so a crafted entry with a high
		// compression ratio (zip bomb) reading far beyond this is not a
		// real config. Reading one extra byte past the limit lets us
		// distinguish "legitimately hit the cap" from "exactly at it".
		limited := io.LimitReader(rc, maxReadFileSize+1)
		data, err := io.ReadAll(limited)
		rc.Close()
		if err != nil {
			results = append(results, ZipImportResult{Name: filepath.Base(f.Name), Error: err.Error()})
			continue
		}
		if len(data) > maxReadFileSize {
			results = append(results, ZipImportResult{Name: filepath.Base(f.Name), Error: fmt.Sprintf("entry too large (max %d bytes)", maxReadFileSize)})
			continue
		}
		info, importErr := s.importNamed(baseName, ext, string(data))
		if importErr != nil {
			results = append(results, ZipImportResult{Name: baseName, Error: importErr.Error()})
		} else {
			results = append(results, ZipImportResult{Name: info.Name})
		}
	}
	if skipped > 0 {
		results = append(results, ZipImportResult{
			Name:  fmt.Sprintf("%d more entries", skipped),
			Error: fmt.Sprintf("zip contains more than %d .conf/.ovpn entries; %d skipped", maxZipEntries, skipped),
		})
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("no .conf or .ovpn files found in zip")
	}
	return results, nil
}

// ImportConfig parses, validates, and saves a tunnel config under the given
// name. Returns a TunnelInfo for optimistic UI display.
func (s *TunnelService) ImportConfig(name, content string) (*TunnelInfo, error) {
	cfg, err := s.tunnelStore.ImportFromContent(name, content)
	if err != nil {
		return nil, err
	}
	endpoint := ""
	if len(cfg.Peers) > 0 {
		endpoint = cfg.Peers[0].Endpoint
	}
	return &TunnelInfo{
		Name:     cfg.Name,
		Endpoint: endpoint,
		Protocol: domain.ProtocolWireGuard,
	}, nil
}

// importOVPN validates and stores a raw OpenVPN config under the given name,
// writing the .ovpn file plus a .meta.json marking the tunnel as OpenVPN.
func (s *TunnelService) importOVPN(name, content string) (*TunnelInfo, error) {
	if err := storage.ValidateTunnelName(name); err != nil {
		return nil, err
	}
	if err := ovpn.ValidateOVPN([]byte(content)); err != nil {
		return nil, err
	}
	if err := s.tunnelStore.SaveOVPN(name, content); err != nil {
		return nil, err
	}
	// Persist the protocol marker so ListTunnels / Connect route correctly.
	meta, _ := s.tunnelStore.LoadMeta(name)
	if meta == nil {
		meta = &storage.TunnelMeta{}
	}
	meta.Protocol = domain.ProtocolOpenVPN
	if err := s.tunnelStore.SaveMeta(name, meta); err != nil {
		// Roll back the .ovpn file so we don't leave a tunnel with no protocol marker.
		_ = s.tunnelStore.Delete(name)
		return nil, fmt.Errorf("saving openvpn metadata: %w", err)
	}

	endpoint := ""
	if cfg, err := ovpn.ParseOVPN([]byte(content)); err == nil {
		endpoint = cfg.Remote
	}
	return &TunnelInfo{
		Name:     name,
		Endpoint: endpoint,
		Protocol: domain.ProtocolOpenVPN,
	}, nil
}

// sanitizeTunnelName turns a filename-derived base name into one that passes
// storage.ValidateTunnelName: characters outside [A-Za-z0-9 _-] become '-',
// runs of '-' collapse, leading/trailing '-' and spaces are trimmed, and the
// result is capped so zipUniqueName's "-N" suffix still fits in 64 chars.
func sanitizeTunnelName(raw string) string {
	var b strings.Builder
	lastDash := false
	for _, r := range raw {
		valid := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '_' || r == ' ' || r == '-'
		if !valid {
			r = '-'
		}
		if r == '-' && lastDash {
			continue
		}
		lastDash = r == '-'
		b.WriteRune(r)
	}
	trim := func(v string) string { return strings.Trim(v, "- ") }
	name := trim(b.String())
	if len(name) > 56 {
		name = trim(name[:56])
	}
	if name == "" || storage.ValidateTunnelName(name) != nil {
		return "tunnel"
	}
	return name
}

// importNamed sanitizes base, picks a free tunnel name for it, and imports
// content as OpenVPN (ext ".ovpn") or WireGuard (anything else). The
// returned TunnelInfo carries the final name actually used.
func (s *TunnelService) importNamed(base, ext, content string) (*TunnelInfo, error) {
	name := s.zipUniqueName(sanitizeTunnelName(base))
	if ext == ".ovpn" {
		return s.importOVPN(name, content)
	}
	return s.ImportConfig(name, content)
}

// ImportFile imports one config file. filename (a bare name or a path) picks
// the protocol by extension (.ovpn → OpenVPN, else WireGuard) and supplies
// the tunnel name, which is sanitized and made unique. Returns the stored
// tunnel, including its final name.
func (s *TunnelService) ImportFile(filename, content string) (*TunnelInfo, error) {
	base, ext := stripKnownTunnelExt(filepath.Base(filename))
	return s.importNamed(base, ext, content)
}

// maxReadFileSize is the largest file ReadFile will accept (10 MB).
// WireGuard configs are typically a few KB; anything larger is almost
// certainly not a valid .conf file.
const maxReadFileSize = 10 << 20

// ReadFile reads a file from disk (used by native file drop). Returns the
// content as a string so the frontend can handle name conflicts before import.
// Only paths granted by the Go side (drop events) are readable, once each.
func (s *TunnelService) ReadFile(path string) (string, error) {
	if err := s.consumePath(path); err != nil {
		return "", err
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", path, err)
	}
	if info.Size() > maxReadFileSize {
		return "", fmt.Errorf("file %s is too large (%d bytes, max %d)", path, info.Size(), maxReadFileSize)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", path, err)
	}
	return string(data), nil
}

// ValidateConfig parses and validates a raw config string. Returns a list of
// human-readable error messages, or nil if the config is valid.
func (s *TunnelService) ValidateConfig(content string) ([]string, error) {
	cfg, err := config.Parse(content)
	if err != nil {
		return []string{err.Error()}, nil
	}
	result := config.Validate(cfg)
	if result.IsValid() {
		return nil, nil
	}
	return result.ErrorMessages(), nil
}

// GetConfigText returns the stored tunnel config as text. For OpenVPN tunnels
// the raw .ovpn content is returned; for WireGuard the serialized INI form.
func (s *TunnelService) GetConfigText(name string) (string, error) {
	if s.tunnelStore.IsOVPN(name) {
		return s.tunnelStore.LoadOVPN(name)
	}
	cfg, err := s.tunnelStore.Load(name)
	if err != nil {
		return "", err
	}
	return config.Serialize(cfg), nil
}

// UpdateConfig parses, validates, and overwrites an existing tunnel's config.
// Rejects edits of a tunnel the helper tracks (running, reconnecting or
// blocked). Routes to the OpenVPN path for .ovpn
// tunnels so the raw config is saved without WireGuard parsing.
func (s *TunnelService) UpdateConfig(name, content string) error {
	tracked, err := s.isTunnelTracked(name)
	if err != nil {
		return fmt.Errorf("cannot verify tunnel state: %w", err)
	}
	if tracked {
		return fmt.Errorf("cannot edit tunnel %q while it is connected, reconnecting or blocked — disconnect first", name)
	}
	if s.tunnelStore.IsOVPN(name) {
		if err := ovpn.ValidateOVPN([]byte(content)); err != nil {
			return fmt.Errorf("invalid .ovpn config: %w", err)
		}
		return s.tunnelStore.SaveOVPN(name, content)
	}
	cfg, err := config.Parse(content)
	if err != nil {
		return err
	}
	result := config.Validate(cfg)
	if !result.IsValid() {
		return fmt.Errorf("validation failed: %s", strings.Join(result.ErrorMessages(), "; "))
	}
	cfg.Name = name
	return s.tunnelStore.Save(cfg)
}

// decodeQRFromImage decodes a WireGuard config from a QR code in an image.
func decodeQRFromImage(img image.Image) (string, error) {
	bmp, err := gozxing.NewBinaryBitmapFromImage(img)
	if err != nil {
		return "", err
	}
	result, err := qrcode.NewQRCodeReader().Decode(bmp, nil)
	if err != nil {
		return "", fmt.Errorf("no WireGuard QR code found in image")
	}
	return result.GetText(), nil
}

// ImportQRFromPath reads an image file, decodes its QR code, and imports the
// WireGuard config under a name derived from the file name. Returns the
// final tunnel name.
func (s *TunnelService) ImportQRFromPath(path string) (string, error) {
	if err := s.consumePath(path); err != nil {
		return "", err
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if info.Size() > maxQRImageBytes {
		return "", fmt.Errorf("image too large (%d bytes, max %d)", info.Size(), maxQRImageBytes)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return s.ImportQRFromBytes(data, path)
}

// maxQRImageBytes bounds the raw input to ImportQRFromBytes. A legitimate
// QR code screenshot or phone photo is a few MB at most.
const maxQRImageBytes = 20 << 20

// maxQRImagePixels bounds decoded image area, checked via image.DecodeConfig
// (header-only, cheap) BEFORE the full pixel decode. Without this, a small
// file with a crafted header declaring an enormous width/height can make
// the decoder allocate memory proportional to the DECLARED dimensions, not
// the input file size — a decompression-bomb-style DoS. 8000x8000 is far
// beyond any real QR photo.
const maxQRImagePixels = 8000 * 8000

// ImportQRFromBytes decodes a QR code from raw image bytes and imports the
// WireGuard config under a name derived from filename (sanitized, made
// unique). Used by the file-picker path where the browser API provides bytes
// rather than a filesystem path. Returns the final tunnel name.
func (s *TunnelService) ImportQRFromBytes(data []byte, filename string) (string, error) {
	if len(data) > maxQRImageBytes {
		return "", fmt.Errorf("image too large (%d bytes, max %d)", len(data), maxQRImageBytes)
	}
	if cfg, _, err := image.DecodeConfig(bytes.NewReader(data)); err == nil {
		if pixels := int64(cfg.Width) * int64(cfg.Height); pixels > maxQRImagePixels {
			return "", fmt.Errorf("image dimensions too large (%dx%d)", cfg.Width, cfg.Height)
		}
	}
	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("cannot decode image: %w", err)
	}
	text, err := decodeQRFromImage(img)
	if err != nil {
		return "", err
	}
	if !strings.Contains(text, "[Interface]") {
		return "", fmt.Errorf("no WireGuard QR code found in image")
	}
	base := filepath.Base(filename)
	base = strings.TrimSuffix(base, filepath.Ext(base))
	info, err := s.importNamed(base, ".conf", text)
	if err != nil {
		return "", err
	}
	return info.Name, nil
}

// ExportTunnel shows a native save dialog and writes the .conf file.
// Returns the saved path, or empty string if the user cancelled.
func (s *TunnelService) ExportTunnel(name string) (string, error) {
	content, err := s.GetConfigText(name)
	if err != nil {
		return "", err
	}
	if s.app == nil {
		return "", fmt.Errorf("app not initialized")
	}

	isOvpn := s.tunnelStore.IsOVPN(name)
	dlg := s.app.Dialog.SaveFile()
	if isOvpn {
		dlg = dlg.SetFilename(name+".ovpn").AddFilter("OpenVPN Config", "*.ovpn")
	} else {
		dlg = dlg.SetFilename(name+".conf").AddFilter("WireGuard Config", "*.conf")
	}
	path, err := dlg.PromptForSingleSelection()
	if err != nil {
		return "", err
	}
	if path == "" {
		return "", nil // user cancelled
	}

	// Exported files contain private keys — write with 0600.
	if err := writePrivateFile(path, []byte(content)); err != nil {
		return "", err
	}
	return path, nil
}

// ExportAllTunnels bundles every stored tunnel's config into a single zip
// (mirroring ImportZip's format, so the result can be re-imported directly)
// via a native save dialog. Returns the saved path, or empty string if the
// user cancelled or there are no tunnels to export.
func (s *TunnelService) ExportAllTunnels() (string, error) {
	names, err := s.tunnelStore.List()
	if err != nil {
		return "", err
	}
	if len(names) == 0 {
		return "", fmt.Errorf("no tunnels to export")
	}
	if s.app == nil {
		return "", fmt.Errorf("app not initialized")
	}

	path, err := s.app.Dialog.SaveFile().
		SetFilename("lockplus-tunnels.zip").
		AddFilter("Zip Archive", "*.zip").
		PromptForSingleSelection()
	if err != nil {
		return "", err
	}
	if path == "" {
		return "", nil // user cancelled
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	usedNames := make(map[string]bool, len(names))
	for _, name := range names {
		content, err := s.GetConfigText(name)
		if err != nil {
			continue // skip tunnels that fail to serialize rather than aborting the whole export
		}
		ext := ".conf"
		if s.tunnelStore.IsOVPN(name) {
			ext = ".ovpn"
		}
		entryName := name + ext
		for i := 1; usedNames[entryName]; i++ {
			entryName = fmt.Sprintf("%s-%d%s", name, i, ext)
		}
		usedNames[entryName] = true

		w, err := zw.Create(entryName)
		if err != nil {
			zw.Close()
			return "", err
		}
		if _, err := w.Write([]byte(content)); err != nil {
			zw.Close()
			return "", err
		}
	}
	if err := zw.Close(); err != nil {
		return "", err
	}

	// The zip contains private keys/credentials for every tunnel — write
	// with 0600, same as a single-tunnel export.
	if err := writePrivateFile(path, buf.Bytes()); err != nil {
		return "", err
	}
	return path, nil
}

// writePrivateFile writes data to path for an export containing secrets.
// Unlike os.WriteFile(…, 0600) it refuses to follow a symlink at path
// (O_NOFOLLOW) and forces 0600 on a pre-existing file, whose mode
// os.WriteFile would otherwise leave untouched. The fchmod happens before any
// data is written, so secrets never land in a group/world-readable file.
func writePrivateFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
