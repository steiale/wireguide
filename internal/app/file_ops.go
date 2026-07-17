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
	"time"

	"github.com/steiale/wireguide/internal/config"
	"github.com/steiale/wireguide/internal/domain"
	"github.com/steiale/wireguide/internal/ovpn"
	"github.com/steiale/wireguide/internal/storage"
	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
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

// importZipReader is the shared implementation for ImportZip and ImportZipData.
// Each entry is imported independently — one failure doesn't abort the rest,
// and each result is keyed to its own filename.
func (s *TunnelService) importZipReader(r *zip.Reader) ([]ZipImportResult, error) {
	var results []ZipImportResult
	for _, f := range r.File {
		baseName, ext := stripKnownTunnelExt(filepath.Base(f.Name))
		if ext == "" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			results = append(results, ZipImportResult{Name: filepath.Base(f.Name), Error: err.Error()})
			continue
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			results = append(results, ZipImportResult{Name: filepath.Base(f.Name), Error: err.Error()})
			continue
		}
		name := s.zipUniqueName(baseName)
		var importErr error
		switch ext {
		case ".ovpn":
			_, importErr = s.ImportOVPN(name, string(data))
		default:
			_, importErr = s.ImportConfig(name, string(data))
		}
		if importErr != nil {
			results = append(results, ZipImportResult{Name: baseName, Error: importErr.Error()})
		} else {
			results = append(results, ZipImportResult{Name: name})
		}
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

// ImportOVPN validates and stores a raw OpenVPN config under the given name,
// writing the .ovpn file plus a .meta.json marking the tunnel as OpenVPN.
func (s *TunnelService) ImportOVPN(name, content string) (*TunnelInfo, error) {
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

// ImportFile dispatches to the correct importer based on the source filename's
// extension: .ovpn → OpenVPN, everything else → WireGuard. Used by the native
// file-drop / picker paths which know the original filename.
func (s *TunnelService) ImportFile(name, content, filename string) (*TunnelInfo, error) {
	if strings.HasSuffix(strings.ToLower(filename), ".ovpn") {
		return s.ImportOVPN(name, content)
	}
	return s.ImportConfig(name, content)
}

// maxReadFileSize is the largest file ReadFile will accept (10 MB).
// WireGuard configs are typically a few KB; anything larger is almost
// certainly not a valid .conf file.
const maxReadFileSize = 10 << 20

// ReadFile reads a file from disk (used by native file drop). Returns the
// content as a string so the frontend can handle name conflicts before import.
func (s *TunnelService) ReadFile(path string) (string, error) {
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

// BaseName extracts the filename without extension from a path.
func (s *TunnelService) BaseName(path string) string {
	return strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
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
// Rejects edits of the connected tunnel. Routes to the OpenVPN path for .ovpn
// tunnels so the raw config is saved without WireGuard parsing.
func (s *TunnelService) UpdateConfig(name, content string) error {
	active, err := s.isTunnelActive(name)
	if err != nil {
		return fmt.Errorf("cannot verify tunnel state: %w", err)
	}
	if active {
		return fmt.Errorf("cannot edit connected tunnel %q — disconnect first", name)
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

// ExportConfig returns the serialized text for display in the export dialog.
func (s *TunnelService) ExportConfig(name string) (string, error) {
	return s.GetConfigText(name)
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
// WireGuard config under the given name.
func (s *TunnelService) ImportQRFromPath(path, name string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return s.ImportQRFromBytes(data, name)
}

// ImportQRFromBytes decodes a QR code from raw image bytes and imports the
// WireGuard config under the given name. Used by the file-picker path where
// the browser API provides bytes rather than a filesystem path.
func (s *TunnelService) ImportQRFromBytes(data []byte, name string) error {
	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("cannot decode image: %w", err)
	}
	text, err := decodeQRFromImage(img)
	if err != nil {
		return err
	}
	if !strings.Contains(text, "[Interface]") {
		return fmt.Errorf("no WireGuard QR code found in image")
	}
	_, err = s.tunnelStore.ImportFromContent(name, text)
	return err
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
		dlg = dlg.SetFilename(name + ".ovpn").AddFilter("OpenVPN Config", "*.ovpn")
	} else {
		dlg = dlg.SetFilename(name + ".conf").AddFilter("WireGuard Config", "*.conf")
	}
	path, err := dlg.PromptForSingleSelection()
	if err != nil {
		return "", err
	}
	if path == "" {
		return "", nil // user cancelled
	}

	// Exported files contain private keys — write with 0600.
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		return "", err
	}
	return path, nil
}
