// Package update checks for new releases and handles auto-update.
package update

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	githubRepo  = "steiale/wireguide"
	apiEndpoint = "https://api.github.com/repos/" + githubRepo + "/releases/latest"
	// fallbackVersion is the build-time constant used when the running
	// bundle's Info.plist cannot be read (e.g. unit tests, non-darwin
	// builds, or running the bare binary without an enclosing .app).
	// Keep this in sync with build/darwin/Info.plist on each release.
	fallbackVersion = "1.0.67"

	// minAssetSize is the minimum acceptable size for a release asset.
	// A macOS .dmg/.zip containing WireGuide.app is always well over 1 MB;
	// anything smaller is almost certainly corrupted or a placeholder file
	// injected by an attacker.
	minAssetSize = 1 << 20 // 1 MB

	// maxSignatureSize bounds how many bytes we read from a `.sig` URL.
	// An Ed25519 signature is exactly 64 bytes; anything larger is bogus.
	maxSignatureSize = 1 << 10 // 1 KB (huge margin over 64 bytes)
)

// requireSignature controls whether a missing or invalid Ed25519 signature
// aborts the install. Verified true for the current release (v1.0.62 has
// lockplus-v1.0.62-darwin-arm64.zip.sig on GitHub) and every release since
// v1.0.20 — the update flow only ever checks the LATEST release regardless
// of what version the caller is currently running, so historical releases
// without a .sig don't matter here. This is now the primary cryptographic
// authenticity guarantee: unlike a checksum file (which lives in the same,
// potentially-compromised release), the Ed25519 private key never touches
// release infrastructure.
//
// A var, not a const, so tests can flip it to false to isolate other
// validation logic (checksum/size/content-length) from the signature
// requirement — same rationale as embeddedPublicKey below being a var;
// production code never reassigns either.
var requireSignature = true

// embeddedPublicKey is the base64-encoded Ed25519 public key used to verify
// release signatures. The matching private key is kept offline and used to
// sign each release zip via `go run ./cmd/sign`. Replacing this value
// invalidates every previously-signed release.
//
// It is a var rather than a const so tests can substitute a known-good
// keypair; production code never reassigns it.
//
// To rotate: run `go run ./cmd/sign --gen`, replace this value with the new
// PUBLIC_KEY, and re-sign any release that should remain installable by
// clients shipped after the rotation.
var embeddedPublicKey = "rq0nNHFzXOrC8zEmipTbresfBioQ6UTe3MldLFPk+hA="

var (
	versionOnce   sync.Once
	cachedVersion string
)

// CurrentVersion returns the running app's version string. On macOS it
// reads CFBundleShortVersionString from the enclosing .app bundle's
// Info.plist (located at ../Info.plist relative to the executable). If
// that lookup fails for any reason we fall back to the build-time
// fallbackVersion constant. The result is cached for the lifetime of
// the process.
func CurrentVersion() string {
	versionOnce.Do(func() {
		if v := readBundleVersion(); v != "" {
			cachedVersion = v
			return
		}
		cachedVersion = fallbackVersion
	})
	return cachedVersion
}

// readBundleVersion attempts to read CFBundleShortVersionString from the
// running .app bundle's Info.plist. Returns "" on any failure so the
// caller can fall back to the build-time constant.
func readBundleVersion() string {
	if runtime.GOOS != "darwin" {
		return ""
	}
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	// Resolve symlinks so /Applications/LockPlus.app/Contents/MacOS/lockplus
	// (or a Homebrew-installed cask, which uses copies, not symlinks) both work.
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	// Bundle layout: <App>.app/Contents/MacOS/<binary>
	// Info.plist sits at <App>.app/Contents/Info.plist (../Info.plist).
	plistPath := filepath.Join(filepath.Dir(exe), "..", "Info.plist")
	data, err := os.ReadFile(plistPath)
	if err != nil {
		return ""
	}
	return parseShortVersion(data)
}

// parseShortVersion extracts CFBundleShortVersionString from a plist's
// XML body using a simple regex. Avoids pulling in an XML/plist library
// for what is a trivial, well-known shape.
var shortVersionRe = regexp.MustCompile(`<key>\s*CFBundleShortVersionString\s*</key>\s*<string>\s*([^<\s][^<]*?)\s*</string>`)

func parseShortVersion(data []byte) string {
	m := shortVersionRe.FindSubmatch(data)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(string(m[1]))
}

// Release represents a GitHub release.
type Release struct {
	TagName     string  `json:"tag_name"`
	Name        string  `json:"name"`
	Body        string  `json:"body"`
	PublishedAt string  `json:"published_at"`
	HTMLURL     string  `json:"html_url"`
	Assets      []Asset `json:"assets"`
}

// Asset represents a downloadable file in a release.
type Asset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
}

// UpdateInfo contains information about an available update.
type UpdateInfo struct {
	Available         bool   `json:"available"`
	Version           string `json:"version"`
	CurrentVer        string `json:"current_version"`
	ReleaseURL        string `json:"release_url"`
	DownloadURL       string `json:"download_url"`
	ReleaseNotes      string `json:"release_notes"`
	AssetName         string `json:"asset_name"`
	AssetSize         int64  `json:"asset_size"`
	ChecksumURL       string `json:"checksum_url,omitempty"`  // URL to SHA256SUMS file
	ExpectedHash      string `json:"expected_hash,omitempty"` // pre-parsed SHA256 for this asset
	HashVerified      bool   `json:"hash_verified"`           // set to true after successful checksum verification
	SignatureURL      string `json:"signature_url,omitempty"` // URL to the Ed25519 .sig file (empty for legacy releases)
	SignatureVerified bool   `json:"signature_verified"`      // set to true after successful Ed25519 verification
}

// isTrustedAssetURL rejects anything that isn't HTTPS to a GitHub-operated
// host. The GitHub API response is otherwise trusted verbatim for these
// URLs — defense in depth in case that response is ever attacker-influenced
// (a compromised API response, a misbehaving proxy) independent of the
// Ed25519 signature check that's the actual authenticity guarantee for the
// asset content itself. github.com serves the release page/redirect;
// release assets are actually downloaded from GitHub's object storage CDN.
func isTrustedAssetURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	if u.Scheme != "https" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	return host == "github.com" || strings.HasSuffix(host, ".github.com") ||
		strings.HasSuffix(host, ".githubusercontent.com")
}

// CheckForUpdate queries GitHub Releases API for newer version.
func CheckForUpdate() (*UpdateInfo, error) {
	cur := CurrentVersion()
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(apiEndpoint)
	if err != nil {
		return nil, fmt.Errorf("checking updates: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return &UpdateInfo{Available: false, CurrentVer: cur}, nil
	}

	var release Release
	// Limit response body to 10 MB to prevent resource exhaustion from
	// malicious or unexpectedly large API responses.
	limited := io.LimitReader(resp.Body, 10<<20)
	if err := json.NewDecoder(limited).Decode(&release); err != nil {
		return nil, err
	}

	latestVer := strings.TrimPrefix(release.TagName, "v")
	if !isNewerVersion(latestVer, cur) {
		return &UpdateInfo{Available: false, CurrentVer: cur}, nil
	}

	// Find matching asset for current OS/arch
	assetName := matchAsset(release.Assets)
	if assetName == "" {
		slog.Warn("update available but no matching asset for this platform",
			"version", latestVer, "os", runtime.GOOS, "arch", runtime.GOARCH)
		return &UpdateInfo{Available: false, CurrentVer: cur}, nil
	}
	downloadURL := ""
	var assetSize int64
	checksumURL := ""
	signatureURL := ""
	wantSigName := strings.ToLower(assetName + ".sig")
	for _, a := range release.Assets {
		if !isTrustedAssetURL(a.BrowserDownloadURL) {
			slog.Warn("ignoring release asset with untrusted download URL", "asset", a.Name, "url", a.BrowserDownloadURL)
			continue
		}
		if a.Name == assetName {
			downloadURL = a.BrowserDownloadURL
			assetSize = a.Size
		}
		lower := strings.ToLower(a.Name)
		// Look for checksum file (SHA256SUMS, checksums.txt, etc.)
		if strings.Contains(lower, "sha256") || strings.Contains(lower, "checksum") {
			checksumURL = a.BrowserDownloadURL
		}
		// Look for the matching Ed25519 detached signature.
		if lower == wantSigName {
			signatureURL = a.BrowserDownloadURL
		}
	}
	if downloadURL == "" {
		return nil, fmt.Errorf("no trustworthy download URL found for asset %s", assetName)
	}

	// Reject assets with a zero or suspiciously small size reported by the
	// GitHub API. A zero size can indicate a failed upload or a tampered
	// release; a very small size is never valid for a packaged application.
	if assetSize <= 0 {
		return nil, fmt.Errorf("refusing update %s: GitHub reports asset size 0 (failed upload or tampered release)", latestVer)
	}
	if assetSize < minAssetSize {
		return nil, fmt.Errorf("refusing update %s: asset size %d bytes is below minimum %d (likely corrupted or malicious)", latestVer, assetSize, minAssetSize)
	}

	// Try to pre-fetch the expected hash from the checksum file.
	var expectedHash string
	if checksumURL != "" && assetName != "" {
		expectedHash = fetchExpectedHash(checksumURL, assetName, client)
	}

	return &UpdateInfo{
		Available:    true,
		Version:      latestVer,
		CurrentVer:   cur,
		ReleaseURL:   release.HTMLURL,
		DownloadURL:  downloadURL,
		ReleaseNotes: release.Body,
		AssetName:    assetName,
		AssetSize:    assetSize,
		ChecksumURL:  checksumURL,
		ExpectedHash: expectedHash,
		SignatureURL: signatureURL,
	}, nil
}

// DownloadUpdate downloads the release asset to a secure temp file and
// verifies the SHA256 checksum if available.
func DownloadUpdate(info *UpdateInfo) (string, error) {
	if info.DownloadURL == "" {
		return "", fmt.Errorf("no download URL for %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(info.DownloadURL)
	if err != nil {
		return "", fmt.Errorf("downloading: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}

	// Verify Content-Length matches the asset size reported by the GitHub API.
	// A mismatch may indicate a MITM or CDN substitution attack.
	if cl := resp.ContentLength; cl > 0 && info.AssetSize > 0 && cl != info.AssetSize {
		return "", fmt.Errorf("Content-Length %d does not match expected asset size %d — possible tampering", cl, info.AssetSize)
	}

	// Limit download to expected size + 10% margin to prevent disk exhaustion.
	maxSize := int64(info.AssetSize) + int64(info.AssetSize)/10
	if maxSize < 100*1024*1024 {
		maxSize = 100 * 1024 * 1024 // minimum 100MB cap
	}
	limitedBody := io.LimitReader(resp.Body, maxSize)

	// Use os.CreateTemp to avoid predictable temp paths (symlink attacks).
	ext := filepath.Ext(info.AssetName)
	f, err := os.CreateTemp("", "wireguide-update-*"+ext)
	if err != nil {
		return "", err
	}
	destPath := f.Name()

	// Hash the content as we download it.
	hasher := sha256.New()
	writer := io.MultiWriter(f, hasher)
	written, err := io.Copy(writer, limitedBody)
	if err != nil {
		f.Close()
		os.Remove(destPath)
		return "", err
	}
	f.Close()

	// Reject files that are empty or unreasonably small for a packaged app.
	if written < minAssetSize {
		os.Remove(destPath)
		return "", fmt.Errorf("downloaded file is %d bytes, below minimum %d — refusing to install", written, minAssetSize)
	}

	// Verify the downloaded size matches the size the GitHub API reported.
	if info.AssetSize > 0 && written != info.AssetSize {
		os.Remove(destPath)
		return "", fmt.Errorf("downloaded %d bytes but expected %d — possible truncation or tampering", written, info.AssetSize)
	}

	// Checksum verification is opportunistic, not mandatory: no release in
	// this project's history has ever uploaded a separate SHA256SUMS-style
	// asset (see build/darwin/Taskfile.yml's release task, which now
	// generates one for future releases), so ExpectedHash was always empty
	// in practice — treating it as mandatory meant every real update
	// silently failed at this exact line. A checksum, when present, is
	// still checked and a MISMATCH is always fatal (strong signal of
	// tampering or a bad build). But its ABSENCE no longer blocks
	// installation on its own: requireSignature below enforces the Ed25519
	// signature instead, which is the actual authenticity guarantee here
	// (signed offline — unlike a checksum file living in the same,
	// potentially-compromised release, which an attacker could simply
	// regenerate to match a tampered asset).
	if info.ExpectedHash != "" {
		actual := hex.EncodeToString(hasher.Sum(nil))
		if !strings.EqualFold(actual, info.ExpectedHash) {
			os.Remove(destPath)
			return "", fmt.Errorf("checksum mismatch: expected %s, got %s", info.ExpectedHash, actual)
		}
		info.HashVerified = true
	} else {
		slog.Info("no checksum file for this release — relying on Ed25519 signature verification", "version", info.Version)
	}

	// Ed25519 signature verification. The signing key is kept offline, so a
	// compromised GitHub release alone cannot forge a valid signature.
	// Reuses the hash computed during download instead of re-reading the
	// whole (potentially ~100MB) file into memory a second time.
	assetHashHex := hex.EncodeToString(hasher.Sum(nil))
	if err := verifySignature(assetHashHex, info, client); err != nil {
		os.Remove(destPath)
		return "", err
	}

	return destPath, nil
}

// verifySignature downloads the detached Ed25519 signature for the asset and
// verifies it against the embedded public key. When `requireSignature` is
// false, missing signatures (e.g. on legacy releases) only log a warning so
// the update can still proceed; signatures that ARE present must always
// verify successfully.
// signedMessage builds the exact byte sequence the release signing key signs
// — see cmd/sign's --version flag. Binding the asset's version into the
// signed message (not just its hash) closes a rollback/downgrade attack: an
// Ed25519 signature over raw file bytes alone authenticates "this exact
// file was signed by us" but says nothing about WHICH release it belongs
// to, so an attacker who could publish a new GitHub release (e.g. a stolen
// token) could tag it with a high version number and attach an OLD,
// genuinely-signed-by-us-but-since-patched asset + its real old .sig — the
// signature would verify, and the client would "upgrade" into a known
// vulnerable build. Requiring the signed message to name the specific
// version being installed means replaying an old (version, hash) pair
// under a new tag fails verification, since the embedded version won't
// match what the client believes it's installing.
func signedMessage(version, assetHashHex string) []byte {
	return []byte(version + "\n" + assetHashHex)
}

func verifySignature(assetHashHex string, info *UpdateInfo, client *http.Client) error {
	pub, err := loadEmbeddedPublicKey()
	if err != nil {
		// A broken embedded key is a programmer error; refuse to install.
		return fmt.Errorf("embedded public key is invalid: %w", err)
	}

	if info.SignatureURL == "" {
		if requireSignature {
			return fmt.Errorf("refusing to install update %s: no Ed25519 signature (.sig) found in release", info.Version)
		}
		slog.Warn("update has no Ed25519 signature — accepting based on SHA256 alone (legacy release)",
			"version", info.Version, "asset", info.AssetName)
		return nil
	}

	sig, err := fetchSignature(info.SignatureURL, client)
	if err != nil {
		if requireSignature {
			return fmt.Errorf("refusing to install update %s: %w", info.Version, err)
		}
		slog.Warn("could not fetch Ed25519 signature — accepting based on SHA256 alone",
			"version", info.Version, "err", err)
		return nil
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("Ed25519 signature has wrong size: got %d bytes, want %d", len(sig), ed25519.SignatureSize)
	}

	if !ed25519.Verify(pub, signedMessage(info.Version, assetHashHex), sig) {
		return fmt.Errorf("Ed25519 signature verification FAILED for %s — possible tampering or a rollback attempt", info.AssetName)
	}
	info.SignatureVerified = true
	slog.Info("Ed25519 signature verified", "asset", info.AssetName, "version", info.Version)
	return nil
}

// loadEmbeddedPublicKey decodes the base64-encoded embedded public key.
func loadEmbeddedPublicKey() (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(embeddedPublicKey))
	if err != nil {
		return nil, fmt.Errorf("decode base64: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("wrong size: got %d bytes, want %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// fetchSignature downloads the detached signature file. The body is capped
// at maxSignatureSize to defend against a hostile server feeding the
// updater an unbounded stream.
func fetchSignature(url string, client *http.Client) ([]byte, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetching signature: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching signature: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSignatureSize))
	if err != nil {
		return nil, fmt.Errorf("reading signature: %w", err)
	}
	return body, nil
}

// isNewerVersion compares two semver strings (without "v" prefix).
// Returns true if latest is newer than current.
func isNewerVersion(latest, current string) bool {
	parseParts := func(v string) []int {
		var parts []int
		for _, s := range strings.Split(v, ".") {
			n, err := strconv.Atoi(s)
			if err != nil {
				return nil
			}
			parts = append(parts, n)
		}
		return parts
	}
	lp := parseParts(latest)
	cp := parseParts(current)
	if lp == nil || cp == nil {
		// If either version string is not valid semver, don't report as newer
		// to avoid false positives from malformed tag names.
		return false
	}
	for i := 0; i < len(lp) && i < len(cp); i++ {
		if lp[i] > cp[i] {
			return true
		}
		if lp[i] < cp[i] {
			return false
		}
	}
	return len(lp) > len(cp)
}

// fetchExpectedHash downloads a SHA256SUMS-style file and extracts the hash
// for the given asset name. Format: "<hex-hash>  <filename>" per line.
func fetchExpectedHash(checksumURL, assetName string, client *http.Client) string {
	resp, err := client.Get(checksumURL)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MB limit
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(body), "\n") {
		parts := strings.Fields(line)
		if len(parts) == 2 && strings.EqualFold(parts[1], assetName) {
			return parts[0]
		}
	}
	return ""
}

func matchAsset(assets []Asset) string {
	arch := runtime.GOARCH

	// Map Go OS names to common release naming conventions.
	osNames := []string{runtime.GOOS}
	switch runtime.GOOS {
	case "darwin":
		osNames = append(osNames, "macos", "osx")
	case "windows":
		osNames = append(osNames, "win", "win64")
	}

	archNames := []string{arch, "universal"}

	// wantedExts, in priority order, restricts matching to actual installer
	// packages. A plain os/arch substring match (the previous behavior) can
	// also match a same-named .sig/.txt/checksum asset — e.g.
	// "lockplus-v1.0.62-darwin-arm64.zip.sig" contains both "darwin" and
	// "arm64" — and GitHub's asset listing order isn't guaranteed to put the
	// real package first, so that could select the .sig file itself as "the
	// asset" (breaking the update, since it's under minAssetSize) or a
	// same-os/arch .dmg over the .zip (breaking signature verification,
	// since only the .zip is ever signed — see build/darwin/Taskfile.yml).
	// Matching by exact expected extension, checked in priority order,
	// removes both failure modes structurally: ".zip.sig" never has
	// HasSuffix(".zip") == true.
	var wantedExts []string
	switch runtime.GOOS {
	case "darwin":
		wantedExts = []string{".zip"} // the only signed artifact; .dmg is direct-download-only
	case "windows":
		wantedExts = []string{".msi", ".exe"}
	default:
		wantedExts = []string{".deb", ".rpm", ".appimage"}
	}

	for _, ext := range wantedExts {
		for _, a := range assets {
			name := strings.ToLower(a.Name)
			if !strings.HasSuffix(name, ext) {
				continue
			}
			for _, osn := range osNames {
				for _, an := range archNames {
					if strings.Contains(name, osn) && strings.Contains(name, an) {
						return a.Name
					}
				}
			}
		}
	}
	return ""
}

// BrewPath returns the absolute path to the brew binary, or empty string
// if brew is not found. GUI apps launched from Finder may not have
// /opt/homebrew/bin in PATH, so we check common paths directly.
func BrewPath() string {
	for _, p := range []string{"/opt/homebrew/bin/brew", "/usr/local/bin/brew"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// IsBrewInstall returns true if WireGuide was installed via Homebrew.
// Homebrew cask copies (not symlinks) the app to /Applications, so we
// can't rely on the binary path containing "homebrew". Instead we check
// if the Caskroom receipt directory exists.
func IsBrewInstall() bool {
	// Check common Homebrew Caskroom paths (Apple Silicon + Intel)
	caskroomPaths := []string{
		"/opt/homebrew/Caskroom/wireguide",
		"/usr/local/Caskroom/wireguide",
	}
	for _, p := range caskroomPaths {
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			if BrewPath() != "" {
				return true
			}
		}
	}
	return false
}
