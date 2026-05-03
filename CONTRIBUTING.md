# Contributing to WireGuide

Thanks for your interest in contributing!

## Development Setup

### Prerequisites

- Go 1.25+
- Node.js 20+
- [Wails v3](https://v3alpha.wails.io/) (`go install github.com/wailsapp/wails/v3/cmd/wails3@latest`)
- macOS with Apple Silicon (for now)

### Build & Run

```bash
# Install frontend dependencies
cd frontend && npm install && cd ..

# Development mode (hot reload)
task dev

# Production build
task build
```

### Project Structure

- `internal/helper/` — Privileged daemon (runs as root)
- `internal/tunnel/` — WireGuard engine and connection phases
- `internal/gui/` — Wails app, tray, event bridge
- `internal/network/` — Platform-specific network config
- `internal/firewall/` — Kill switch (pf on macOS)
- `internal/ipc/` — JSON-RPC 2.0 transport
- `frontend/` — Svelte UI

## Pull Requests

1. Fork the repo and create a branch from `main`
2. Make your changes
3. Test on macOS Apple Silicon
4. Open a PR with a clear description of what and why

Keep PRs focused — one fix or feature per PR.

## Issues

Found a bug? Have a feature idea? Open an issue using the templates provided.

## Code Style

- Follow existing patterns in the codebase
- `go vet` and `go build` must pass with no errors
- Frontend: follow existing Svelte conventions

## Releasing (maintainers)

The auto-updater verifies an Ed25519 detached signature against a public
key embedded in `internal/update/checker.go`. To cut a release:

1. Bump `CFBundleShortVersionString` in `build/darwin/Info.plist` and the
   `fallbackVersion` constant in `internal/update/checker.go`.
2. Export the offline signing key (kept out of git):
   ```bash
   export WIREGUIDE_SIGNING_KEY="$(cat ~/.secrets/wireguide-ed25519.key)"
   ```
   The key file should contain a single base64-encoded Ed25519 private key
   (64 raw bytes, the format produced by `crypto/ed25519.GenerateKey`).
3. Run `task darwin:release`. The task signs/notarizes the app, zips it,
   and produces `<zip>.sig` next to the zip via `go run ./cmd/sign`.
4. Upload BOTH the `.zip` and the `.zip.sig` to the GitHub release.
5. (Optional) Generate a new keypair: `go run ./cmd/sign --gen`. Replace
   the `embeddedPublicKey` value in `internal/update/checker.go` with the
   new `PUBLIC_KEY` and store the `PRIVATE_KEY` offline. Note that
   rotating the key invalidates older releases — only do this if a
   compromise is suspected.

The updater currently runs in grace mode: releases without a `.sig` file
verify by SHA-256 alone (so old releases keep working). Once every
supported release has been re-signed, flip `requireSignature` to `true`
in `internal/update/checker.go`.
