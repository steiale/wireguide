// Command sign produces an Ed25519 detached signature for a release asset.
//
// Usage:
//
//	go run ./cmd/sign --key <path-to-private-key> <file-to-sign>
//	go run ./cmd/sign --key-env WIREGUIDE_SIGNING_KEY <file-to-sign>
//
// The private key must be a base64-encoded Ed25519 private key (64 raw bytes,
// the form returned by crypto/ed25519's GenerateKey). The output is written
// next to the input file as `<file>.sig` containing the raw 64-byte signature.
//
// To generate a fresh keypair:
//
//	go run ./cmd/sign --gen
//
// The matching public key must be embedded in internal/update/checker.go as
// the `embeddedPublicKey` constant before releasing a build that should
// trust signatures made with the corresponding private key.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

func main() {
	keyPath := flag.String("key", "", "path to base64-encoded Ed25519 private key file")
	keyEnv := flag.String("key-env", "", "environment variable holding the base64-encoded Ed25519 private key")
	gen := flag.Bool("gen", false, "generate a fresh Ed25519 keypair and print both keys (base64)")
	out := flag.String("o", "", "output path for the signature (default: <input>.sig)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: sign [--key path | --key-env NAME] <file>\n       sign --gen\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *gen {
		if err := generate(); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		return
	}

	args := flag.Args()
	if len(args) != 1 {
		flag.Usage()
		os.Exit(2)
	}
	target := args[0]

	priv, err := loadPrivateKey(*keyPath, *keyEnv)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	data, err := os.ReadFile(target)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: read input:", err)
		os.Exit(1)
	}

	sig := ed25519.Sign(priv, data)

	outPath := *out
	if outPath == "" {
		outPath = target + ".sig"
	}
	if err := os.WriteFile(outPath, sig, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "error: write signature:", err)
		os.Exit(1)
	}

	pub := priv.Public().(ed25519.PublicKey)
	fmt.Printf("signed %s\n", target)
	fmt.Printf("  signature -> %s (%d bytes)\n", outPath, len(sig))
	fmt.Printf("  public key (verify with) -> %s\n", base64.StdEncoding.EncodeToString(pub))
}

func generate() error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	fmt.Println("# Save these somewhere safe.")
	fmt.Println("# Embed the PUBLIC KEY in internal/update/checker.go as embeddedPublicKey.")
	fmt.Println("# Keep the PRIVATE KEY offline; never commit it.")
	fmt.Printf("PUBLIC_KEY=%s\n", base64.StdEncoding.EncodeToString(pub))
	fmt.Printf("PRIVATE_KEY=%s\n", base64.StdEncoding.EncodeToString(priv))
	return nil
}

func loadPrivateKey(path, env string) (ed25519.PrivateKey, error) {
	var raw string
	switch {
	case path != "" && env != "":
		return nil, errors.New("provide either --key or --key-env, not both")
	case path != "":
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read key file: %w", err)
		}
		raw = string(b)
	case env != "":
		raw = os.Getenv(env)
		if raw == "" {
			return nil, fmt.Errorf("environment variable %s is empty or unset", env)
		}
	default:
		// Allow piping the key on stdin as a final option.
		b, err := io.ReadAll(os.Stdin)
		if err != nil || len(b) == 0 {
			return nil, errors.New("no private key supplied (use --key, --key-env, or pipe on stdin)")
		}
		raw = string(b)
	}

	// Trim whitespace/newlines that often sneak into key files.
	raw = trimWhitespace(raw)
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("private key is not valid base64: %w", err)
	}
	if len(decoded) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("private key has wrong size: got %d bytes, want %d", len(decoded), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(decoded), nil
}

func trimWhitespace(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\n' || c == '\r' || c == '\t' {
			continue
		}
		out = append(out, c)
	}
	return string(out)
}
