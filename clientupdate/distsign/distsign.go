// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package distsign implements signature and validation of arbitrary
// distributable files.
//
// There are 3 parties in this exchange:
//   - builder, which creates files, signs them with signing keys and publishes
//     to server
//   - server, which distributes public signing keys, files and signatures
//   - client, which downloads files and signatures from server, and validates
//     the signatures
//
// There are 2 types of keys:
//   - signing keys, that sign individual distributable files on the builder
//   - root keys, that sign signing keys and are kept offline
//
// root keys -(sign)-> signing keys -(sign)-> files
//
// All keys are asymmetric Ed25519 key pairs.
//
// The server serves static files under some known prefix. The kinds of files are:
//   - distsign.pub - bundle of PEM-encoded public signing keys
//   - distsign.pub.sig - signature of distsign.pub using one of the root keys
//   - $file - any distributable file
//   - $file.sig - signature of $file using any of the signing keys
//
// The root public keys are baked into the client software at compile time.
// These keys are long-lived and prove the validity of current signing keys
// from distsign.pub. To rotate root keys, a new client release must be
// published, they are not rotated dynamically. There are multiple root keys in
// different locations specifically to allow this rotation without using the
// discarded root key for any new signatures.
//
// The signing public keys are fetched by the client dynamically before every
// download and can be rotated more readily, assuming that most deployed
// clients trust the root keys used to issue fresh signing keys.
package distsign

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
)

const (
	pemTypePrivate = "PRIVATE KEY"
	pemTypePublic  = "PUBLIC KEY"

	downloadSizeLimit    = 1 << 29 // 512MB
	signingKeysSizeLimit = 1 << 20 // 1MB
	signatureSizeLimit   = ed25519.SignatureSize
)

// GenerateKey generates a new key pair and encodes it as PEM.
func GenerateKey() (priv, pub []byte, err error) {
	pub, priv, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{
			Type:  pemTypePrivate,
			Bytes: []byte(priv),
		}), pem.EncodeToMemory(&pem.Block{
			Type:  pemTypePublic,
			Bytes: []byte(pub),
		}), nil
}

// RootKey is a root key Signer used to sign signing keys.
type RootKey Signer

// SignSigningKeys signs the bundle of public signing keys. The bundle must be
// a sequence of PEM blocks joined with newlines.
func (s *RootKey) SignSigningKeys(pubBundle []byte) ([]byte, error) {
	return s.Sign(nil, pubBundle, crypto.Hash(0))
}

// SigningKey is a signing key Signer used to sign packages.
type SigningKey Signer

// SignPackageHash signs a SHA-512 hash of a package.
func (s SigningKey) SignPackageHash(sha512 []byte) ([]byte, error) {
	return s.Sign(nil, sha512, crypto.SHA512)
}

// Signer is crypto.Signer using a single key (root or signing).
type Signer struct {
	crypto.Signer
}

// NewSigner parses the PEM-encoded private key stored in the file named
// privKeyPath and creates a Signer for it. The key is expected to be in the
// same format as returned by GenerateKey.
func NewSigner(privKeyPath string) (Signer, error) {
	raw, err := os.ReadFile(privKeyPath)
	if err != nil {
		return Signer{}, err
	}
	k, err := parsePrivateKey(raw)
	if err != nil {
		return Signer{}, fmt.Errorf("failed to parse %q", privKeyPath)
	}
	return Signer{Signer: k}, nil
}

// Client downloads and validates files from a distribution server.
type Client struct {
	roots    []ed25519.PublicKey
	pkgsAddr *url.URL
}

// NewClient returns a new client for distribution server located at pkgsAddr,
// and uses embedded root keys from the roots/ subdirectory of this package.
func NewClient(pkgsAddr string) (*Client, error) {
	u, err := url.Parse(pkgsAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid pkgsAddr %q: %w", pkgsAddr, err)
	}
	return &Client{roots: roots(), pkgsAddr: u}, nil
}

func (c *Client) url(path string) string {
	return c.pkgsAddr.JoinPath(path).String()
}

// Download fetches a file at path srcPath from pkgsAddr passed in NewClient.
// The file is downloaded to dstPath and its signature is validated using the
// embedded root keys. Download returns an error if anything goes wrong with
// the actual file download or with signature validation.
func (c *Client) Download(srcPath, dstPath string) error {
	// Always fetch a fresh signing key.
	sigPub, err := c.signingKeys()
	if err != nil {
		return err
	}

	srcURL := c.url(srcPath)
	sigURL := srcURL + ".sig"

	hash, err := download(srcURL, dstPath, downloadSizeLimit)
	if err != nil {
		return err
	}
	sig, err := fetch(sigURL, signatureSizeLimit)
	if err != nil {
		return err
	}
	if !verifyAny(sigPub, hash, sig, &ed25519.Options{Hash: crypto.SHA512}) {
		return fmt.Errorf("signature %q for key %q does not validate with the current release signing key; either you are under attack, or attempting to download an old version of Tailscale which was signed with an older signing key", sigURL, srcURL)
	}

	return nil
}

// signingKeys fetches current signing keys from the server and validates them
// against the roots. Should be called before validation of any downloaded file
// to get the fresh keys.
func (c *Client) signingKeys() ([]ed25519.PublicKey, error) {
	keyURL := c.url("distsign.pub")
	sigURL := keyURL + ".sig"
	raw, err := fetch(keyURL, signingKeysSizeLimit)
	if err != nil {
		return nil, err
	}
	sig, err := fetch(sigURL, signatureSizeLimit)
	if err != nil {
		return nil, err
	}
	if !verifyAny(c.roots, raw, sig, &ed25519.Options{Hash: crypto.Hash(0)}) {
		return nil, fmt.Errorf("signature %q for key %q does not validate with any known root key; either you are under attack, or running a very old version of Tailscale with outdated root keys", sigURL, keyURL)
	}

	// Parse the bundle of public signing keys.
	var keys []ed25519.PublicKey
	for len(raw) > 0 {
		pub, rest, err := parsePublicKey(raw)
		if err != nil {
			return nil, err
		}
		keys = append(keys, pub)
		raw = rest
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no signing keys found at %q", keyURL)
	}
	return keys, nil
}

// fetch reads the response body from url into memory, up to limit bytes.
func fetch(url string, limit int64) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return io.ReadAll(io.LimitReader(resp.Body, limit))
}

// download writes the response body of url into a local file at dst, up to
// limit bytes. On success, the returned value is a SHA-512 hash of the file.
func download(url, dst string, limit int64) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	h := sha512.New()
	r := io.TeeReader(io.LimitReader(resp.Body, limit), h)

	f, err := os.Create(dst)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	if _, err := io.Copy(f, r); err != nil {
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

func parsePrivateKey(data []byte) (ed25519.PrivateKey, error) {
	b, rest := pem.Decode(data)
	if b == nil {
		return nil, errors.New("failed to decode PEM data")
	}
	if len(rest) > 0 {
		return nil, errors.New("trailing PEM data")
	}
	if b.Type != pemTypePrivate {
		return nil, fmt.Errorf("PEM type is %q, want %q", b.Type, pemTypePrivate)
	}
	if len(b.Bytes) != ed25519.PrivateKeySize {
		return nil, errors.New("private key has incorrect length for an Ed25519 private key")
	}
	return ed25519.PrivateKey(b.Bytes), nil
}

func parseSinglePublicKey(data []byte) (ed25519.PublicKey, error) {
	pub, rest, err := parsePublicKey(data)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, errors.New("trailing PEM data")
	}
	return pub, err
}

func parsePublicKey(data []byte) (pub ed25519.PublicKey, rest []byte, retErr error) {
	b, rest := pem.Decode(data)
	if b == nil {
		return nil, nil, errors.New("failed to decode PEM data")
	}
	if b.Type != pemTypePublic {
		return nil, nil, fmt.Errorf("PEM type is %q, want %q", b.Type, pemTypePublic)
	}
	if len(b.Bytes) != ed25519.PublicKeySize {
		return nil, nil, errors.New("public key has incorrect length for an Ed25519 public key")
	}
	return ed25519.PublicKey(b.Bytes), rest, nil
}

func verifyAny(keys []ed25519.PublicKey, msg, sig []byte, opts *ed25519.Options) bool {
	for _, k := range keys {
		if err := ed25519.VerifyWithOptions(k, msg, sig, opts); err == nil {
			return true
		}
	}
	return false
}
