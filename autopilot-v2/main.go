// AutoPilot: bounded retrieval, strict parsing and single-writer installation.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const maxXML = 1 << 20

var errUnchanged = errors.New("unchanged")

//go:embed roots.json
var rootBundle []byte

func trusted(h Health) bool {
	var roots []string
	if json.Unmarshal(rootBundle, &roots) != nil {
		return false
	}
	pins := map[string]bool{}
	for _, p := range roots {
		b, _ := pem.Decode([]byte(p))
		if b == nil {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			continue
		}
		hash := sha256.Sum256(c.RawSubjectPublicKeyInfo)
		pins[hex.EncodeToString(hash[:])] = true
	}
	if len(h.Roots) == 0 {
		return false
	}
	for _, p := range h.Roots {
		if !pins[p] {
			return false
		}
	}
	return true
}

type Key struct {
	Count        int      `xml:"CertificateChain>NumberOfCertificates"`
	Algorithm    string   `xml:"algorithm,attr"`
	Private      string   `xml:"PrivateKey"`
	Certificates []string `xml:"CertificateChain>Certificate"`
}
type Box struct {
	Keys []Key `xml:"Key"`
}
type Document struct {
	XMLName xml.Name `xml:"AndroidAttestation"`
	Count   int      `xml:"NumberOfKeyboxes"`
	Boxes   []Box    `xml:"Keybox"`
}
type Health struct {
	Identity    string    `json:"keybox_identity"`
	Roots       []string  `json:"root_public_key_hashes"`
	State       string    `json:"state"`
	Fingerprint string    `json:"fingerprint"`
	Serials     []string  `json:"serials"`
	Expires     time.Time `json:"expires"`
	Anchor      bool      `json:"anchor"`
}

func serial(n *big.Int) string { return strings.TrimLeft(strings.ToLower(n.Text(16)), "0") }
func cleanPEM(s string) []byte {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	for i := range lines {
		lines[i] = strings.TrimSpace(lines[i])
	}
	return []byte(strings.Join(lines, "\n"))
}
func signer(data string) (crypto.Signer, error) {
	p, rest := pem.Decode(cleanPEM(data))
	if p == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("invalid private PEM")
	}
	if k, e := x509.ParsePKCS8PrivateKey(p.Bytes); e == nil {
		if s, ok := k.(crypto.Signer); ok {
			return s, nil
		}
	}
	if k, e := x509.ParseECPrivateKey(p.Bytes); e == nil {
		return k, nil
	}
	if k, e := x509.ParsePKCS1PrivateKey(p.Bytes); e == nil {
		return k, nil
	}
	return nil, errors.New("unsupported private key")
}
func inspect(data []byte, now time.Time) (Health, error) {
	h := Health{State: "invalid"}
	sum := sha256.Sum256(data)
	h.Fingerprint = hex.EncodeToString(sum[:])
	if len(data) == 0 || len(data) > maxXML {
		return h, errors.New("XML size")
	}
	data = bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})
	if bytes.Contains(bytes.ToUpper(data), []byte("<!DOCTYPE")) || bytes.Contains(bytes.ToUpper(data), []byte("<!ENTITY")) {
		return h, errors.New("XML directives forbidden")
	}
	if err := validateXMLShape(data); err != nil {
		return h, err
	}
	var d Document
	dec := xml.NewDecoder(bytes.NewReader(data))
	if e := dec.Decode(&d); e != nil {
		return h, errors.New("invalid keybox XML values")
	}
	for {
		t, e := dec.Token()
		if e == io.EOF {
			break
		}
		if e != nil {
			return h, errors.New("invalid keybox XML syntax")
		}
		if _, ok := t.(xml.Comment); ok {
			continue
		}
		if c, ok := t.(xml.CharData); !ok || strings.TrimSpace(string(c)) != "" {
			return h, errors.New("trailing XML")
		}
	}
	if len(d.Boxes) != 1 || d.Count != 1 {
		return h, errors.New("expected one keybox")
	}
	if len(d.Boxes[0].Keys) < 1 || len(d.Boxes[0].Keys) > 4 {
		return h, errors.New("key count")
	}
	h.State = "valid"
	identities := []string{}
	algorithms := map[string]bool{}
	for _, k := range d.Boxes[0].Keys {
		if algorithms[k.Algorithm] {
			return h, errors.New("duplicate key algorithm")
		}
		algorithms[k.Algorithm] = true
		s, e := signer(k.Private)
		if e != nil {
			return h, e
		}
		switch s.(type) {
		case *rsa.PrivateKey:
			if k.Algorithm != "rsa" {
				return h, errors.New("algorithm label mismatch")
			}
		case *ecdsa.PrivateKey:
			if k.Algorithm != "ecdsa" {
				return h, errors.New("algorithm label mismatch")
			}
		default:
			return h, errors.New("key algorithm")
		}
		if len(k.Certificates) < 2 || len(k.Certificates) > 8 || k.Count != len(k.Certificates) {
			return h, errors.New("chain count")
		}
		var previous *x509.Certificate
		chain := []*x509.Certificate{}
		for i, text := range k.Certificates {
			p, rest := pem.Decode(cleanPEM(text))
			if p == nil || p.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
				return h, errors.New("certificate PEM")
			}
			c, e := x509.ParseCertificate(p.Bytes)
			if e != nil {
				return h, e
			}
			chain = append(chain, c)
			if i == 0 {
				if !c.BasicConstraintsValid || !c.IsCA || c.KeyUsage&x509.KeyUsageCertSign == 0 {
					return h, errors.New("keybox certificate cannot sign attestations")
				}
				id := sha256.Sum256(c.Raw)
				identities = append(identities, hex.EncodeToString(id[:]))
				a, _ := x509.MarshalPKIXPublicKey(s.Public())
				b, _ := x509.MarshalPKIXPublicKey(c.PublicKey)
				if !bytes.Equal(a, b) {
					return h, errors.New("private/public mismatch")
				}
			}
			if previous != nil {
				if e := previous.CheckSignatureFrom(c); e != nil {
					return h, fmt.Errorf("chain signature: %w", e)
				}
			}
			previous = c
			h.Serials = append(h.Serials, serial(c.SerialNumber))

			if h.Expires.IsZero() || c.NotAfter.Before(h.Expires) {
				h.Expires = c.NotAfter
			}
			if now.Before(c.NotBefore) {
				h.State = "not_yet_valid"
			}
			if !now.Before(c.NotAfter) {
				h.State = "expired"
			}
		}
		if h.State == "valid" && now.Year() >= 2025 {
			roots := x509.NewCertPool()
			roots.AddCert(previous)
			intermediates := x509.NewCertPool()
			for _, c := range chain[1 : len(chain)-1] {
				intermediates.AddCert(c)
			}
			if _, er := chain[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); er != nil {
				return h, errors.New("unsupported certificate chain constraints")
			}
		}
		rootHash := sha256.Sum256(previous.RawSubjectPublicKeyInfo)
		h.Roots = append(h.Roots, hex.EncodeToString(rootHash[:]))
		// Require a self-signed terminal certificate. Trust provenance remains separate.
		if e := previous.CheckSignature(previous.SignatureAlgorithm, previous.RawTBSCertificate, previous.Signature); e != nil {
			return h, errors.New("terminal signature")
		}
	}
	sort.Strings(identities)
	identity := sha256.Sum256([]byte(strings.Join(identities, "|")))
	h.Identity = hex.EncodeToString(identity[:])
	if now.Year() < 2025 {
		h.State = "time_unknown"
	}
	return h, nil
}

type Status struct {
	InstalledSource string    `json:"installed_source"`
	Ready           bool      `json:"ready"`
	NextSearch      time.Time `json:"next_search_due"`
	NextCRL         time.Time `json:"next_crl_due"`
	TimeState       string    `json:"time_state"`
	CRLChecked      time.Time `json:"crl_checked"`
	CRLUntil        time.Time `json:"crl_valid_until"`
	Enabled         bool      `json:"desired_enabled"`
	Running         bool      `json:"running"`
	Phase           string    `json:"phase"`
	Local           Health    `json:"local"`
	Revocation      string    `json:"revocation_state"`
	Integrity       string    `json:"integrity_verdict"`
	Reason          string    `json:"reason"`
	Next            time.Time `json:"next_due"`
	Source          string    `json:"source"`
	PID             int       `json:"pid"`
	Heartbeat       time.Time `json:"heartbeat"`
}
type Engine struct {
	bootClock         func() float64
	statusErrorAt     time.Time
	timeCheck         func(context.Context) error
	moduleRoot        string
	crlBoot           float64
	crlTTL            time.Duration
	workerCommand     func() *exec.Cmd
	request           func(*http.Request) (*http.Response, error)
	forcedTier        string
	slot              string
	cache             map[string]cacheEntry
	hostNext          map[string]time.Time
	root, ram, brain  string
	dryRun            bool
	client            *http.Client
	status            Status
	revoked           map[string]bool
	crlAt             time.Time
	cursor            int
	automaticFetchDue float64
	searched          bool
	lastSearchBoot    float64
	urgentEvidence    string
}

func (e *Engine) uptime() float64 {
	if e.bootClock != nil {
		return e.bootClock()
	}
	return bootSeconds()
}
func exists(p string) bool { _, e := os.Stat(p); return e == nil }
func (e *Engine) target() string {
	if e.slot != "" {
		return filepath.Join(e.root, e.slot)
	}
	return filepath.Join(e.root, "keybox.xml")
}
func (e *Engine) enabled() bool {
	return exists(filepath.Join(e.brain, "autopilot")) && (e.moduleRoot == "" || exists(e.moduleRoot) && !exists(filepath.Join(e.moduleRoot, "disable")) && !exists(filepath.Join(e.moduleRoot, "remove")))
}
func writeJSON(p string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return atomic(p, b, 0600)
}
func atomic(p string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(p), ".autopilot-*")
	if err != nil {
		return err
	}
	n := f.Name()
	defer os.Remove(n)
	if err = f.Chmod(mode); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	ce := f.Close()
	if err == nil {
		err = ce
	}
	if err != nil {
		return err
	}
	if err = os.Rename(n, p); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(p))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
func lock(p string) (*os.File, error) {
	f, err := os.OpenFile(p, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}
func (e *Engine) publish() {
	e.status.Enabled = e.enabled()
	e.status.NextSearch = time.Time{}
	e.status.NextCRL = time.Time{}
	if e.automaticFetchDue > e.uptime() {
		e.status.NextSearch = time.Now().Add(time.Duration((e.automaticFetchDue - e.uptime()) * float64(time.Second)))
	}
	if !e.crlAt.IsZero() {
		e.status.NextCRL = time.Now().Add(time.Duration((e.crlBoot + e.crlTTL.Seconds() - e.uptime()) * float64(time.Second)))
	}
	e.status.Heartbeat = time.Now()
	if err := writeJSON(filepath.Join(e.ram, "status.json"), e.status); err != nil {
		if time.Since(e.statusErrorAt) > 30*time.Minute {
			logEvent("status_write_failed", "local", 0)
			e.statusErrorAt = time.Now()
		}
	} else {
		e.statusErrorAt = time.Time{}
	}
}
func readLimited(path string, limit int64) ([]byte, error) {
	if er := safeRegular(path, false); er != nil {
		return nil, er
	}
	f, er := os.Open(path)
	if er != nil {
		return nil, er
	}
	defer f.Close()
	st, er := f.Stat()
	if er != nil {
		return nil, er
	}
	if st.Size() > limit {
		return nil, errors.New("file byte limit")
	}
	b, er := io.ReadAll(io.LimitReader(f, limit+1))
	if int64(len(b)) > limit {
		return nil, errors.New("file byte limit")
	}
	return b, er
}
func readKey(path string) ([]byte, error) { return readLimited(path, maxXML) }
func (e *Engine) health() Health {
	b, err := readKey(e.target())
	if err != nil {
		return Health{State: "missing"}
	}
	h, err := inspect(b, time.Now())
	if err != nil {
		h.State = "invalid"
	} else if !trusted(h) {
		h.State = "untrusted"
	}
	if e.isKnownAnchor(h.Identity) || e.isKnownAnchor(h.Fingerprint) {
		h.Anchor = true
	}
	return h
}
func (e *Engine) isRevoked(h Health) bool {
	for _, s := range h.Serials {
		if e.revoked[s] {
			return true
		}
	}
	return false
}
func allowedHost(host string) bool {
	return host == "rawbin.dpejoh.com" || host == "github.com" || host == "release-assets.githubusercontent.com" || host == "objects.githubusercontent.com" || host == "android.googleapis.com"
}

func cacheTTL(header string) time.Duration {
	ttl := 12 * time.Hour
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "max-age=") {
			v, err := strconv.Atoi(strings.TrimPrefix(part, "max-age="))
			if err == nil && v >= 0 && v < 43200 {
				ttl = time.Duration(v) * time.Second
			}
		}
	}
	if ttl < 30*time.Minute {
		ttl = 30 * time.Minute
	}
	return ttl
}

type cacheEntry struct {
	TTL            time.Duration
	Body           []byte
	ETag, Modified string
}

func (e *Engine) get(ctx context.Context, address string, limit int64) ([]byte, error) {
	u, err := url.Parse(address)
	if err != nil || u.Scheme != "https" || !allowedHost(u.Hostname()) || u.User != nil || u.Port() != "" && u.Port() != "443" {
		return nil, errors.New("URL policy")
	}
	if e.hostNext == nil {
		e.hostNext = map[string]time.Time{}
	}
	if time.Now().Before(e.hostNext[u.Hostname()]) {
		return nil, errors.New("host cooldown")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	headers := http.Header{}
	cached := e.cache[address]
	if cached.ETag != "" {
		headers.Set("If-None-Match", cached.ETag)
	}
	if cached.Modified != "" {
		headers.Set("If-Modified-Since", cached.Modified)
	}
	var response *http.Response
	if e.request != nil {
		req, er := http.NewRequestWithContext(ctx, "GET", address, nil)
		if er != nil {
			return nil, er
		}
		req.Header = headers
		response, err = e.request(req)
	} else if exists("/system/bin/curl") {
		response, err = nativeHTTP(ctx, address, limit, headers)
	} else {
		req, er := http.NewRequestWithContext(ctx, "GET", address, nil)
		if er != nil {
			return nil, er
		}
		req.Header = headers
		if e.client == nil {
			return nil, errors.New("HTTP backend unavailable")
		}
		response, err = e.client.Do(req)
	}
	if err != nil {
		logEvent("transport_failed", u.Hostname(), 0)
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode == 304 && cached.Body != nil {
		return cached.Body, nil
	}
	if response.StatusCode == 429 || response.StatusCode == 503 {
		delay := 30 * time.Minute
		value := response.Header.Get("Retry-After")
		if seconds, er := strconv.Atoi(value); er == nil && seconds > 0 {
			delay = time.Duration(seconds) * time.Second
		} else if at, er := http.ParseTime(value); er == nil {
			delay = time.Until(at)
		}
		if delay < 30*time.Minute {
			delay = 30 * time.Minute
		}
		if delay > 24*time.Hour {
			delay = 24 * time.Hour
		}
		e.hostNext[u.Hostname()] = time.Now().Add(delay)
	}
	if response.StatusCode != 200 {
		logEvent("http_rejected", u.Hostname(), response.StatusCode)
		return nil, fmt.Errorf("HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if int64(len(body)) > limit {
		return nil, errors.New("response too large")
	}
	if err != nil {
		return nil, err
	}
	if strings.HasSuffix(u.Path, "/catalog") || strings.HasSuffix(u.Path, "/status") {
		if e.cache == nil {
			e.cache = map[string]cacheEntry{}
		}
		e.cache[address] = cacheEntry{Body: body, ETag: response.Header.Get("ETag"), Modified: response.Header.Get("Last-Modified"), TTL: cacheTTL(response.Header.Get("Cache-Control"))}
	}
	return body, nil
}

// Native Android curl uses bionic/netd DNS; static Linux Go DNS does not.
type cappedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.limit {
		return 0, errors.New("HTTP output limit")
	}
	return b.Buffer.Write(p)
}
func nativeHTTP(ctx context.Context, address string, limit int64, headers http.Header) (*http.Response, error) {
	for redirect := 0; redirect < 5; redirect++ {
		u, err := url.Parse(address)
		if err != nil || u.Scheme != "https" || u.User != nil || !allowedHost(u.Hostname()) || u.Port() != "" && u.Port() != "443" {
			return nil, errors.New("redirect policy")
		}
		args := []string{"--disable", "--silent", "--show-error", "--include", "--raw", "--connect-timeout", "4", "--max-time", "10", "--max-filesize", strconv.FormatInt(limit, 10), "--proto", "=https"}
		for name, values := range headers {
			for _, value := range values {
				if !strings.ContainsAny(value, "\r\n") {
					args = append(args, "--header", name+": "+value)
				}
			}
		}
		args = append(args, "--", address)
		cmd := exec.CommandContext(ctx, "/system/bin/curl", args...)
		output := &cappedBuffer{limit: int(limit) + 65536}
		cmd.Stdout = output
		if err = cmd.Run(); err != nil {
			return nil, fmt.Errorf("native HTTP failed: %w", err)
		}
		response, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(output.Bytes())), nil)
		if err != nil {
			return nil, err
		}
		response.Request = &http.Request{URL: u}
		if response.StatusCode >= 300 && response.StatusCode <= 399 && response.StatusCode != 304 {
			location, err := response.Location()
			response.Body.Close()
			if err != nil {
				return nil, err
			}
			address = location.String()
			continue
		}
		return response, nil
	}
	return nil, errors.New("redirect count")
}
func (e *Engine) crl(ctx context.Context) {
	if !e.crlAt.IsZero() && e.uptime() >= e.crlBoot && e.uptime()-e.crlBoot < e.crlTTL.Seconds() {
		return
	}
	b, err := e.get(ctx, "https://android.googleapis.com/attestation/status", 4<<20)
	if err != nil {
		e.status.Revocation = "unknown_or_stale"
		return
	}
	var d struct {
		Entries map[string]struct {
			Status string `json:"status"`
		} `json:"entries"`
	}
	if json.Unmarshal(b, &d) != nil || d.Entries == nil {
		e.status.Revocation = "invalid_response"
		return
	}
	m := map[string]bool{}
	for s, v := range d.Entries {
		if s == "" || s[0] == '0' || strings.Trim(s, "0123456789abcdef") != "" || (v.Status != "REVOKED" && v.Status != "SUSPENDED") {
			e.status.Revocation = "invalid_response"
			logEvent("crl_invalid_schema", "android.googleapis.com", 200)
			return
		}
		m[s] = true
	}
	e.revoked = m
	e.crlAt = time.Now()
	e.crlBoot = e.uptime()
	e.crlTTL = e.cache["https://android.googleapis.com/attestation/status"].TTL
	if e.crlTTL == 0 {
		e.crlTTL = 12 * time.Hour
	}
	e.status.Revocation = "fresh"
	e.status.CRLChecked = time.Now()
	e.status.CRLUntil = time.Now().Add(e.crlTTL)
}
func decodeOfficial(b []byte) ([]byte, error) {
	var err error
	for i := 0; i < 10; i++ {
		b, err = base64.StdEncoding.DecodeString(strings.Join(strings.Fields(string(b)), ""))
		if err != nil {
			return nil, err
		}
		if len(b) > maxXML {
			return nil, errors.New("decode size")
		}
	}
	b, err = hex.DecodeString(strings.Join(strings.Fields(string(b)), ""))
	if err != nil {
		return nil, err
	}
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = 'a' + (c-'a'+13)%26
		}
		if c >= 'A' && c <= 'Z' {
			b[i] = 'A' + (c-'A'+13)%26
		}
	}
	return b, nil
}
func decodeSecondary(b []byte) ([]byte, error) {
	const shuffled = "1dgWnocayqxU3r6vA5lCIPYfHmkV08b4tz+KMsp2NQ9LRXihODwSj7BEFJ/ZuGTe"
	const standard = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	b = []byte(strings.Join(strings.Fields(string(b)), ""))
	for i, c := range b {
		j := strings.IndexByte(shuffled, c)
		if j >= 0 {
			b[i] = standard[j]
		} else if c != '=' {
			return nil, errors.New("encoded character")
		}
	}
	return base64.StdEncoding.DecodeString(string(b))
}
func (e *Engine) candidate(ctx context.Context, u string, secondary bool) ([]byte, Health, error) {
	b, err := e.get(ctx, u, maxXML)
	if err != nil {
		return nil, Health{}, err
	}
	if secondary {
		b, err = decodeSecondary(b)
	} else {
		b, err = decodeOfficial(b)
	}
	if err != nil {
		return nil, Health{}, err
	}
	h, err := inspect(b, time.Now())
	if err != nil {
		return nil, h, err
	}
	if strings.HasSuffix(u, "/Megatron2") || e.isKnownAnchor(h.Identity) || e.isKnownAnchor(h.Fingerprint) {
		h.Anchor = true
	}
	address, _ := url.Parse(u)
	if e.isRevoked(h) {
		logEvent("candidate_revoked", address.Hostname(), 0)
		return nil, h, errors.New("candidate revoked")
	}
	if h.State != "valid" || !trusted(h) {
		logEvent("candidate_invalid", address.Hostname(), 0)
		return nil, h, errors.New("candidate invalid or untrusted")
	}
	return b, h, nil
}
func (e *Engine) secondary(ctx context.Context) ([]byte, Health, error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	b, err := e.get(ctx, "https://rawbin.dpejoh.com/catalog", 1<<20)
	if err != nil {
		return nil, Health{}, err
	}
	var d struct {
		Entries []struct {
			Source  string          `json:"source"`
			Version json.RawMessage `json:"version"`
			Revoked *bool           `json:"revoked"`
			Soft    *bool           `json:"softbanned"`
		} `json:"entries"`
	}
	if err = json.Unmarshal(b, &d); err != nil {
		return nil, Health{}, err
	}
	// Round-robin sources rather than spending all slots on one publisher.
	groups := map[string][]string{}
	order := []string{}
	for _, v := range d.Entries {
		if v.Revoked == nil || v.Soft == nil || *v.Revoked || *v.Soft {
			continue
		}
		if len(v.Source) > 80 || strings.ContainsAny(v.Source, "/\\\r\n") {
			continue
		}
		var ver string
		if json.Unmarshal(v.Version, &ver) != nil {
			ver = string(v.Version)
		}
		if len(ver) == 0 || len(ver) > 40 || strings.ContainsAny(ver, "/\\\r\n") {
			continue
		}
		if _, ok := groups[v.Source]; !ok {
			order = append(order, v.Source)
		}
		groups[v.Source] = append(groups[v.Source], "https://rawbin.dpejoh.com/key/"+url.PathEscape(v.Source)+"/"+url.PathEscape(ver))
	}
	rank := func(s string) int {
		switch s {
		case "TAKR":
			return 0
		case "@Xiaomi_Lei_Jun":
			return 1
		case "@Samsung_Jae_Yong":
			return 2
		case "Yuri":
			return 3
		}
		return 4
	}
	sort.SliceStable(order, func(i, j int) bool { return rank(order[i]) < rank(order[j]) })
	urls := []string{}
	for round := 0; round < len(d.Entries); round++ {
		added := false
		for _, s := range order {
			if round < len(groups[s]) {
				urls = append(urls, groups[s][round])
				added = true
			}
		}
		if !added {
			break
		}
	}
	seen := map[string]bool{}
	start := e.cursor
	for i := 0; i < 5 && i < len(urls); i++ {
		idx := (start + i) % len(urls)
		e.cursor = (idx + 1) % len(urls)
		u := urls[idx]
		if seen[u] {
			continue
		}
		seen[u] = true
		b, h, err := e.candidate(ctx, u, true)
		if err == nil && e.eligible(h) {
			return b, h, nil
		}
		if ctx.Err() != nil {
			break
		}
	}
	return nil, Health{}, errors.New("secondary exhausted")
}
func (e *Engine) eligible(c Health) bool {
	h := e.status.Local
	if c.Fingerprint == h.Fingerprint || (h.Identity != "" && c.Identity == h.Identity && !c.Expires.After(h.Expires)) {
		return false
	}
	if h.State == "valid" && !e.isRevoked(h) && ((h.Anchor && (c.Anchor || e.status.Revocation != "fresh")) || (!h.Anchor && (c.Anchor || !c.Expires.After(h.Expires) || e.status.Revocation != "fresh"))) {
		return false
	}
	return true
}
func generation(brain string) string {
	var b strings.Builder
	for _, n := range []string{"autopilot", "disable-default-source", "omk-key", "sim-key"} {
		fmt.Fprintf(&b, "%s:%t;", n, exists(filepath.Join(brain, n)))
	}
	for _, mod := range []string{"teesim", "oh_my_keymint"} {
		p := filepath.Join("/data/adb/modules", mod)
		fmt.Fprintf(&b, "%s:%t:%t:%t;", mod, exists(p), exists(filepath.Join(p, "disable")), exists(filepath.Join(p, "remove")))
	}
	rev, err := readLimited(filepath.Join(brain, ".autopilot-config-revision"), 64)
	if err != nil && !os.IsNotExist(err) {
		b.WriteString("revision_unreadable")
	}
	b.Write(rev)
	return b.String()
}
func (e *Engine) cycle(ctx context.Context, automatic bool) error {
	searchLock, lockErr := lock(filepath.Join(e.ram, "search.lock"))
	if lockErr != nil {
		return errors.New("search already running")
	}
	defer searchLock.Close()
	if !e.dryRun {
		f, er := lock(filepath.Join(e.ram, "write.lock"))
		if er != nil {
			return er
		}
		er = e.recoverTransaction()
		f.Close()
		if er != nil {
			return er
		}
	}
	e.status.Phase = "auditing"
	e.publish()
	if _, revisionErr := configRevision(e.brain); revisionErr != nil {
		return errors.New("invalid configuration revision")
	}
	previousLocal := e.status.Local
	e.status.Local = e.health()
	if _, er := e.knownAnchors(); er != nil {
		return errors.New("anchor metadata unavailable; current file preserved")
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	if !e.dryRun {
		if er := e.checkTime(ctx); er != nil {
			e.status.Phase = "time_unknown"
			return er
		}
	}
	e.crl(ctx)
	h := e.status.Local
	if h.State == "time_unknown" {
		return errors.New("system clock unknown")
	}
	needs := h.State != "valid" || h.Anchor || e.isRevoked(h) || time.Until(h.Expires) < 24*time.Hour
	if !needs && e.forcedTier == "" {
		return nil
	}
	event := ""
	if e.isRevoked(h) {
		event = "revoked:" + h.Fingerprint
	} else if h.State == "expired" {
		event = "expired:" + h.Fingerprint
	}
	if automatic && event != "" && e.urgentEvidence != event {
		e.urgentEvidence = event
		urgent := e.lastSearchBoot + 1800
		if (e.isRevoked(h) || previousLocal.State == "valid") && e.automaticFetchDue > urgent {
			e.automaticFetchDue = urgent
		}
	}
	if automatic && e.uptime() < e.automaticFetchDue {
		return nil
	}
	e.searched = true
	e.lastSearchBoot = e.uptime()
	original, err := readKey(e.target())
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	sum := sha256.Sum256(original)
	expected := hex.EncodeToString(sum[:])
	gen := generation(e.brain)
	tiers := []string{"Megatron", "secondary"}
	if exists(filepath.Join(e.brain, "disable-default-source")) {
		tiers = []string{"secondary", "Megatron"}
	}
	// Anchor is only a last resort when the current certificate is unusable.
	if h.State != "valid" || e.isRevoked(h) || !trusted(h) {
		tiers = append(tiers, "Megatron2")
	}
	if e.forcedTier != "" {
		tiers = []string{e.forcedTier}
	}
	for _, tier := range tiers {
		e.status.Phase = "fetching"
		e.status.Source = tier
		e.publish()
		var data []byte
		var candidate Health
		if tier == "secondary" {
			data, candidate, err = e.secondary(ctx)
		} else {
			data, candidate, err = e.candidate(ctx, "https://github.com/MeowDump/Integrity-Box/releases/download/archive/"+tier, false)
		}
		if err != nil {
			continue
		}
		if !e.eligible(candidate) {
			continue
		}

		if ctx.Err() != nil {
			return ctx.Err()
		}
		e.status.Phase = "installing"
		e.publish()
		if automatic {
			if er := e.checkTime(ctx); er != nil {
				return er
			}
		}
		err = e.install(data, expected, gen, automatic)
		if err != nil {
			return err
		}
		e.status.Local = e.health()
		e.status.Phase = "installed"
		if e.dryRun {
			e.status.Phase = "dry_run_candidate_validated"
			e.status.Local = candidate
		}
		// Tricky Store watches its config; no global keystore restart is required.
		return nil
	}
	return errors.New("no suitable replacement; current file preserved")
}
func (e *Engine) recordSearchResult(err error, failures int) int {
	if !e.searched {
		return failures
	}
	if err == nil {
		e.automaticFetchDue = 0
		return 0
	}
	e.automaticFetchDue = e.uptime() + jitter(backoff(failures)).Seconds()
	return failures + 1
}
func localAuditDeadline(h Health, now time.Time) time.Time {
	if h.State != "valid" || !h.Expires.After(now) {
		return time.Time{}
	}
	boundary := h.Expires.Add(-24 * time.Hour)
	if boundary.After(now) {
		return boundary
	}
	return h.Expires
}
func (e *Engine) targetSignature() string {
	st, err := os.Lstat(e.target())
	if err != nil {
		return "unavailable"
	}
	inode := uint64(0)
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		inode = uint64(sys.Ino)
	}
	return fmt.Sprintf("%d:%d:%d", inode, st.Size(), st.ModTime().UnixNano())
}
func jitter(d time.Duration) time.Duration {
	n, err := rand.Int(rand.Reader, big.NewInt(201))
	if err != nil {
		return d
	}
	v := d + time.Duration(int64(d)*(n.Int64()-100)/1000)
	if v > 12*time.Hour {
		v = 12 * time.Hour
	}
	return v
}
func backoff(failures int) time.Duration {
	switch failures {
	case 0:
		return 30 * time.Minute
	case 1:
		return 2 * time.Hour
	case 2:
		return 6 * time.Hour
	default:
		return 12 * time.Hour
	}
}
func charging() bool {
	for _, n := range []string{"usb", "pc_port", "dc"} {
		b, _ := os.ReadFile("/sys/class/power_supply/" + n + "/online")
		if strings.TrimSpace(string(b)) == "1" {
			return true
		}
	}
	return false
}
func screen() bool {
	b, err := os.ReadFile("/sys/class/backlight/panel0-backlight/brightness")
	if err != nil {
		return false
	}
	v, err := strconv.Atoi(strings.TrimSpace(string(b)))
	return err == nil && v > 0
}
func tooHot() bool {
	b, err := os.ReadFile("/sys/class/power_supply/battery/temp")
	if err != nil {
		return false
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	return err == nil && n >= 450
}
func batteryOK() bool {
	b, err := os.ReadFile("/sys/class/power_supply/battery/capacity")
	if err != nil {
		return false
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	return err == nil && n >= 15
}
func bootSeconds() float64 {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		if runtime.GOOS != "linux" {
			return float64(time.Now().Unix())
		}
		return math.NaN()
	}
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return math.NaN()
	}
	v, err := strconv.ParseFloat(f[0], 64)
	if err != nil || v < 0 {
		return math.NaN()
	}
	return v
}
func (e *Engine) daemon(ctx context.Context) error {
	if math.IsNaN(e.uptime()) {
		return errors.New("BOOTTIME unavailable")
	}
	f, err := lock(filepath.Join(e.ram, "daemon.lock"))
	if err != nil {
		return err
	}
	defer f.Close()
	applyBackground()
	recoveryLock, recoveryErr := lock(filepath.Join(e.ram, "write.lock"))
	if recoveryErr != nil {
		return recoveryErr
	}
	recoveryErr = e.recoverTransaction()
	recoveryLock.Close()
	if recoveryErr != nil {
		e.status.Phase = "recovery_required"
		e.status.Reason = recoveryErr.Error()
		e.publish()
		return recoveryErr
	}
	if _, revisionErr := configRevision(e.brain); revisionErr != nil {
		e.status.Phase = "configuration_required"
		e.status.Reason = "invalid configuration revision"
		e.publish()
		return errors.New("invalid configuration revision")
	}
	deadline := time.Now().Add(60 * time.Second)
	bootCtx, bootCancel := context.WithTimeout(ctx, 60*time.Second)
	defer bootCancel()
	for {
		b, er := exec.CommandContext(bootCtx, "getprop", "sys.boot_completed").Output()
		if er != nil {
			return errors.New("boot status unavailable")
		}
		if strings.TrimSpace(string(b)) == "1" {
			break
		}
		if time.Now().After(deadline) {
			return errors.New("boot not complete")
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(time.Second):
		}
	}
	e.status.Ready = true
	e.status.Running = true
	e.status.PID = os.Getpid()
	defer func() { e.status.Ready = false; e.status.Running = false; e.status.Phase = "stopped"; e.publish() }()
	failures := 0
	next := time.Now().Add(2 * time.Minute)
	nextBoot := e.uptime() + 120
	var screenSince time.Time
	lastAttemptBoot := float64(-3600)
	wasCharging := charging()
	observedFile := e.targetSignature()
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		if !e.enabled() {
			return nil
		}
		e.status.Next = time.Now().Add(time.Duration((nextBoot - e.uptime()) * float64(time.Second)))
		e.publish()
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
		signature := e.targetSignature()
		if signature != observedFile {
			observedFile = signature
			nextBoot = e.uptime()
		}
		chargingNow := charging()
		if chargingNow && !wasCharging && e.uptime()-lastAttemptBoot >= 1800 {
			nextBoot = e.uptime()
		}
		wasCharging = chargingNow
		on := screen()
		if on && screenSince.IsZero() {
			screenSince = time.Now()
		}
		if !on {
			screenSince = time.Time{}
		}
		if e.uptime() < nextBoot {
			continue
		}
		if tooHot() || !chargingNow && (!batteryOK() || !on || time.Since(screenSince) < 25*time.Second) {
			e.status.Phase = "deferred_power_or_screen"
			continue
		}
		lastAttemptBoot = e.uptime()
		e.searched = false
		err = e.cycle(ctx, true)
		failures = e.recordSearchResult(err, failures)
		if err != nil {
			e.status.Reason = err.Error()

			next = time.Now().Add(2 * time.Hour)
			if e.automaticFetchDue > e.uptime() {
				next = time.Now().Add(time.Duration((e.automaticFetchDue - e.uptime()) * float64(time.Second)))
			}
		} else {
			e.status.Reason = ""

			next = time.Now().Add(12 * time.Hour)
			if e.status.Local.Anchor || time.Until(e.status.Local.Expires) < 24*time.Hour {
				next = time.Now().Add(30 * time.Minute)
			}
		}
		if e.automaticFetchDue > e.uptime() && time.Until(next).Seconds() > e.automaticFetchDue-e.uptime() {
			next = time.Now().Add(time.Duration((e.automaticFetchDue - e.uptime()) * float64(time.Second)))
		}
		if e.status.TimeState == "verified" {
			audit := localAuditDeadline(e.status.Local, time.Now())
			if !audit.IsZero() && audit.Before(next) {
				next = audit
			}
		}
		nextBoot = e.uptime() + time.Until(next).Seconds()
		if e.status.Revocation == "fresh" {
			remaining := e.crlTTL.Seconds() - (e.uptime() - e.crlBoot)
			if remaining < 1800 {
				remaining = 1800
			}
			if remaining < time.Until(next).Seconds() {
				next = time.Now().Add(time.Duration(remaining * float64(time.Second)))
				nextBoot = e.uptime() + remaining
			}
		}
		if e.status.Revocation != "fresh" && time.Until(next) > 2*time.Hour {
			next = time.Now().Add(2 * time.Hour)
			nextBoot = e.uptime() + 7200
		}
		if exists("/system/bin/log") {
			message := "cycle complete; local=" + e.status.Local.State + "; source=" + e.status.Source + "; result=" + e.status.Reason
			_ = exec.Command("/system/bin/log", "-p", "i", "-t", "BoxAutoPilot", message).Run()
		}
		e.status.Phase = "waiting"
	}
}
func main() {
	syscall.Umask(0077)
	debug.SetMemoryLimit(32 << 20)
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "commands: inspect PATH | status | daemon | run-once")
		os.Exit(2)
	}
	if os.Args[1] == "inspect" && len(os.Args) == 3 {
		b, err := readKey(os.Args[2])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		h, err := inspect(b, time.Now())
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		_ = json.NewEncoder(os.Stdout).Encode(h)
		return
	}
	e := Engine{root: "/data/adb/tricky_store", ram: "/dev/.box_brain_v2", brain: "/data/adb/Box-Brain"}
	if exe, er := os.Executable(); er == nil {
		e.moduleRoot = filepath.Clean(filepath.Join(filepath.Dir(exe), "../../.."))
	}
	if os.Args[1] == "status" {
		b, err := readLimited(filepath.Join(e.ram, "status.json"), 64<<10)
		if err != nil {
			_ = json.NewEncoder(os.Stdout).Encode(Status{Enabled: e.enabled(), Local: e.health(), Integrity: "not_measured", Phase: "not_started", TimeState: "unknown", Revocation: "unknown"})
			return
		}
		var st Status
		if json.Unmarshal(b, &st) == nil {
			if st.TimeState == "" {
				st.TimeState = "unknown"
			}
			st.Enabled = e.enabled()
			st.Running = held(filepath.Join(e.ram, "daemon.lock"))
			st.Ready = st.Ready && st.Running
			st.Local = e.health()
			st.InstalledSource = e.installedSource(st.Local.Fingerprint)
			if st.Revocation == "fresh" && (time.Now().After(st.CRLUntil) || time.Now().Before(st.CRLChecked)) {
				st.Revocation = "stale"
			}
			_ = json.NewEncoder(os.Stdout).Encode(st)
		}
		return
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "root required")
		os.Exit(1)
	}
	if st, er := os.Lstat(e.ram); er == nil && (!st.IsDir() || st.Mode()&os.ModeSymlink != 0) {
		fmt.Fprintln(os.Stderr, "unsafe runtime directory")
		os.Exit(1)
	}
	if err := os.MkdirAll(e.ram, 0700); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	// Android uses native curl and its trust store; avoid loading a second CA pool.
	if !exists("/system/bin/curl") {
		roots, _ := x509.SystemCertPool()
		if roots == nil {
			roots = x509.NewCertPool()
		}
		files, _ := filepath.Glob("/system/etc/security/cacerts/*")
		for _, p := range files {
			b, er := os.ReadFile(p)
			if er == nil {
				roots.AppendCertsFromPEM(b)
			}
		}
		e.client = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, DialContext: (&net.Dialer{Timeout: 4 * time.Second}).DialContext, TLSHandshakeTimeout: 4 * time.Second, Proxy: http.ProxyFromEnvironment, DisableCompression: true, MaxIdleConns: 2, IdleConnTimeout: 30 * time.Second}, CheckRedirect: func(r *http.Request, via []*http.Request) error {
			if len(via) >= 5 || r.URL.Scheme != "https" || !allowedHost(r.URL.Hostname()) {
				return errors.New("redirect policy")
			}
			return nil
		}}

	}
	e.status = Status{Integrity: "not_measured", Revocation: "unknown", Phase: "starting", TimeState: "unknown"}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	defer cancel()
	var err error
	switch os.Args[1] {
	case "clock-status":
		err = e.checkTime(ctx)
		_ = json.NewEncoder(os.Stdout).Encode(map[string]string{"time_state": e.status.TimeState})
	case "configure":
		if len(os.Args) != 4 || (os.Args[3] != "on" && os.Args[3] != "off") {
			err = errors.New("configure FLAG on|off required")
			break
		}
		err = e.setFlag(ctx, os.Args[2], os.Args[3] == "on")
	case "disable":
		err = e.disable(ctx)
	case "supervise":
		err = e.supervise(ctx)
	case "daemon":
		err = e.daemon(ctx)
	case "import":
		if err = e.checkTime(ctx); err != nil {
			break
		}
		if len(os.Args) < 3 || len(os.Args) > 4 {
			err = errors.New("import requires a path and optional slot")
			break
		}
		if len(os.Args) == 4 {
			switch os.Args[3] {
			case "1":
			case "2":
				e.slot = "keybox2.xml"
			case "3":
				e.slot = "keybox3.xml"
			default:
				err = errors.New("invalid slot")
				break
			}
		}
		if err != nil {
			break
		}
		var data []byte
		data, err = readKey(os.Args[2])
		if err != nil {
			break
		}
		var h Health
		h, err = inspect(data, time.Now())
		if err != nil {
			break
		}
		if h.State != "valid" || !trusted(h) {
			err = errors.New("import certificate not valid or untrusted")
			break
		}
		e.crl(ctx)
		if e.status.Revocation != "fresh" {
			err = errors.New("import blocked: revocation status unknown or stale")
			break
		}
		if e.isRevoked(h) {
			err = errors.New("import revoked")
			break
		}
		old, _ := readKey(e.target())
		sum := sha256.Sum256(old)
		e.status.Source = "manual_import"
		err = e.install(data, hex.EncodeToString(sum[:]), generation(e.brain), false)
	case "probe":
		e.dryRun = true
		e.ram = filepath.Join(e.ram, "probe")
		if er := os.MkdirAll(e.ram, 0700); er != nil {
			fmt.Fprintln(os.Stderr, er)
			os.Exit(1)
		}
		err = e.cycle(ctx, false)
		e.publish()
		_ = json.NewEncoder(os.Stdout).Encode(e.status)
	case "fetch":
		if len(os.Args) != 3 || (os.Args[2] != "secondary" && os.Args[2] != "Megatron" && os.Args[2] != "Megatron2") {
			err = errors.New("invalid tier")
			break
		}
		e.forcedTier = os.Args[2]
		err = e.cycle(ctx, false)
		e.publish()
	case "run-once":
		err = e.cycle(ctx, false)
		e.publish()
	default:
		err = errors.New("unknown command")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
