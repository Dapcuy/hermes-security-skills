package proxycore

// MODE 2 — TLS MITM (EKSPERIMENTAL) — ROADMAP §11 Mode 2, §38 item 7.5.
//
// PERINGATAN: mode ini EKSPERIMENTAL. CA di-generate in-memory per-engagement,
// private key TIDAK pernah ditulis ke disk (yang boleh diekspor hanya sertifikat
// publik via --ca-out). Intersepsi hanya sah terhadap target yang diizinkan
// policy bundle — setiap request hasil intercept melewati jalur policy yang
// SAMA dengan Mode 1 (scope, budget, rate limit, redaksi, evidence).
//
// Mitigasi dampak: leaf certificate di-generate dinamis per SNI, ditandatangani
// CA ephemeral yang hanya dipercaya client yang secara eksplisit memasang CA
// tersebut sebagai root (bukan browser secara default).

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// caValidity: CA dan leaf cert ephemeral per-engagement (§11/§23: mati
// bersama container, tidak pernah persist).
const caValidity = 24 * time.Hour

// MITMCA adalah CA per-engagement in-memory.
type MITMCA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
	DER  []byte
}

// GenerateCA membuat CA self-signed ECDSA P-256 in-memory dengan validitas
// 24 jam. Private key tidak pernah ditulis ke disk.
func GenerateCA(now time.Time) (*MITMCA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("proxycore/mitm: generate CA key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("proxycore/mitm: generate serial: %w", err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "hermes-proxy MITM CA (ephemeral, experimental)", Organization: []string{"Hermes Security Skills"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("proxycore/mitm: buat CA cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("proxycore/mitm: parse CA cert: %w", err)
	}
	return &MITMCA{Cert: cert, Key: key, DER: der}, nil
}

// CertPEM mengekspor sertifikat publik CA dalam format PEM — BUKAN private
// key (client yang mau mempercayai MITM harus memasang sertifikat ini manual).
func (ca *MITMCA) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.DER})
}

// MITMProxy adalah http.Handler yang menangani CONNECT tunneling dengan
// TLS interception dinamis per SNI.
type MITMProxy struct {
	ca     *MITMCA
	engine *Engine

	mu      sync.Mutex
	leaves  map[string]*tls.Certificate
	idle    time.Duration // batas baca antar request pada koneksi tunnel
	maxBody int           // batas baca body request hasil intercept
}

// NewMITMProxy membangun MITM proxy di atas Engine yang sama dengan Mode 1
// (jalur policy identik: scope, budget, rate limit, redaksi, evidence).
func NewMITMProxy(ca *MITMCA, eng *Engine) *MITMProxy {
	return &MITMProxy{
		ca:      ca,
		engine:  eng,
		leaves:  map[string]*tls.Certificate{},
		idle:    5 * time.Minute,
		maxBody: maxStoreBodyBytes,
	}
}

// prefixConn menggabungkan sisa data yang sudah ter-buffer oleh http.Server
// (mis. ClientHello yang dikirim client segera setelah CONNECT) dengan data
// berikutnya dari koneksi mentah, sehingga handshake TLS tidak kehilangan byte.
type prefixConn struct {
	net.Conn
	r io.Reader
}

func (c *prefixConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// ServeHTTP melayani method CONNECT: hijack koneksi, balas 200, lalu bungkus
// dengan tls.Server yang men-generate leaf cert per SNI secara dinamis.
func (m *MITMProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		http.Error(w, "proxy MITM hanya melayani CONNECT", http.StatusMethodNotAllowed)
		return
	}
	authority := r.URL.Host
	if authority == "" {
		authority = r.Host
	}
	hostOnly := authority
	if h, _, err := net.SplitHostPort(authority); err == nil {
		hostOnly = h
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack tidak didukung", http.StatusInternalServerError)
		return
	}
	conn, brw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()

	// Balas 200 SEBELUM handshake TLS (kontrak CONNECT).
	if _, err := brw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err := brw.Flush(); err != nil {
		return
	}

	pc := &prefixConn{Conn: conn, r: io.MultiReader(brw.Reader, conn)}
	tlsSrv := tls.Server(pc, &tls.Config{
		MinVersion: tls.VersionTLS12,
		// Leaf cert dinamis per SNI (ditandatangani CA ephemeral).
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			name := hello.ServerName
			if name == "" {
				name = hostOnly
			}
			leaf, err := m.leafFor(name)
			if err != nil {
				return nil, err
			}
			return &tls.Config{
				Certificates: []tls.Certificate{*leaf},
				MinVersion:   tls.VersionTLS12,
			}, nil
		},
	})
	defer tlsSrv.Close()

	if err := tlsSrv.HandshakeContext(r.Context()); err != nil {
		fmt.Printf("hermes-proxy/mitm: handshake gagal untuk %q: %v\n", hostOnly, err)
		return
	}

	rdr := bufio.NewReader(tlsSrv)
	for {
		if m.idle > 0 {
			_ = tlsSrv.SetReadDeadline(time.Now().Add(m.idle))
		}
		ireq, err := http.ReadRequest(rdr)
		if err != nil {
			return // koneksi tutup / EOF / error — selesaikan tunnel
		}
		m.handleIntercepted(tlsSrv, hostOnly, ireq)
	}
}

// handleIntercepted menjalankan jalur policy yang SAMA dengan Mode 1 atas
// request hasil intercept, lalu menulis kembali response asli ke client.
func (m *MITMProxy) handleIntercepted(wc net.Conn, authorityHost string, ireq *http.Request) {
	defer ireq.Body.Close()

	var body []byte
	if ireq.Body != nil {
		b, err := io.ReadAll(io.LimitReader(ireq.Body, int64(m.maxBody)+1))
		if err == nil && len(b) > m.maxBody {
			b = b[:m.maxBody]
		}
		body = b
	}

	// Susun URL absolut dari CONNECT authority + Host + RequestURI.
	host := ireq.Host
	if host == "" {
		host = authorityHost
	}
	u := &url.URL{Scheme: "https", Host: host}
	if ru, err := url.ParseRequestURI(ireq.RequestURI); err == nil {
		u.Path, u.RawQuery = ru.Path, ru.RawQuery
	} else {
		u.Path = ireq.URL.Path
		u.RawQuery = ireq.URL.RawQuery
	}

	headers := make(map[string]string, len(ireq.Header))
	for k := range ireq.Header {
		headers[k] = ireq.Header.Get(k)
	}

	res, denial, err := m.engine.Execute(ireq.Context(), Request{
		URL:     u.String(),
		Method:  ireq.Method,
		Headers: headers,
		Body:    string(body),
	})
	switch {
	case denial != nil:
		writeSimpleJSON(wc, denial.HTTP, map[string]string{"status": "denied", "reason": denial.Reason})
	case err != nil:
		writeSimpleJSON(wc, http.StatusBadGateway, map[string]string{"status": "error", "error": err.Error()})
	default:
		// Passthrough ke client memakai header ASLI + body PENUH — redaksi
		// hanya berlaku untuk data yang masuk evidence/reasoning (§24/§25),
		// bukan untuk stream antara browser dan target.
		writeRawResponse(wc, res)
	}
}

// writeSimpleJSON menulis response HTTP minimal pada koneksi tunnel.
func writeSimpleJSON(wc net.Conn, code int, payload map[string]string) {
	b, _ := json.Marshal(payload)
	fmt.Fprintf(wc, "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		code, http.StatusText(code), len(b), b)
}

// writeRawResponse menulis kembali response target ke client tunnel:
// status + header asli (tanpa hop-by-hop) + Content-Length + body penuh.
func writeRawResponse(wc net.Conn, res Result) {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "HTTP/1.1 %d %s\r\n", res.Response.Status, http.StatusText(res.Response.Status))
	for name, vals := range res.RawHeaders {
		lower := strings.ToLower(name)
		if lower == "content-length" || lower == "transfer-encoding" || lower == "connection" ||
			lower == "keep-alive" || lower == "proxy-connection" {
			continue
		}
		for _, v := range vals {
			buf.WriteString(name)
			buf.WriteString(": ")
			buf.WriteString(v)
			buf.WriteString("\r\n")
		}
	}
	fmt.Fprintf(&buf, "Content-Length: %d\r\n\r\n", len(res.FullBody))
	buf.Write(res.FullBody)
	_, _ = wc.Write(buf.Bytes())
}

// leafFor menghasilkan (dan meng-cache) leaf certificate untuk satu hostname,
// ditandatangani CA ephemeral. Host berupa IP literal memakai IPAddresses.
func (m *MITMProxy) leafFor(host string) (*tls.Certificate, error) {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" {
		return nil, fmt.Errorf("proxycore/mitm: SNI/host kosong")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if leaf, ok := m.leaves[host]; ok {
		return leaf, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("proxycore/mitm: generate leaf key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("proxycore/mitm: generate serial: %w", err)
	}
	now := time.Now()
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host, Organization: []string{"Hermes Security Skills"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, m.ca.Cert, &key.PublicKey, m.ca.Key)
	if err != nil {
		return nil, fmt.Errorf("proxycore/mitm: buat leaf cert untuk %q: %w", host, err)
	}
	leaf := &tls.Certificate{
		Certificate: [][]byte{der, m.ca.DER},
		PrivateKey:  key,
	}
	m.leaves[host] = leaf
	return leaf, nil
}
