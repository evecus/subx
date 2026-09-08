package processor

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// Network transports for DNS resolution: plain HTTP(S) requests for the
// JSON-based providers plus UDP / TCP / TLS DNS wire transports used by the
// Custom provider (mirroring queryDnsOverUdp / queryDnsOverTcp in dns.js).

func httpClientFor(timeoutMS int, insecure bool) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if insecure {
		if transport.TLSClientConfig == nil {
			transport.TLSClientConfig = &tls.Config{}
		}
		transport.TLSClientConfig.InsecureSkipVerify = true
	}
	timeout := time.Duration(timeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = 8000 * time.Millisecond
	}
	return &http.Client{Timeout: timeout, Transport: transport}
}

func httpGetString(reqURL string, timeoutMS int, insecure bool, headers map[string]string) ([]byte, error) {
	client := httpClientFor(timeoutMS, insecure)
	req, err := http.NewRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, reqURL)
	}
	return io.ReadAll(resp.Body)
}

// dnsQueryUDP sends a wire-format query over UDP and returns the response.
func dnsQueryUDP(host string, port int, payload []byte, timeoutMS int) ([]byte, error) {
	timeout := time.Duration(timeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = 8000 * time.Millisecond
	}
	conn, err := net.DialTimeout("udp", net.JoinHostPort(host, fmt.Sprint(port)), timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	if _, err := conn.Write(payload); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
			return nil, errors.New("DNS UDP query timeout")
		}
		return nil, err
	}
	return buf[:n], nil
}

// dnsQueryStream sends a wire-format query over TCP or TLS (2-byte length
// prefixed) and returns the response message.
func dnsQueryStream(host string, port int, payload []byte, timeoutMS int, useTLS, insecure bool) ([]byte, error) {
	timeout := time.Duration(timeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = 8000 * time.Millisecond
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprint(port)), timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if useTLS {
		serverName := host
		if ip := net.ParseIP(host); ip != nil {
			serverName = ""
		}
		conn = tls.Client(conn, &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: insecure,
		})
	}
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	req := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(req, uint16(len(payload)))
	copy(req[2:], payload)
	if _, err := conn.Write(req); err != nil {
		return nil, err
	}
	var resp []byte
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, errors.New("DNS stream connection ended before response")
	}
	length := int(binary.BigEndian.Uint16(header))
	msg := make([]byte, length)
	if _, err := io.ReadFull(conn, msg); err != nil {
		return nil, errors.New("DNS stream connection ended before response")
	}
	resp = msg
	return resp, nil
}
