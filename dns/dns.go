package dns

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Resolver resolves domain names to IP addresses
type Resolver struct {
	server string       // DNS server address or DoH URL
	isDoH  bool         // Whether to use DNS-over-HTTPS
	client *http.Client // HTTP client for DoH
}

// NewResolver creates a new DNS resolver
// If server starts with "https://", it's treated as DoH
func NewResolver(server string) *Resolver {
	r := &Resolver{
		server: server,
		isDoH:  strings.HasPrefix(server, "https://"),
	}

	if r.isDoH {
		r.client = &http.Client{
			Timeout: 10 * time.Second,
		}
	}

	return r
}

// Resolve resolves a hostname to an IP address
func (r *Resolver) Resolve(hostname string) (string, error) {
	if r.isDoH {
		return r.resolveDoH(hostname)
	}
	return r.resolveDNS(hostname)
}

// resolveDNS resolves using traditional DNS
func (r *Resolver) resolveDNS(hostname string) (string, error) {
	c := dns.Client{
		Timeout: 5 * time.Second,
	}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(hostname), dns.TypeA)
	m.RecursionDesired = true

	resp, _, err := c.Exchange(m, r.server)
	if err != nil {
		return "", fmt.Errorf("DNS query failed: %w", err)
	}

	if resp.Rcode != dns.RcodeSuccess {
		return "", fmt.Errorf("DNS query returned error: %s", dns.RcodeToString[resp.Rcode])
	}

	for _, ans := range resp.Answer {
		if a, ok := ans.(*dns.A); ok {
			return a.A.String(), nil
		}
	}

	return "", fmt.Errorf("no A record found for %s", hostname)
}

// resolveDoH resolves using DNS-over-HTTPS (RFC 8484)
func (r *Resolver) resolveDoH(hostname string) (string, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(hostname), dns.TypeA)
	m.RecursionDesired = true

	// Encode DNS message
	data, err := m.Pack()
	if err != nil {
		return "", fmt.Errorf("failed to pack DNS message: %w", err)
	}

	// Create DoH request (GET with dns parameter)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Try POST method first (more reliable)
	req, err := http.NewRequestWithContext(ctx, "POST", r.server, bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("failed to create DoH request: %w", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := r.client.Do(req)
	if err != nil {
		// Fall back to GET method
		encoded := base64.RawURLEncoding.EncodeToString(data)
		url := r.server + "?dns=" + encoded
		req, err = http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return "", fmt.Errorf("failed to create DoH request: %w", err)
		}
		req.Header.Set("Accept", "application/dns-message")
		resp, err = r.client.Do(req)
		if err != nil {
			return "", fmt.Errorf("DoH request failed: %w", err)
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("DoH request returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read DoH response: %w", err)
	}

	// Parse DNS response
	var response dns.Msg
	if err := response.Unpack(body); err != nil {
		return "", fmt.Errorf("failed to unpack DNS response: %w", err)
	}

	if response.Rcode != dns.RcodeSuccess {
		return "", fmt.Errorf("DoH query returned error: %s", dns.RcodeToString[response.Rcode])
	}

	for _, ans := range response.Answer {
		if a, ok := ans.(*dns.A); ok {
			return a.A.String(), nil
		}
	}

	return "", fmt.Errorf("no A record found for %s", hostname)
}

// ResolveWithPort resolves a hostname and returns address with port
func (r *Resolver) ResolveWithPort(hostname string, port int) (string, error) {
	ip, err := r.Resolve(hostname)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(ip, fmt.Sprintf("%d", port)), nil
}

// doDoHQuery performs a raw DoH query and returns the DNS message
func (r *Resolver) doDoHQuery(data []byte) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Try POST method first
	req, err := http.NewRequestWithContext(ctx, "POST", r.server, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to create DoH request: %w", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := r.client.Do(req)
	if err != nil {
		// Fall back to GET method
		encoded := base64.RawURLEncoding.EncodeToString(data)
		url := r.server + "?dns=" + encoded
		req, err = http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create DoH request: %w", err)
		}
		req.Header.Set("Accept", "application/dns-message")
		resp, err = r.client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("DoH request failed: %w", err)
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH request returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read DoH response: %w", err)
	}

	var response dns.Msg
	if err := response.Unpack(body); err != nil {
		return nil, fmt.Errorf("failed to unpack DNS response: %w", err)
	}

	return &response, nil
}
