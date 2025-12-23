package config

import (
	"fmt"
	"net"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config represents the root configuration structure
type Config struct {
	Mappings []MappingEntry `yaml:"mappings"`
	DNS      []DNSEntry     `yaml:"dns"`
}

// MappingEntry represents a host mapping configuration
type MappingEntry struct {
	Hosts   []string `yaml:"hosts"`
	SNI     string   `yaml:"sni,omitempty"`
	Address string   `yaml:"address,omitempty"`
}

// DNSEntry represents a DNS override configuration
type DNSEntry struct {
	Hosts []string `yaml:"hosts"`
	IP    string   `yaml:"ip"`
}

// Mapping represents a resolved mapping for a host
type Mapping struct {
	SNI     string // Target SNI for MITM, empty means no MITM
	Address string // Target address (host:port), empty means use DNS
}

// DNSOverride represents a DNS override with optional CIDR-based selection
type DNSOverride struct {
	CIDR      *net.IPNet // Optional CIDR for conditional IP
	CIDRAddr  string     // IP to return if client matches CIDR
	DefaultIP string     // Default IP to return
}

// Manager manages configuration and host lookups
type Manager struct {
	config       *Config
	hostMappings map[string]*Mapping     // Exact host mappings
	starMappings map[string]*Mapping     // Wildcard host mappings (*.example.com)
	dnsOverrides map[string]*DNSOverride // Exact DNS overrides
	dnsStar      map[string]*DNSOverride // Wildcard DNS overrides
}

// parseDNSIP parses the IP field which can be:
// - Simple: "192.168.1.1"
// - CIDR-based: "10.0.0.0/24:10.0.0.2,192.168.1.1"
func parseDNSIP(ipField string) (*DNSOverride, error) {
	override := &DNSOverride{}

	// Check if it contains CIDR format: CIDR:A_IP,B_IP
	if idx := strings.Index(ipField, ","); idx != -1 {
		// Format: CIDR:A_IP,B_IP
		cidrPart := ipField[:idx]
		override.DefaultIP = strings.TrimSpace(ipField[idx+1:])

		// Parse CIDR:A_IP
		if colonIdx := strings.Index(cidrPart, ":"); colonIdx != -1 {
			cidrStr := cidrPart[:colonIdx]
			override.CIDRAddr = strings.TrimSpace(cidrPart[colonIdx+1:])

			_, cidr, err := net.ParseCIDR(cidrStr)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR: %s: %w", cidrStr, err)
			}
			override.CIDR = cidr
		} else {
			return nil, fmt.Errorf("invalid IP format: %s", ipField)
		}
	} else {
		// Simple format: just an IP
		override.DefaultIP = strings.TrimSpace(ipField)
	}

	return override, nil
}

// Load loads configuration from the specified file
// Load loads configuration from the specified file
// If path is empty, returns an empty configuration
func Load(path string) (*Manager, error) {
	var cfg Config
	var err error

	if path != "" {
		var data []byte
		data, err = os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}

		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("failed to parse config file: %w", err)
		}
	}

	m := &Manager{
		config:       &cfg,
		hostMappings: make(map[string]*Mapping),
		starMappings: make(map[string]*Mapping),
		dnsOverrides: make(map[string]*DNSOverride),
		dnsStar:      make(map[string]*DNSOverride),
	}

	// Process mappings
	for _, entry := range cfg.Mappings {
		mapping := &Mapping{
			SNI:     entry.SNI,
			Address: entry.Address,
		}
		for _, host := range entry.Hosts {
			if strings.HasPrefix(host, "*.") {
				// Wildcard mapping: *.example.com -> example.com
				m.starMappings[host[2:]] = mapping
			} else {
				m.hostMappings[host] = mapping
			}
		}
	}

	// Process DNS overrides
	for _, entry := range cfg.DNS {
		override, err := parseDNSIP(entry.IP)
		if err != nil {
			return nil, fmt.Errorf("failed to parse DNS IP for hosts %v: %w", entry.Hosts, err)
		}

		for _, host := range entry.Hosts {
			if strings.HasPrefix(host, "*.") {
				m.dnsStar[host[2:]] = override
			} else {
				m.dnsOverrides[host] = override
			}
		}
	}

	return m, nil
}

// GetMapping returns the mapping for a host, or nil if not found
func (m *Manager) GetMapping(host string) *Mapping {
	// Try exact match first
	if mapping, ok := m.hostMappings[host]; ok {
		return mapping
	}

	// Try wildcard match
	idx := 0
	for {
		idx = strings.Index(host[idx:], ".")
		if idx == -1 {
			break
		}
		idx++ // Skip the dot
		superDomain := host[idx:]
		if mapping, ok := m.starMappings[superDomain]; ok {
			return mapping
		}
		host = superDomain
		idx = 0
	}

	return nil
}

// GetDNSOverride returns the IP override for a host based on client IP
// clientIP can be empty, in which case the default IP is returned
func (m *Manager) GetDNSOverride(host string, clientIP string) string {
	override := m.getDNSOverrideEntry(host)
	if override == nil {
		return ""
	}

	// If we have a CIDR rule and a client IP, check if it matches
	if override.CIDR != nil && clientIP != "" {
		// Parse client IP (remove port if present)
		clientHost := clientIP
		if h, _, err := net.SplitHostPort(clientIP); err == nil {
			clientHost = h
		}

		ip := net.ParseIP(clientHost)
		if ip != nil && override.CIDR.Contains(ip) {
			return override.CIDRAddr
		}
	}

	return override.DefaultIP
}

// getDNSOverrideEntry returns the DNS override entry for a host
func (m *Manager) getDNSOverrideEntry(host string) *DNSOverride {
	// Try exact match first
	if override, ok := m.dnsOverrides[host]; ok {
		return override
	}

	// Try wildcard match
	idx := 0
	for {
		idx = strings.Index(host[idx:], ".")
		if idx == -1 {
			break
		}
		idx++
		superDomain := host[idx:]
		if override, ok := m.dnsStar[superDomain]; ok {
			return override
		}
		host = superDomain
		idx = 0
	}

	return nil
}
