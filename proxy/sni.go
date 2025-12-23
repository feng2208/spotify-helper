package proxy

import (
	"bufio"
	"fmt"
)

// ClientHello represents a parsed TLS ClientHello message
type ClientHello struct {
	ServerName string
}

// peekClientHello reads the TLS ClientHello without consuming the entire stream
// Returns the parsed ClientHello and the raw bytes that were read
func peekClientHello(reader *bufio.Reader) (*ClientHello, []byte, error) {
	// TLS record header is 5 bytes
	header, err := reader.Peek(5)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read TLS record header: %w", err)
	}

	// Check if it's a TLS handshake record
	if header[0] != 0x16 {
		return nil, nil, fmt.Errorf("not a TLS handshake record: %x", header[0])
	}

	// Get record length
	recordLen := int(header[3])<<8 | int(header[4])
	if recordLen > 16384 {
		return nil, nil, fmt.Errorf("TLS record too large: %d", recordLen)
	}

	// Read the entire record
	fullRecord, err := reader.Peek(5 + recordLen)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read full TLS record: %w", err)
	}

	// Now actually consume the bytes we peeked
	data := make([]byte, 5+recordLen)
	if _, err := reader.Read(data); err != nil {
		return nil, nil, fmt.Errorf("failed to read TLS record: %w", err)
	}

	// Parse the ClientHello
	hello, err := parseClientHello(fullRecord[5:])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse ClientHello: %w", err)
	}

	return hello, data, nil
}

// parseClientHello parses a TLS ClientHello message
func parseClientHello(data []byte) (*ClientHello, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("ClientHello too short")
	}

	// Check handshake type (ClientHello = 1)
	if data[0] != 0x01 {
		return nil, fmt.Errorf("not a ClientHello: %x", data[0])
	}

	// Get handshake length
	hsLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if len(data) < 4+hsLen {
		return nil, fmt.Errorf("ClientHello truncated")
	}

	pos := 4

	// Skip client version (2 bytes)
	pos += 2

	// Skip client random (32 bytes)
	pos += 32

	// Skip session ID
	if pos >= len(data) {
		return nil, fmt.Errorf("ClientHello truncated at session ID length")
	}
	sessionIDLen := int(data[pos])
	pos += 1 + sessionIDLen

	// Skip cipher suites
	if pos+2 > len(data) {
		return nil, fmt.Errorf("ClientHello truncated at cipher suites")
	}
	cipherSuitesLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2 + cipherSuitesLen

	// Skip compression methods
	if pos >= len(data) {
		return nil, fmt.Errorf("ClientHello truncated at compression methods")
	}
	compressionLen := int(data[pos])
	pos += 1 + compressionLen

	// Check if we have extensions
	if pos+2 > len(data) {
		// No extensions
		return &ClientHello{}, nil
	}

	extensionsLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2

	if pos+extensionsLen > len(data) {
		return nil, fmt.Errorf("ClientHello extensions truncated")
	}

	// Parse extensions
	extensionsEnd := pos + extensionsLen
	hello := &ClientHello{}

	for pos+4 <= extensionsEnd {
		extType := int(data[pos])<<8 | int(data[pos+1])
		extLen := int(data[pos+2])<<8 | int(data[pos+3])
		pos += 4

		if pos+extLen > extensionsEnd {
			break
		}

		// SNI extension (type 0)
		if extType == 0 && extLen > 2 {
			// Parse SNI extension
			sni := parseSNIExtension(data[pos : pos+extLen])
			if sni != "" {
				hello.ServerName = sni
			}
		}

		pos += extLen
	}

	return hello, nil
}

// parseSNIExtension parses the SNI extension data
func parseSNIExtension(data []byte) string {
	if len(data) < 5 {
		return ""
	}

	// SNI list length
	listLen := int(data[0])<<8 | int(data[1])
	if listLen+2 > len(data) {
		return ""
	}

	pos := 2
	for pos+3 <= 2+listLen {
		nameType := data[pos]
		nameLen := int(data[pos+1])<<8 | int(data[pos+2])
		pos += 3

		if pos+nameLen > len(data) {
			break
		}

		// Host name type (0)
		if nameType == 0 {
			return string(data[pos : pos+nameLen])
		}

		pos += nameLen
	}

	return ""
}
