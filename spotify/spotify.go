package spotify

import (
	"bytes"
	"fmt"
	"log"
	"strings"
)

// Protobuf wire types
const (
	wireTypeVarint          = 0
	wireTypeLengthDelimited = 2
)

// Premium attributes to inject
var spotifyAttributes = map[string]interface{}{
	"player-license":    "premium",
	"streaming-rules":   "",
	"financial-product": "pr:premium,tc:0",
	"name":              "Spotify Premium",
	"on-demand":         int64(1),
	"ads":               int64(0),
	"catalogue":         "premium",
	"high-bitrate":      int64(1),
	"nft-disabled":      "1",
	"offline":           int64(1),
	"pause-after":       int64(0),
	"can_use_superbird": int64(1),
	"type":              "premium",
	"com.spotify.madprops.use.ucs.product.state": int64(1),
	"com.spotify.madprops.delivered.by.ucs":      int64(1),
	"payments-initial-campaign":                  "default",
	"unrestricted":                               int64(1),
	"shuffle-eligible":                           int64(1),
	"social-session":                             int64(1),
	"social-session-free-tier":                   int64(0),
}

// Attributes to delete
var spotifyDelete = []string{
	"ad-use-adlogic",
	"ad-catalogues",
}

// IsSpotifyClient checks if the host is a Spotify client host
func IsSpotifyClient(host string) bool {
	return host == "spclient.wg.spotify.com" || strings.Contains(host, "spclient.spotify.com")
}

// IsSpotifyPath checks if the request path requires modification
func IsSpotifyPath(path string) bool {
	paths := []string{"v1/customize", "v1/bootstrap"}
	for _, p := range paths {
		if strings.Contains(path, p) {
			return true
		}
	}
	return false
}

// ShouldBlockPath checks if the request should be blocked (ads, trackers)
func ShouldBlockPath(path string) bool {
	blockedPaths := []string{
		"/ads/",
		"/ad-logic/",
		"/desktop-update/",
		"/gabo-receiver-service/",
	}
	for _, p := range blockedPaths {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// ModifyArtistViewPath modifies artist view path for better content
func ModifyArtistViewPath(path string) string {
	if strings.HasPrefix(path, "/artistview/v1/artist") {
		return strings.Replace(path, "platform=iphone", "platform=ipad", 1)
	}
	return path
}

// ModifyProtobufResponse modifies the Spotify protobuf response to enable premium features
// This is a simplified implementation - protobuf modification without external dependencies
func ModifyProtobufResponse(data []byte, isBootstrap bool) ([]byte, error) {
	// Find config list in protobuf structure
	// The protobuf structure varies between bootstrap and regular requests

	// For now, we'll use a simple pattern matching approach
	// In a production implementation, you'd want a proper protobuf parser

	modified := false
	result := data

	// Look for known attribute patterns and modify them
	for key, value := range spotifyAttributes {
		keyBytes := []byte(key)
		idx := bytes.Index(result, keyBytes)
		if idx != -1 {
			// Found the key, this is a simplified approach
			// Real implementation would need proper protobuf field parsing
			modified = true
			log.Printf("[Spotify] Found attribute: %s", key)
			_ = value // Would be used in actual modification
		}
	}

	// Check for attributes to delete
	for _, key := range spotifyDelete {
		keyBytes := []byte(key)
		if bytes.Contains(result, keyBytes) {
			log.Printf("[Spotify] Found attribute to delete: %s", key)
			modified = true
		}
	}

	if modified {
		log.Println("[Spotify] Protobuf structure detected, attempting modification")
		// Apply modifications using the protobuf helper
		modifiedData, err := modifyProtobufConfigs(result, isBootstrap)
		if err != nil {
			return nil, fmt.Errorf("failed to modify protobuf: %w", err)
		}
		return modifiedData, nil
	}

	log.Println("[Spotify] No modifications needed")
	return nil, nil
}

// modifyProtobufConfigs handles the actual protobuf modification
func modifyProtobufConfigs(data []byte, isBootstrap bool) ([]byte, error) {
	// Parse the protobuf message
	msg, err := parseProtobuf(data)
	if err != nil {
		return nil, err
	}

	// Navigate to configs based on bootstrap flag
	var configs interface{}
	if isBootstrap {
		// message['2']['1']['1']['1']['3']['1']
		configs = navigateProto(msg, []int{2, 1, 1, 1, 3, 1})
	} else {
		// message['1']['3']['1']
		configs = navigateProto(msg, []int{1, 3, 1})
	}

	if configs == nil {
		return nil, fmt.Errorf("configs not found in protobuf")
	}

	// Modify configs
	modified, newConfigs := modifyConfigs(configs)
	if !modified {
		return nil, nil
	}

	// Write back the modified configs to the message
	if isBootstrap {
		if err := setProtoValue(msg, []int{2, 1, 1, 1, 3, 1}, newConfigs); err != nil {
			return nil, err
		}
	} else {
		if err := setProtoValue(msg, []int{1, 3, 1}, newConfigs); err != nil {
			return nil, err
		}
	}

	// Re-encode the message
	return encodeProtobuf(msg)
}

// setProtoValue sets a value at a specific path in the protobuf message
func setProtoValue(msg ProtoMessage, path []int, value interface{}) error {
	if len(path) == 0 {
		return fmt.Errorf("empty path")
	}

	// Navigate to the parent of the target
	var current interface{} = msg
	for i := 0; i < len(path)-1; i++ {
		idx := path[i]
		if m, ok := current.(ProtoMessage); ok {
			if next, ok := m[idx]; ok {
				current = next
			} else {
				return fmt.Errorf("path not found at index %d", idx)
			}
		} else {
			return fmt.Errorf("intermediate node is not a message")
		}
	}

	// Set the value in the parent
	targetIdx := path[len(path)-1]
	if m, ok := current.(ProtoMessage); ok {
		m[targetIdx] = value
		return nil
	}

	return fmt.Errorf("parent is not a message")
}

// ProtoMessage represents a parsed protobuf message
type ProtoMessage map[int]interface{}

// parseProtobuf parses raw protobuf bytes into a message structure
func parseProtobuf(data []byte) (ProtoMessage, error) {
	msg := make(ProtoMessage)
	pos := 0

	for pos < len(data) {
		if pos >= len(data) {
			break
		}

		// Read field header (varint)
		fieldHeader, n := decodeVarint(data[pos:])
		if n == 0 {
			break
		}
		pos += n

		fieldNum := int(fieldHeader >> 3)
		wireType := fieldHeader & 0x7

		var value interface{}
		var consumed int

		switch wireType {
		case 0: // Varint
			v, n := decodeVarint(data[pos:])
			value = v
			consumed = n
		case 1: // 64-bit
			if pos+8 > len(data) {
				return nil, fmt.Errorf("truncated 64-bit field")
			}
			value = data[pos : pos+8]
			consumed = 8
		case 2: // Length-delimited
			length, n := decodeVarint(data[pos:])
			if n == 0 {
				return nil, fmt.Errorf("invalid length prefix")
			}
			pos += n
			if pos+int(length) > len(data) {
				return nil, fmt.Errorf("truncated length-delimited field")
			}
			fieldData := data[pos : pos+int(length)]

			// Try to parse as nested message
			if nested, err := parseProtobuf(fieldData); err == nil && len(nested) > 0 {
				value = nested
			} else {
				// Treat as bytes/string
				value = fieldData
			}
			consumed = int(length)
		case 5: // 32-bit
			if pos+4 > len(data) {
				return nil, fmt.Errorf("truncated 32-bit field")
			}
			value = data[pos : pos+4]
			consumed = 4
		default:
			return nil, fmt.Errorf("unknown wire type: %d", wireType)
		}

		pos += consumed

		// Handle repeated fields
		if existing, ok := msg[fieldNum]; ok {
			switch e := existing.(type) {
			case []interface{}:
				msg[fieldNum] = append(e, value)
			default:
				msg[fieldNum] = []interface{}{e, value}
			}
		} else {
			msg[fieldNum] = value
		}
	}

	return msg, nil
}

// encodeProtobuf encodes a message back to bytes
func encodeProtobuf(msg ProtoMessage) ([]byte, error) {
	var buf bytes.Buffer

	for fieldNum, value := range msg {
		if err := encodeField(&buf, fieldNum, value); err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

func encodeField(buf *bytes.Buffer, fieldNum int, value interface{}) error {
	switch v := value.(type) {
	case int64, uint64:
		// Varint
		header := uint64(fieldNum<<3) | wireTypeVarint
		buf.Write(encodeVarint(header))
		var val uint64
		switch vv := v.(type) {
		case int64:
			val = uint64(vv)
		case uint64:
			val = vv
		}
		buf.Write(encodeVarint(val))

	case []byte:
		// Length-delimited
		header := uint64(fieldNum<<3) | wireTypeLengthDelimited
		buf.Write(encodeVarint(header))
		buf.Write(encodeVarint(uint64(len(v))))
		buf.Write(v)

	case string:
		// Length-delimited string
		header := uint64(fieldNum<<3) | wireTypeLengthDelimited
		buf.Write(encodeVarint(header))
		buf.Write(encodeVarint(uint64(len(v))))
		buf.WriteString(v)

	case ProtoMessage:
		// Nested message
		nested, err := encodeProtobuf(v)
		if err != nil {
			return err
		}
		header := uint64(fieldNum<<3) | wireTypeLengthDelimited
		buf.Write(encodeVarint(header))
		buf.Write(encodeVarint(uint64(len(nested))))
		buf.Write(nested)

	case []interface{}:
		// Repeated field
		for _, item := range v {
			if err := encodeField(buf, fieldNum, item); err != nil {
				return err
			}
		}

	default:
		return fmt.Errorf("unsupported type: %T", v)
	}

	return nil
}

func decodeVarint(data []byte) (uint64, int) {
	var result uint64
	var shift uint
	for i, b := range data {
		result |= uint64(b&0x7F) << shift
		if b&0x80 == 0 {
			return result, i + 1
		}
		shift += 7
		if shift >= 64 {
			return 0, 0
		}
	}
	return 0, 0
}

func encodeVarint(v uint64) []byte {
	var buf [10]byte
	n := 0
	for v >= 0x80 {
		buf[n] = byte(v) | 0x80
		v >>= 7
		n++
	}
	buf[n] = byte(v)
	return buf[:n+1]
}

func navigateProto(msg ProtoMessage, path []int) interface{} {
	var current interface{} = msg
	for _, idx := range path {
		switch c := current.(type) {
		case ProtoMessage:
			var ok bool
			current, ok = c[idx]
			if !ok {
				return nil
			}
		default:
			return nil
		}
	}
	return current
}

func modifyConfigs(configs interface{}) (bool, interface{}) {
	modified := false
	newConfigs := configs

	switch c := configs.(type) {
	case []interface{}:
		var newList []interface{}
		for _, item := range c {
			if configMap, ok := item.(ProtoMessage); ok {
				mod, del := modifyConfig(configMap)
				if del {
					modified = true
					continue // Skip this item (delete)
				}
				if mod {
					modified = true
				}
				newList = append(newList, configMap)
			} else {
				newList = append(newList, item)
			}
		}
		newConfigs = newList
	case ProtoMessage:
		if mod, del := modifyConfig(c); mod || del {
			modified = true
			if del {
				newConfigs = nil // Should not happen for repeated field usually, but handling generic case
			}
		}
	}

	return modified, newConfigs
}

func modifyConfig(config ProtoMessage) (bool, bool) {
	// Config structure: {'1': 'attr_key', '2': {'value_key': 'value'}}
	attrKeyRaw, ok := config[1]
	if !ok {
		return false, false
	}

	var attrKey string
	switch v := attrKeyRaw.(type) {
	case []byte:
		attrKey = string(v)
	case string:
		attrKey = v
	default:
		return false, false
	}

	// Check if this attribute should be deleted
	for _, del := range spotifyDelete {
		if attrKey == del {
			log.Printf("[Spotify] Deleting attribute: %s", attrKey)
			return true, true // Modified, Deleted
		}
	}

	// Check if this attribute should be modified
	newValue, ok := spotifyAttributes[attrKey]
	if !ok {
		return false, false
	}

	// Modify the value
	valueMap, ok := config[2].(ProtoMessage)
	if !ok {
		return false, false
	}

	for key := range valueMap {
		switch v := newValue.(type) {
		case string:
			valueMap[key] = []byte(v)
		case int64:
			valueMap[key] = v
		}
		log.Printf("[Spotify] Modified attribute: %s", attrKey)
		return true, false // Modified, Not Deleted
	}

	return false, false
}
