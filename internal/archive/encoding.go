package archive

import (
	"encoding/base64"
	"encoding/hex"
)

func b64Encode(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func b64Decode(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }

func b64DecodeStrict(s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func hexDecode(s string) ([]byte, error) { return hex.DecodeString(s) }
