package authn

import (
	"crypto/rand"
	"fmt"
)

// RandHex32 generates a random 32-byte hex string
func RandHex32() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	return fmt.Sprintf("%x", b), err
}
