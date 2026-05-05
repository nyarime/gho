package gho

import "errors"

// ErrBadPassword is returned when the password is empty or decryption fails.
var ErrBadPassword = errors.New("gho: invalid password")

// CRC16Cipher implements the Ghost CRC-16 stream cipher used for GHO encryption.
//
// Ghost uses a CRC-16 based stream cipher where each byte of plaintext is
// XORed with the low byte of a running CRC-16 state. The CRC state is
// updated with each plaintext byte, creating a password-dependent keystream.
//
// The password is used to initialize the CRC-16 state by feeding each
// password byte through the CRC update function.
//
// Reversed from Norton Ghost 11.5.1 encryption routines.
type CRC16Cipher struct {
	state uint16
}

// CRC-16 lookup table (CRC-16/ARC polynomial 0xA001, bit-reversed 0x8005)
var crc16Table [256]uint16

func init() {
	for i := 0; i < 256; i++ {
		crc := uint16(i)
		for j := 0; j < 8; j++ {
			if crc&1 != 0 {
				crc = (crc >> 1) ^ 0xA001
			} else {
				crc >>= 1
			}
		}
		crc16Table[i] = crc
	}
}

// NewCRC16Cipher creates a new CRC-16 stream cipher initialized with the given password.
func NewCRC16Cipher(password string) (*CRC16Cipher, error) {
	if password == "" {
		return nil, ErrBadPassword
	}

	c := &CRC16Cipher{state: 0xFFFF}
	// Initialize state from password
	for _, b := range []byte(password) {
		c.state = crc16Update(c.state, b)
	}
	return c, nil
}

// crc16Update updates the CRC-16 state with one byte.
func crc16Update(crc uint16, b byte) uint16 {
	return (crc >> 8) ^ crc16Table[(crc^uint16(b))&0xFF]
}

// Decrypt decrypts data in-place using the CRC-16 stream cipher.
// Each byte is XORed with the low byte of the CRC state, then the CRC
// state is updated with the decrypted (plaintext) byte.
func (c *CRC16Cipher) Decrypt(data []byte) {
	for i := range data {
		plain := data[i] ^ byte(c.state)
		c.state = crc16Update(c.state, plain)
		data[i] = plain
	}
}

// Encrypt encrypts data in-place using the CRC-16 stream cipher.
// Each plaintext byte updates the CRC state, then is XORed with the
// low byte of the previous CRC state.
func (c *CRC16Cipher) Encrypt(data []byte) {
	for i := range data {
		cipher := data[i] ^ byte(c.state)
		c.state = crc16Update(c.state, data[i])
		data[i] = cipher
	}
}

// Reset reinitializes the cipher with a new password.
func (c *CRC16Cipher) Reset(password string) {
	c.state = 0xFFFF
	for _, b := range []byte(password) {
		c.state = crc16Update(c.state, b)
	}
}

// IsEncrypted checks if a GHO file header indicates encryption is enabled.
// Ghost sets a specific flag pattern when encryption is used.
// The encryption indicator is at header byte 12 (after ID field), bit 0.
func IsEncrypted(header []byte) bool {
	if len(header) < 14 {
		return false
	}
	// Ghost encryption flag: byte 12 bit 1
	// Bytes 8-10 are generic flags, NOT encryption indicators
	return header[12]&0x02 != 0
}
