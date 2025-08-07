package util

/*
	Sliver Implant Framework
	Copyright (C) 2021  Bishop Fox

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rc4"
	"errors"
	"io"
	"math"
)

// RC4 encryption - Cryptographically insecure!
// Added for stage-listener shellcode obfuscation
// Dont use for anything else!
// DEPRECATED: This function is cryptographically insecure and should not be used
// in production environments. Use AES-GCM or ChaCha20-Poly1305 instead.
func RC4EncryptUnsafe(data []byte, key []byte) []byte {
	// Validate key length for RC4 (should be 1-256 bytes)
	if len(key) == 0 || len(key) > 256 {
		return make([]byte, 0)
	}

	cipher, err := rc4.NewCipher(key)
	if err != nil {
		return make([]byte, 0)
	}
	cipherText := make([]byte, len(data))
	cipher.XORKeyStream(cipherText, data)
	return cipherText
}

// PreludeEncrypt the results
func PreludeEncrypt(data []byte, key []byte, iv []byte) []byte {
	plainText, err := pad(data, aes.BlockSize)
	if err != nil {
		return make([]byte, 0)
	}
	block, _ := aes.NewCipher(key)

	// Check for integer overflow in buffer allocation
	if len(plainText) > math.MaxInt-aes.BlockSize {
		return make([]byte, 0)
	}

	cipherText := make([]byte, aes.BlockSize+len(plainText))
	// Create a random IV if none was provided
	// len(nil) returns 0
	if len(iv) == 0 {
		iv = cipherText[:aes.BlockSize]
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return make([]byte, 0)
		}
	} else {
		// make sure we copy the IV
		copy(cipherText[:aes.BlockSize], iv)
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText[aes.BlockSize:], plainText)
	return cipherText
}

// PreludeDecrypt a command
func PreludeDecrypt(data []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	iv := data[:aes.BlockSize]
	data = data[aes.BlockSize:]
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(data, data)
	data, _ = unpad(data, aes.BlockSize)
	return data
}

func pad(buf []byte, size int) ([]byte, error) {
	const maxPadInputSize = 64 * 1024 * 1024 // 64 MiB
	bufLen := len(buf)
	if bufLen < 0 || bufLen > maxPadInputSize {
		return nil, errors.New("pkcs7: Input too large or negative")
	}
	padLen := size - bufLen%size
	if padLen <= 0 || padLen > size {
		return nil, errors.New("pkcs7: Invalid pad length")
	}
	// Check for integer overflow (platform independent)
	if bufLen > math.MaxInt-padLen {
		return nil, errors.New("pkcs7: Input too large, would cause integer overflow")
	}
	totalLen := bufLen + padLen
	if totalLen < 0 || totalLen > maxPadInputSize+size {
		return nil, errors.New("pkcs7: Padded buffer too large or negative")
	}
	padded := make([]byte, totalLen)
	copy(padded, buf)
	for i := 0; i < padLen; i++ {
		padded[bufLen+i] = byte(padLen)
	}
	return padded, nil
}

func unpad(padded []byte, size int) ([]byte, error) {
	if len(padded)%size != 0 {
		return nil, errors.New("pkcs7: Padded value wasn't in correct size")
	}

	// Check for buffer underflow
	if len(padded) == 0 {
		return nil, errors.New("pkcs7: Empty padded data")
	}

	padLen := int(padded[len(padded)-1])
	if padLen <= 0 || padLen > len(padded) {
		return nil, errors.New("pkcs7: Invalid padding length")
	}

	bufLen := len(padded) - padLen
	if bufLen < 0 {
		return nil, errors.New("pkcs7: Invalid buffer length")
	}

	buf := make([]byte, bufLen)
	copy(buf, padded[:bufLen])
	return buf, nil
}
