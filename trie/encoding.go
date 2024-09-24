// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package trie

// Trie keys are dealt with in three distinct encodings:
//
// KEYBYTES encoding contains the actual key and nothing else. This encoding is the
// input to most API functions.
//
// HEX encoding contains one byte for each nibble of the key and an optional trailing
// 'terminator' byte of value 0x10 which indicates whether or not the node at the key
// contains a value. Hex key encoding is used for nodes loaded in memory because it's
// convenient to access.
//
// COMPACT encoding is defined by the Ethereum Yellow Paper (it's called "hex prefix
// encoding" there) and contains the bytes of the key and a flag. The high nibble of the
// first byte contains the flag; the lowest bit encoding the oddness of the length and
// the second-lowest encoding whether the node at the key is a value node. The low nibble
// of the first byte is zero in the case of an even number of nibbles and the first nibble
// in the case of an odd number. All remaining nibbles (now an even number) fit properly
// into the remaining bytes. Compact encoding is used for nodes stored on disk.

func hexToCompact(hex []byte) []byte {
	terminator := byte(0)
	if hasTerm(hex) {
		terminator = 1
		hex = hex[:len(hex)-1]
	}
	buf := make([]byte, len(hex)/2+1)
	buf[0] = terminator << 5 // the flag byte
	if len(hex)&1 == 1 {
		buf[0] |= 1 << 4 // odd flag
		buf[0] |= hex[0] // first nibble is contained in the first byte
		hex = hex[1:]
	}
	decodeNibbles(hex, buf[1:])
	return buf
}

// hexToCompactInPlace places the compact key in input buffer, returning the length
// needed for the representation
func hexToCompactInPlace(hex []byte) int {
	var (
		hexLen    = len(hex) // length of the hex input
		firstByte = byte(0)
	)
	// Check if we have a terminator there
	if hexLen > 0 && hex[hexLen-1] == 16 {
		firstByte = 1 << 5
		hexLen-- // last part was the terminator, ignore that
	}
	var (
		binLen = hexLen/2 + 1
		ni     = 0 // index in hex
		bi     = 1 // index in bin (compact)
	)
	if hexLen&1 == 1 {
		firstByte |= 1 << 4 // odd flag
		firstByte |= hex[0] // first nibble is contained in the first byte
		ni++
	}
	for ; ni < hexLen; bi, ni = bi+1, ni+2 {
		hex[bi] = hex[ni]<<4 | hex[ni+1]
	}
	hex[0] = firstByte
	return binLen
}

func compactToHex(compact []byte) []byte {
	if len(compact) == 0 {
		return compact
	}
	base := keybytesToHex(compact)
	// delete terminator flag
	if base[0] < 2 {
		base = base[:len(base)-1]
	}
	// apply odd flag
	chop := 2 - base[0]&1
	return base[chop:]
}

func keybytes32ToToHex(str [32]byte) []byte {
	l := len(str)*2 + 1
	var nibbles = make([]byte, l)

	nibbles[0*2] = str[0] / 16
	nibbles[0*2+1] = str[0] % 16
	nibbles[1*2] = str[1] / 16
	nibbles[1*2+1] = str[1] % 16
	nibbles[2*2] = str[2] / 16
	nibbles[2*2+1] = str[2] % 16
	nibbles[3*2] = str[3] / 16
	nibbles[3*2+1] = str[3] % 16
	nibbles[4*2] = str[4] / 16
	nibbles[4*2+1] = str[4] % 16
	nibbles[5*2] = str[5] / 16
	nibbles[5*2+1] = str[5] % 16
	nibbles[6*2] = str[6] / 16
	nibbles[6*2+1] = str[6] % 16
	nibbles[7*2] = str[7] / 16
	nibbles[7*2+1] = str[7] % 16
	nibbles[8*2] = str[8] / 16
	nibbles[8*2+1] = str[8] % 16
	nibbles[9*2] = str[9] / 16
	nibbles[9*2+1] = str[9] % 16
	nibbles[10*2] = str[10] / 16
	nibbles[10*2+1] = str[10] % 16
	nibbles[11*2] = str[11] / 16
	nibbles[11*2+1] = str[11] % 16
	nibbles[12*2] = str[12] / 16
	nibbles[12*2+1] = str[12] % 16
	nibbles[13*2] = str[13] / 16
	nibbles[13*2+1] = str[13] % 16
	nibbles[14*2] = str[14] / 16
	nibbles[14*2+1] = str[14] % 16
	nibbles[15*2] = str[15] / 16
	nibbles[15*2+1] = str[15] % 16
	nibbles[16*2] = str[16] / 16
	nibbles[16*2+1] = str[16] % 16
	nibbles[17*2] = str[17] / 16
	nibbles[17*2+1] = str[17] % 16
	nibbles[18*2] = str[18] / 16
	nibbles[18*2+1] = str[18] % 16
	nibbles[19*2] = str[19] / 16
	nibbles[19*2+1] = str[19] % 16
	nibbles[20*2] = str[20] / 16
	nibbles[20*2+1] = str[20] % 16
	nibbles[21*2] = str[21] / 16
	nibbles[21*2+1] = str[21] % 16
	nibbles[22*2] = str[22] / 16
	nibbles[22*2+1] = str[22] % 16
	nibbles[23*2] = str[23] / 16
	nibbles[23*2+1] = str[23] % 16
	nibbles[24*2] = str[24] / 16
	nibbles[24*2+1] = str[24] % 16
	nibbles[25*2] = str[25] / 16
	nibbles[25*2+1] = str[25] % 16
	nibbles[26*2] = str[26] / 16
	nibbles[26*2+1] = str[26] % 16
	nibbles[27*2] = str[27] / 16
	nibbles[27*2+1] = str[27] % 16
	nibbles[28*2] = str[28] / 16
	nibbles[28*2+1] = str[28] % 16
	nibbles[29*2] = str[29] / 16
	nibbles[29*2+1] = str[29] % 16
	nibbles[30*2] = str[30] / 16
	nibbles[30*2+1] = str[30] % 16
	nibbles[31*2] = str[31] / 16
	nibbles[31*2+1] = str[31] % 16

	nibbles[l-1] = 16
	return nibbles
}

func keybytesToHex(str []byte) []byte {
	if len(str) == 32 {
		return keybytes32ToToHex(([32]byte)(str))
	}

	l := len(str)*2 + 1
	var nibbles = make([]byte, l)
	for i, b := range str {
		nibbles[i*2] = b / 16
		nibbles[i*2+1] = b % 16
	}
	nibbles[l-1] = 16
	return nibbles
}

// hexToKeybytes turns hex nibbles into key bytes.
// This can only be used for keys of even length.
func hexToKeybytes(hex []byte) []byte {
	if hasTerm(hex) {
		hex = hex[:len(hex)-1]
	}
	if len(hex)&1 != 0 {
		panic("can't convert hex key of odd length")
	}
	key := make([]byte, len(hex)/2)
	decodeNibbles(hex, key)
	return key
}

func decodeNibbles(nibbles []byte, bytes []byte) {
	for bi, ni := 0, 0; ni < len(nibbles); bi, ni = bi+1, ni+2 {
		bytes[bi] = nibbles[ni]<<4 | nibbles[ni+1]
	}
}

// prefixLen returns the length of the common prefix of a and b.
func prefixLen(a, b []byte) int {
	var i, length = 0, len(a)
	if len(b) < length {
		length = len(b)
	}
	for ; i < length; i++ {
		if a[i] != b[i] {
			break
		}
	}
	return i
}

// hasTerm returns whether a hex key has the terminator flag.
func hasTerm(s []byte) bool {
	return len(s) > 0 && s[len(s)-1] == 16
}
