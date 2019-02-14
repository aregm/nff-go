// Copyright 2019 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Only IPv4, Only tunnel, Only ESP, Only AES-128-CBC
package ipsec

import "github.com/intel-go/nff-go/packet"
import "github.com/intel-go/nff-go/flow"
import "github.com/intel-go/nff-go/types"
import "bytes"
import "unsafe"
import "crypto/aes"

const esp = 0x32
const mode1234 = 1234
const espHeadLen = 24
const authLen = 12
const espTailLen = authLen + 2
const etherLen = types.EtherLen
const outerIPLen = types.IPv4MinLen

type espHeader struct {
	SPI uint32
	SEQ uint32
	IV  [16]byte
}

type espTail struct {
	paddingLen uint8
	nextIP     uint8
	Auth       [authLen]byte
}

// General decapsulation
func Decapsulation(currentPacket *packet.Packet, context flow.UserContext) bool {
	length := currentPacket.GetPacketLen()
	currentESPHeader := (*espHeader)(currentPacket.StartAtOffset(etherLen + outerIPLen))
	currentESPTail := (*espTail)(unsafe.Pointer(currentPacket.StartAtOffset(uintptr(length) - espTailLen)))
	// Security Association
	switch packet.SwapBytesUint32(currentESPHeader.SPI) {
	case mode1234:
		encryptionPart := (*[types.MaxLength]byte)(unsafe.Pointer(currentPacket.StartAtOffset(0)))[etherLen+outerIPLen+espHeadLen : length-authLen]
		authPart := (*[types.MaxLength]byte)(unsafe.Pointer(currentPacket.StartAtOffset(0)))[etherLen+outerIPLen : length-authLen]
		if decapsulationSPI123(authPart, currentESPTail.Auth, currentESPHeader.IV, encryptionPart, context) == false {
			return false
		}
	default:
		return false
	}
	// Decapsulate
	currentPacket.DecapsulateHead(etherLen, outerIPLen+espHeadLen)
	currentPacket.DecapsulateTail(length-espTailLen-uint(currentESPTail.paddingLen), uint(currentESPTail.paddingLen)+espTailLen)

	return true
}

// Specific decapsulation
func decapsulationSPI123(currentAuth []byte, Auth [authLen]byte, iv [16]byte, ciphertext []byte, context0 flow.UserContext) bool {
	context := (context0).(*SContext)

	context.mac123.Reset()
	context.mac123.Write(currentAuth)
	if bytes.Equal(context.mac123.Sum(nil)[0:12], Auth[:]) == false {
		return false
	}

	// Decryption
	if len(ciphertext) < aes.BlockSize || len(ciphertext)%aes.BlockSize != 0 {
		return false
	}
	context.modeDec.(SetIVer).SetIV(iv[:])
	context.modeDec.CryptBlocks(ciphertext, ciphertext)
	return true
}

// General encapsulation
func VectorEncapsulation(currentPackets []*packet.Packet, mask *[32]bool, notDrop *[32]bool, context flow.UserContext) {
	n := uint(0)
	for i := uint(0); i < 32; i++ {
		if (*mask)[i] == true {
			currentPackets[i].EncapsulateHead(etherLen, outerIPLen+espHeadLen)
			currentPackets[i].ParseL3()
			ipv4 := currentPackets[i].GetIPv4NoCheck()
			ipv4.SrcAddr = types.BytesToIPv4(111, 22, 3, 0)
			ipv4.DstAddr = types.BytesToIPv4(3, 22, 111, 0)
			ipv4.VersionIhl = 0x45
			ipv4.NextProtoID = esp
			notDrop[i] = true
			n++
		}
	}
	// TODO All packets will be encapsulated as 1234
	vectorEncapsulationSPI123(currentPackets, n, context)
}

// Specific encapsulation
func vectorEncapsulationSPI123(currentPackets []*packet.Packet, n uint, context0 flow.UserContext) {
	context := context0.(*VContext)
	s := VECTOR * (n/VECTOR + 1)
	var Z uint

	// TODO Only for equal length
	length := currentPackets[0].GetPacketLen()
	paddingLength := uint8((16 - (length-(etherLen+outerIPLen+espHeadLen)-espTailLen)%16) % 16)
	newLength := length + uint(paddingLength) + espTailLen

	for i := uint(0); i < s; i += VECTOR {
		if i == s-VECTOR {
			Z = n % VECTOR
		} else {
			Z = VECTOR
		}
		for t := uint(0); t < Z; t++ {
			currentPackets[i+t].GetIPv4NoCheck().TotalLength = packet.SwapBytesUint16(uint16(newLength) - etherLen)
			currentPackets[i+t].EncapsulateTail(length, uint(paddingLength)+espTailLen)

			currentESPHeader := (*espHeader)(unsafe.Pointer(currentPackets[i+t].StartAtOffset(etherLen + outerIPLen)))
			currentESPHeader.SPI = packet.SwapBytesUint32(mode1234)
			// TODO should be random
			currentESPHeader.IV = [16]byte{0x90, 0x9d, 0x78, 0xa8, 0x72, 0x70, 0x68, 0x00, 0x8f, 0xdc, 0x55, 0x73, 0xa3, 0x75, 0xb5, 0xa7}

			currentESPTail := (*espTail)(unsafe.Pointer(currentPackets[i+t].StartAtOffset(uintptr(newLength) - espTailLen)))
			if paddingLength > 0 {
				// 1 2 3 4 5 6 7 8
				*(*uint64)(unsafe.Pointer(uintptr(unsafe.Pointer(currentESPTail)) - uintptr(paddingLength))) = 578437695752307201
				if paddingLength > 8 {
					// 9 10 11 12 13 14 15 16
					*(*uint64)(unsafe.Pointer(uintptr(unsafe.Pointer(currentESPTail)) - uintptr(paddingLength) + 8)) = 1157159078456920585
				}
			}
			currentESPTail.paddingLen = paddingLength
			currentESPTail.nextIP = types.IPNumber

			context.vectorEncryptionPart[t] = (*[types.MaxLength]byte)(unsafe.Pointer(currentPackets[i+t].StartAtOffset(0)))[etherLen+outerIPLen+espHeadLen : newLength-authLen]
			context.vectorIV[t] = currentESPHeader.IV[:]
			context.vectorAuthPart[t] = (*[types.MaxLength]byte)(unsafe.Pointer(currentPackets[i+t].StartAtOffset(0)))[etherLen+outerIPLen : newLength-authLen]
			context.vectorAuthPlace[t] = currentESPTail.Auth[:]
		}
		Encrypt(context.vectorEncryptionPart, context.vectorEncryptionPart, context.vectorIV, Z, context)
		Authenticate(context.vectorAuthPart, context.vectorAuthPlace, Z, context)
	}
}

// General encapsulation
func ScalarEncapsulation(currentPacket *packet.Packet, context flow.UserContext) bool {
	currentPacket.EncapsulateHead(etherLen, outerIPLen+espHeadLen)

	currentPacket.ParseL3()
	ipv4 := currentPacket.GetIPv4NoCheck()
	ipv4.SrcAddr = types.BytesToIPv4(111, 22, 3, 0)
	ipv4.DstAddr = types.BytesToIPv4(3, 22, 111, 0)
	ipv4.VersionIhl = 0x45
	ipv4.NextProtoID = esp

	// TODO All packets will be encapsulated as 1234
	scalarEncapsulationSPI123(currentPacket, context)
	return true
}

// Specific encapsulation
func scalarEncapsulationSPI123(currentPacket *packet.Packet, context0 flow.UserContext) {
	context := (context0).(*SContext)
	length := currentPacket.GetPacketLen()
	paddingLength := uint8((16 - (length-(etherLen+outerIPLen+espHeadLen)-espTailLen)%16) % 16)
	newLength := length + uint(paddingLength) + espTailLen
	currentPacket.GetIPv4NoCheck().TotalLength = packet.SwapBytesUint16(uint16(newLength) - etherLen)
	currentPacket.EncapsulateTail(length, uint(paddingLength)+espTailLen)

	currentESPHeader := (*espHeader)(currentPacket.StartAtOffset(etherLen + outerIPLen))
	currentESPHeader.SPI = packet.SwapBytesUint32(mode1234)
	// TODO should be random
	currentESPHeader.IV = [16]byte{0x90, 0x9d, 0x78, 0xa8, 0x72, 0x70, 0x68, 0x00, 0x8f, 0xdc, 0x55, 0x73, 0xa3, 0x75, 0xb5, 0xa7}

	currentESPTail := (*espTail)(currentPacket.StartAtOffset(uintptr(newLength) - espTailLen))
	if paddingLength > 0 {
		*(*uint64)(unsafe.Pointer(uintptr(unsafe.Pointer(currentESPTail)) - uintptr(paddingLength))) = 578437695752307201
		if paddingLength > 8 {
			*(*uint64)(unsafe.Pointer(uintptr(unsafe.Pointer(currentESPTail)) - uintptr(paddingLength) + 8)) = 1157159078456920585
		}
	}
	currentESPTail.paddingLen = paddingLength
	currentESPTail.nextIP = types.IPNumber

	// Encryption
	EncryptionPart := (*[types.MaxLength]byte)(currentPacket.StartAtOffset(0))[etherLen+outerIPLen+espHeadLen : newLength-authLen]
	context.modeEnc.(SetIVer).SetIV(currentESPHeader.IV[:])
	context.modeEnc.CryptBlocks(EncryptionPart, EncryptionPart)

	// Authentication
	context.mac123.Reset()
	AuthPart := (*[types.MaxLength]byte)(currentPacket.StartAtOffset(0))[etherLen+outerIPLen : newLength-authLen]
	context.mac123.Write(AuthPart)
	copy(currentESPTail.Auth[:], context.mac123.Sum(nil))
}
