// Only IPv4, Only tunnel, Only ESP, Only AES-128-CBC
package main

import "github.com/intel-go/yanff/flow"
import "github.com/intel-go/yanff/packet"

import "unsafe"
import "math"
import "bytes"

import "crypto/aes"
import "crypto/cipher"
import "crypto/hmac"
import "crypto/sha1"
import "hash"

func main() {
	flow.SystemInit(32)

	input := flow.SetReceiver(0)
	flow.SetHandler(input, encapsulation, *(new(Context)))
	flow.SetHandler(input, decapsulation, *(new(Context)))
	flow.SetSender(input, 1)

	flow.SystemStart()
}

type Context struct {
	mac123  hash.Hash
	modeEnc cipher.BlockMode
	modeDec cipher.BlockMode
}

type SetIVer interface {
	SetIV([]byte)
}

func (c Context) Copy() interface{} {
	n := new(Context)
	n.mac123 = hmac.New(sha1.New, []byte("qqqqqqqqqqqqqqqqqqqq"))
	block123, _ := aes.NewCipher([]byte("AES128Key-16Char"))
	n.modeEnc = cipher.NewCBCEncrypter(block123, make([]byte, 16))
	n.modeDec = cipher.NewCBCDecrypter(block123, make([]byte, 16))
	return n
}

const ESP = 0x32
const MODE_1230 = 1230
const espHeadLen = 24
const authLen = 12
const espTailLen = authLen + 2
const etherLen = packet.EtherLen
const outerIPLen = packet.IPv4MinLen

type ESPHeader struct {
	SPI uint32
	SEQ uint32
	IV  [16]byte
}

type ESPTail struct {
	paddingLen uint8
	nextIP     uint8
	Auth       [authLen]byte
}

// General decapsulation
func decapsulation(currentPacket *packet.Packet, context flow.UserContext) bool {
	length := currentPacket.GetPacketLen()
	currentESPHeader := (*ESPHeader)(unsafe.Pointer(currentPacket.Unparsed + etherLen + outerIPLen))
	currentESPTail := (*ESPTail)(unsafe.Pointer(currentPacket.Unparsed + uintptr(length) - espTailLen))
	// Security Association
	switch packet.SwapBytesUint32(currentESPHeader.SPI) {
	case MODE_1230:
		encryptionPart := (*[math.MaxInt32]byte)(unsafe.Pointer(currentPacket.Unparsed))[etherLen+outerIPLen+espHeadLen : length-authLen]
		authPart := (*[math.MaxInt32]byte)(unsafe.Pointer(currentPacket.Unparsed))[etherLen+outerIPLen : length-authLen]
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
	context := context0.(*Context)

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
func encapsulation(currentPacket *packet.Packet, context flow.UserContext) bool {
	// Limitation: All packets will be encapsulated as 1230
	currentPacket.EncapsulateHead(etherLen, outerIPLen+espHeadLen)

	currentPacket.ParseIPv4()
	*(*([4]byte))(unsafe.Pointer(&currentPacket.IPv4.SrcAddr)) = [4]byte{111, 22, 3, 0}
	*(*([4]byte))(unsafe.Pointer(&currentPacket.IPv4.DstAddr)) = [4]byte{3, 22, 111, 0}
	currentPacket.IPv4.VersionIhl = 0x45
	currentPacket.IPv4.NextProtoID = ESP

	encapsulationSPI123(currentPacket, context)

	return true
}

// Specific encapsulation
func encapsulationSPI123(currentPacket *packet.Packet, context0 flow.UserContext) {
	context := context0.(*Context)
	length := currentPacket.GetPacketLen()
	paddingLength := uint8((16 - (length-(etherLen+outerIPLen+espHeadLen)-espTailLen)%16) % 16)
	new_length := length + uint(paddingLength) + espTailLen
	currentPacket.EncapsulateTail(length, uint(paddingLength)+espTailLen)

	currentESPHeader := (*ESPHeader)(unsafe.Pointer(currentPacket.Unparsed + etherLen + outerIPLen))
	currentESPHeader.SPI = packet.SwapBytesUint32(MODE_1230)
	// Limitation: should be random
	currentESPHeader.IV = [16]byte{0x90, 0x9d, 0x78, 0xa8, 0x72, 0x70, 0x68, 0x00, 0x8f, 0xdc, 0x55, 0x73, 0xa3, 0x75, 0xb5, 0xa7}

	currentESPTail := (*ESPTail)(unsafe.Pointer(currentPacket.Unparsed + uintptr(new_length) - espTailLen))
	currentESPTail.paddingLen = paddingLength
	currentESPTail.nextIP = packet.IPNumber

	// Encryption
	EncryptionPart := (*[math.MaxInt32]byte)(unsafe.Pointer(currentPacket.Unparsed))[etherLen+outerIPLen+espHeadLen : new_length-authLen]
	context.modeEnc.(SetIVer).SetIV(currentESPHeader.IV[:])
	context.modeEnc.CryptBlocks(EncryptionPart, EncryptionPart)

	// Authentication
	context.mac123.Reset()
	AuthPart := (*[math.MaxInt32]byte)(unsafe.Pointer(currentPacket.Unparsed))[etherLen+outerIPLen : new_length-authLen]
	context.mac123.Write(AuthPart)
	copy(currentESPTail.Auth[:], context.mac123.Sum(nil))
}
