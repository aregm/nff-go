package utils

import (
	"encoding/binary"
	"fmt"
	"github.com/intel-go/nff-go/common"
	"net"
	"os"
	"strconv"
	"strings"
)

func StringToIPv4(ipaddr string) uint32 {
	str_ary := strings.Split(ipaddr, ".")
	bIp := [4]byte{}

	i := 0
	for _, element := range str_ary {
		val, err := strconv.Atoi(element)
		if err != nil {
			panic(err)
		}
		bIp[i] = byte(val)
		i++
	}
	return ByteAryToIPv4(bIp)

}

func NextIP(ip net.IP, inc uint) net.IP {
	i := ip.To4()
	v := uint(i[0])<<24 + uint(i[1])<<16 + uint(i[2])<<8 + uint(i[3])
	v += inc
	v3 := byte(v & 0xFF)
	v2 := byte((v >> 8) & 0xFF)
	v1 := byte((v >> 16) & 0xFF)
	v0 := byte((v >> 24) & 0xFF)
	return net.IPv4(v0, v1, v2, v3)
}

func SwapBytesUint32(x uint32) uint32 {
	return ((x & 0x000000ff) << 24) | ((x & 0x0000ff00) << 8) | ((x & 0x00ff0000) >> 8) | ((x & 0xff000000) >> 24)
}

func Ip2int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

func Int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}

func PrintMAC(prompt string, mac [common.EtherAddrLen]uint8) {
	str_map := fmt.Sprintf("%s: %02x:%02x:%02x:%02x:%02x:%02x", prompt, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
	LogInfo(Info, str_map)
}

func ByteAryToIPv4(ipB [4]byte) uint32 {
	return uint32(ipB[3])<<24 | uint32(ipB[2])<<16 | uint32(ipB[1])<<8 | uint32(ipB[0])
}

// CheckFatal is an error handling function
func CheckFatal(err error) {
	if err != nil {
		fmt.Printf("checkfail: %+v\n", err)
		os.Exit(1)
	}
}
