package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var (
	appVersion = "dev"
	buildTime  = "unknown"
	gitCommit  = "unknown"
)

type Rule struct {
	localCidr       *net.IPNet
	remoteCidr      *net.IPNet
	localPortRange  [2]uint16
	remotePortRange [2]uint16
	Reject          bool
}

type RulesType []Rule

type Config struct {
	TTL     uint
	Mode    uint // 0: trigger on SYN, 1: trigger on SYN+ACK
	Enabled bool
	Rules   RulesType
	Device  string
}

func (rules *RulesType) String() string {
	return "rules"
}

func (rules *RulesType) Set(value string) error {
	// "localCidr,localPortRange,remotePortRange,Reject"
	// 0.0.0.0/0,0-65535,0-65535,0

	var localPortRange [2]uint16
	var remotePortRange [2]uint16
	var reject bool

	slice := strings.Split(value, ",")
	if len(slice) != 5 {
		return fmt.Errorf("invalid rule: %s", value)
	}
	_, localCidr, err := net.ParseCIDR(slice[0])
	if err != nil {
		return err
	}
	_, remoteCidr, err := net.ParseCIDR(slice[2])
	if err != nil {
		return err
	}
	if _, err = fmt.Sscanf(slice[1], "%d-%d", &localPortRange[0], &localPortRange[1]); err != nil {
		return err
	}
	if _, err = fmt.Sscanf(slice[3], "%d-%d", &remotePortRange[0], &remotePortRange[1]); err != nil {
		return err
	}
	if localPortRange[0] > localPortRange[1] || remotePortRange[0] > remotePortRange[1] {
		return fmt.Errorf("invalid port range: %s", value)
	}
	switch slice[4] {
	case "accept":
		reject = false
	case "reject":
		reject = true
	default:
		return fmt.Errorf("invalid reject value: %s", slice[4])
	}

	*rules = append(*rules, Rule{
		localCidr:       localCidr,
		remoteCidr:      remoteCidr,
		localPortRange:  localPortRange,
		remotePortRange: remotePortRange,
		Reject:          reject,
	})
	return nil
}

func main() {
	config := Config{
		TTL:     6,
		Mode:    0,
		Enabled: true,
		Rules:   RulesType{},
		Device:  "eth0",
	}
	flag.StringVar(&config.Device, "d", config.Device, "device")
	flag.UintVar(&config.TTL, "ttl", config.TTL, "ttl")
	flag.UintVar(&config.Mode, "m", config.Mode, "mode (0: trigger on SYN, 1: trigger on SYN+ACK)")
	flag.Var(&config.Rules, "r", "rules")
	showVersion := flag.Bool("v", false, "show version")
	flag.Parse()

	if *showVersion {
		fmt.Printf("Version: %s\n", appVersion)
		fmt.Printf("Build time: %s\n", buildTime)
		fmt.Printf("Git commit: %s\n", gitCommit)
		return
	}

	appendRule := func(cidr string) {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Fatalf("failed to parse CIDR: %v", err)
		}
		config.Rules = append(config.Rules, Rule{
			localCidr:       &net.IPNet{IP: net.ParseIP("0.0.0.0"), Mask: net.CIDRMask(0, 32)},
			remoteCidr:      ipNet,
			localPortRange:  [2]uint16{0, 65535},
			remotePortRange: [2]uint16{0, 65535},
			Reject:          true,
		})
	}

	appendRule("162.105.0.0/16")  // PKU
	appendRule("115.27.0.0/16")   // PKU
	appendRule("222.29.0.0/17")   // PKU
	appendRule("222.29.128.0/19") // PKU
	appendRule("202.112.7.0/24")  // PKU
	appendRule("202.112.8.0/24")  // PKU
	appendRule("0.0.0.0/8")       // Software
	appendRule("10.0.0.0/8")      // Private network
	appendRule("127.0.0.0/8")     // Loopback
	appendRule("100.64.0.0/10")   // Carrier-grade NAT
	appendRule("169.254.0.0/16")  // Subnet
	appendRule("172.16.0.0/12")   // Private network
	appendRule("192.0.0.0/24")    // Private network
	appendRule("192.168.0.0/16")  // Private network

	receiver := make(chan []byte)
	sender := make(chan []byte)
	go KokiStart(receiver, sender, config)

	for {
		pkt := <-receiver
		if !config.Enabled {
			continue
		}

		var eth layers.Ethernet
		var ip4 layers.IPv4
		var tcp layers.TCP

		parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &tcp)
		decoded := []gopacket.LayerType{}
		if err := parser.DecodeLayers(pkt, &decoded); err != nil {
			continue
		}

		var localMac net.HardwareAddr
		var remoteMac net.HardwareAddr
		var localIp net.IP
		var remoteIp net.IP
		var localPort layers.TCPPort
		var remotePort layers.TCPPort

		if config.Mode == 0 { // trigger on SYN
			if !(tcp.SYN && !tcp.ACK) {
				continue
			}
			localMac = eth.SrcMAC
			remoteMac = eth.DstMAC
			localIp = ip4.SrcIP
			remoteIp = ip4.DstIP
			localPort = tcp.SrcPort
			remotePort = tcp.DstPort
		} else if config.Mode == 1 { // trigger on SYN+ACK
			if !(tcp.SYN && tcp.ACK) {
				continue
			}
			localMac = eth.DstMAC
			remoteMac = eth.SrcMAC
			localIp = ip4.DstIP
			remoteIp = ip4.SrcIP
			localPort = tcp.DstPort
			remotePort = tcp.SrcPort
		} else {
			log.Fatal("Invalid mode")
		}

		accepted := true
		for _, rule := range config.Rules {
			if rule.localCidr.Contains(localIp) && rule.remoteCidr.Contains(remoteIp) &&
				uint16(localPort) >= rule.localPortRange[0] && uint16(localPort) <= rule.localPortRange[1] &&
				uint16(remotePort) >= rule.remotePortRange[0] && uint16(remotePort) <= rule.remotePortRange[1] {
				if rule.Reject {
					accepted = false
				}
				break
			}
		}

		if !accepted {
			continue
		}

		log.Printf("%s:%d -> %s:%d\n", localIp, localPort, remoteIp, remotePort)

		fakeBody := []byte{
			0x16, 0x03, 0x01, 0x00, 0x5c, 0x01, 0x00, 0x00, 0x58, 0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
			0x00, 0x2f, 0x00, 0x00, 0x00, 0x2b, 0x00, 0x29, 0x00, 0x00, 0x26, 0x70, 0x6b, 0x75, 0x2e, 0x73,
			0x70, 0x65, 0x65, 0x64, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x6f, 0x6f, 0x6b, 0x6c, 0x61, 0x73, 0x65,
			0x72, 0x76, 0x65, 0x72, 0x2e, 0x68, 0x69, 0x61, 0x6f, 0x78, 0x75, 0x69, 0x2e, 0x77, 0x6f, 0x72,
			0x6b,
		}
		fakeTcp := layers.TCP{
			SrcPort: localPort,
			DstPort: remotePort,
			SYN:     false,
			ACK:     true,
			PSH:     true,
			Window:  HostToNetShort(65535),
		}
		fakeIp := layers.IPv4{
			SrcIP:    localIp,
			DstIP:    remoteIp,
			Protocol: layers.IPProtocolTCP,
			Version:  4,
			TTL:      uint8(config.TTL),
		}
		fakeEth := layers.Ethernet{
			SrcMAC:       localMac,
			DstMAC:       remoteMac,
			EthernetType: layers.EthernetTypeIPv4,
		}

		fakeTcp.SetNetworkLayerForChecksum(&fakeIp)
		buffer := gopacket.NewSerializeBuffer()
		options := gopacket.SerializeOptions{
			ComputeChecksums: true,
			FixLengths:       true,
		}

		if err := gopacket.SerializeLayers(buffer, options, &fakeEth, &fakeIp, &fakeTcp, gopacket.Payload(fakeBody)); err != nil {
			log.Fatal(err)
		}

		sender <- buffer.Bytes()
	}
}
