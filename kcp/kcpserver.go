package kcp

import (
	"crypto/sha1"
	"log"
	"time"
	"net"	

	"github.com/golang/snappy"
	"github.com/net-byte/vtun/common/cache"
	"github.com/net-byte/vtun/common/cipher"
	"github.com/net-byte/vtun/common/config"
	"github.com/net-byte/vtun/common/counter"
	"github.com/net-byte/vtun/common/netutil"
	"github.com/net-byte/water"
	"github.com/xtaci/kcp-go"
	"golang.org/x/crypto/pbkdf2"
)

func StartServer(iface *water.Interface, config config.Config) {
	log.Printf("vtun kcp server started on %v", config.LocalAddr)
	key := pbkdf2.Key([]byte(config.Key), []byte("default_salt"), 1024, 32, sha1.New)
	block, err := kcp.NewAESBlockCrypt(key)
	if err != nil {
		netutil.PrintErr(err, config.Verbose)
		return
	}

	udpaddr, err := net.ResolveUDPAddr("udp", config.LocalAddr)
	if err != nil {
		netutil.PrintErr(err, config.Verbose)
		return
	}
	if udpaddr.IP.To4() == nil { // ipv6
		conn, err := net.ListenUDP("udp", udpaddr)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			return
		}

		listener, err := kcp.ServeConn(block, 10, 3, conn)
		if err == nil {			
			log.Printf("StartServer, LocalAddr: %+v,  RemoteAddr: %+v", config.LocalAddr, config.ServerAddr)
			go toHeartbeat(conn, config) // 定时心跳，为了打通防火墙
			go toClient(iface, config)
			for {
				session, err := listener.AcceptKCP()
				if err != nil {
					netutil.PrintErr(err, config.Verbose)
					continue
				}
				go toServer(iface, session, config)
			}
		} else {
			log.Fatal(err)
		}
		return
	}	

	if listener, err := kcp.ListenWithOptions(config.LocalAddr, block, 10, 3); err == nil {
		go toClient(iface, config)
		for {
			session, err := listener.AcceptKCP()
			if err != nil {
				netutil.PrintErr(err, config.Verbose)
				continue
			}
			go toServer(iface, session, config)
		}
	} else {
		log.Fatal(err)
	}
}

func toServer(iface *water.Interface, session *kcp.UDPSession, config config.Config) {
	packet := make([]byte, config.BufferSize)
	shb := make([]byte, 2)
	defer session.Close()
	for {
		n, err := session.Read(shb)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			break
		}
		if n < 2 {
			break
		}
		shn := 0
		shn = ((shn & 0x00) | int(shb[0])) << 8
		shn = shn | int(shb[1])
		splitSize := 99
		var count = 0
		if shn < splitSize {
			n, err = session.Read(packet[:shn])
			if err != nil {
				netutil.PrintErr(err, config.Verbose)
				break
			}
			count = n
		} else {
			for count < shn {
				receiveSize := splitSize
				if shn-count < splitSize {
					receiveSize = shn - count
				}
				n, err = session.Read(packet[count : count+receiveSize])
				if err != nil {
					netutil.PrintErr(err, config.Verbose)
					break
				}
				count += n
			}
		}
		b := packet[:shn]
		if config.Compress {
			b, err = snappy.Decode(nil, b)
			if err != nil {
				netutil.PrintErr(err, config.Verbose)
				break
			}
		}
		if config.Obfs {
			b = cipher.XOR(b)
		}
		if key := netutil.GetSrcKey(b); key != "" {
			cache.GetCache().Set(key, session, 24*time.Hour)
			n, err = iface.Write(b)
			if err != nil {
				netutil.PrintErr(err, config.Verbose)
				break
			}
			counter.IncrReadBytes(n)
		}
	}
}

func toClient(iface *water.Interface, config config.Config) {
	packet := make([]byte, config.BufferSize)
	shb := make([]byte, 2)
	for {
		shn, err := iface.Read(packet)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			continue
		}
		shb[0] = byte(shn >> 8 & 0xff)
		shb[1] = byte(shn & 0xff)
		b := packet[:shn]
		if key := netutil.GetDstKey(b); key != "" {
			if v, ok := cache.GetCache().Get(key); ok {
				if config.Obfs {
					b = cipher.XOR(b)
				}
				if config.Compress {
					b = snappy.Encode(nil, b)
				}
				copy(packet[len(shb):len(shb)+len(b)], b)
				copy(packet[:len(shb)], shb)
				session := v.(*kcp.UDPSession)
				n, err := session.Write(packet[:len(shb)+len(b)])
				if err != nil {
					cache.GetCache().Delete(key)
					netutil.PrintErr(err, config.Verbose)
					continue
				}
				counter.IncrWrittenBytes(n)
			}
		}
	}
}


func toHeartbeat(conn *net.UDPConn, config config.Config) {
	serverAddr, err := net.ResolveUDPAddr("udp", config.ServerAddr)
	if err != nil {
		log.Fatalln("failed to resolve server addr:", err)
	}
	
	b := make([]byte, 1)
	for range time.NewTicker(5 * time.Second).C {
		log.Printf("toHeartbeat: RemoteAddr: %+v", config.ServerAddr)
		_, err := conn.WriteToUDP(b, serverAddr)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
		}
	}
}
