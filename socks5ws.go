// Socks5 Proxy over HTTP/WebSocket (socks5ws)
// 基于ws的内网穿透工具
// Sparkle 20210430
// 0.2

package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	"github.com/bingotang1981/socks5ws/httpsniff"
	"github.com/bingotang1981/socks5ws/tlssniff"
)

type tcp2wsSparkle struct {
	tcpConn  net.Conn
	tcpConn2 net.Conn
	wsConn   *websocket.Conn
	uuid     string
	del      bool
	buf      [][]byte
	t        int64
}

// AddrSpec is used to return the target AddrSpec
// which may be specified as IPv4, IPv6, or a FQDN
type AddrSpec struct {
	FQDN string
	IP   net.IP
	Port int
}

const (
	HEART_BEAT_INTERVAL = 90
	VERSION             = "0.3.0"
	ipv4Address         = uint8(1)
	fqdnAddress         = uint8(3)
	ipv6Address         = uint8(4)
	socks5Version       = uint8(5)
)

var (
	//Only used when in server mode
	serverToken string

	//Only used when in client mode
	ruleMap map[string]string

	connMap map[string]*tcp2wsSparkle = make(map[string]*tcp2wsSparkle)
	// go的map不是线程安全的 读写冲突就会直接exit
	connMapLock *sync.RWMutex = new(sync.RWMutex)
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

func getConn(uuid string) (*tcp2wsSparkle, bool) {
	connMapLock.Lock()
	defer connMapLock.Unlock()
	conn, haskey := connMap[uuid]
	return conn, haskey
}

func setConn(uuid string, conn *tcp2wsSparkle) {
	connMapLock.Lock()
	defer connMapLock.Unlock()
	connMap[uuid] = conn
}

func deleteConn(uuid string) {
	connMapLock.Lock()
	defer connMapLock.Unlock()
	conn, haskey := connMap[uuid]

	if haskey {
		if conn != nil && !conn.del {
			conn.del = true
			if conn.tcpConn != nil {
				conn.tcpConn.Close()
				conn.tcpConn = nil
			}
			if conn.tcpConn2 != nil {
				conn.tcpConn2.Close()
				conn.tcpConn2 = nil
			}
			if conn.wsConn != nil {
				log.Print(uuid, " bye")
				conn.wsConn.WriteMessage(websocket.TextMessage, []byte("tcp2wsSparkleClose"))
				conn.wsConn.Close()
				conn.wsConn = nil
			}
		}
		delete(connMap, uuid)
	}
}

func deleteConnUponCloseMessage(uuid string) {
	connMapLock.Lock()
	defer connMapLock.Unlock()
	conn, haskey := connMap[uuid]

	if haskey {
		if conn != nil && !conn.del {
			conn.del = true

			if conn.tcpConn != nil {
				conn.tcpConn.Close()
				conn.tcpConn = nil
			}
			if conn.tcpConn2 != nil {
				conn.tcpConn2.Close()
				conn.tcpConn2 = nil
			}
			if conn.wsConn != nil {
				log.Print(uuid, " say bye")
				conn.wsConn.Close()
				conn.wsConn = nil
			}
		}

		delete(connMap, uuid)
	}
}

func monitorConnHeartbeat() {
	connMapLock.Lock()
	defer connMapLock.Unlock()

	startTime := time.Now().Unix()
	nowTimeCut := startTime - HEART_BEAT_INTERVAL
	// check ws
	for _, conn := range connMap {
		// 如果超时没有收到消息，才发心跳，避免读写冲突
		if conn.t < nowTimeCut {

			wsConn := conn.wsConn
			if wsConn == nil || wsConn.WriteMessage(websocket.TextMessage, []byte("tcp2wsSparkle")) != nil {
				log.Print(conn.uuid, " tcp timeout close")
				conn.del = true

				if conn.tcpConn != nil {
					conn.tcpConn.Close()
					conn.tcpConn = nil
				}
				if conn.tcpConn2 != nil {
					conn.tcpConn2.Close()
					conn.tcpConn2 = nil
				}
				if conn.wsConn != nil {
					log.Print(conn.uuid, " bye")
					conn.wsConn.WriteMessage(websocket.TextMessage, []byte("tcp2wsSparkleClose"))
					conn.wsConn.Close()
					conn.wsConn = nil
				}
				delete(connMap, conn.uuid)
			}

		}
	}

	endTime := time.Now().Unix()
	log.Print("Active cons: ", len(connMap), " (", endTime-startTime, "s)")
}

//dial a new tcp, only works in client mode
func dialNewLocalTcpOnClient(uuid string, sbytes []byte) bool {
	log.Print("local dial ", uuid)

	us := strings.Split(uuid, " ")
	if len(us) == 1 {
		log.Print("Invalid uuid: ", uuid)
		return false
	}

	mytcpAddr := us[1]

	tcpConn2, err := net.DialTimeout("tcp", mytcpAddr, 5*time.Second)

	if err != nil {
		log.Print("connect to tcp err: ", err)
		return false
	}

	if len(sbytes) > 0 {
		if _, err = tcpConn2.Write(sbytes); err != nil {
			log.Print(uuid, " tcp write err: ", err)
			tcpConn2.Close()
			return false
		}
	}

	// update
	if conn, haskey := getConn(uuid); haskey {
		if conn.tcpConn2 != nil {
			conn.tcpConn2.Close()
		}
		conn.tcpConn2 = tcpConn2
		conn.t = time.Now().Unix()
	}
	return true
}

//This method dial a new websocket on client
func dialNewWsOnClient(uuid string, wsAddr string, token string, sbytes []byte) bool {
	log.Print("dial ", uuid)
	// call ws
	dialer := websocket.Dialer{TLSClientConfig: &tls.Config{RootCAs: nil, InsecureSkipVerify: true}, Proxy: http.ProxyFromEnvironment, NetDial: meDial}

	// Define custom headers for the connection
	headers := http.Header{
		"Authorization": []string{("Bearer " + token)},
	}

	wsConn, _, err := dialer.Dial(wsAddr, headers)
	if err != nil {
		log.Print("connect to ws err: ", err)
		return false
	}
	// send uuid
	if err := wsConn.WriteMessage(websocket.TextMessage, []byte(uuid)); err != nil {
		log.Print("udp send ws uuid err: ", err)
		wsConn.Close()
		return false
	}

	if len(sbytes) > 0 {
		if err := wsConn.WriteMessage(websocket.BinaryMessage, sbytes); err != nil {
			log.Print("send ws sbytes err: ", err)
			wsConn.Close()
			return false
		}
	}

	// update
	if conn, haskey := getConn(uuid); haskey {
		if conn.wsConn != nil {
			conn.wsConn.Close()
		}
		conn.wsConn = wsConn
		conn.t = time.Now().Unix()
		// writeErrorBuf2Ws(conn)
	}
	return true
}

//Server side: read Tcp to Ws connection
//If Tcp errors are encountered, close the work
//If Ws connection errors are met, wait for 10 seconds for the reovery of the ws connection
func readTcp2WsOnServer(uuid string) {
	defer func() {
		err := recover()
		if err != nil {
			log.Print(uuid, " server tcp -> ws Boom!\n", err)
		}
	}()

	//buffer as 32K
	buf := make([]byte, 32768)

	for {

		conn, haskey := getConn(uuid)
		if !haskey {
			return
		}

		tcpConn := conn.tcpConn

		if conn.del || tcpConn == nil {
			return
		}
		var length int
		var err error

		length, err = tcpConn.Read(buf)

		if err != nil {
			if conn, haskey := getConn(uuid); haskey && !conn.del {
				// tcp中断 关闭所有连接 关过的就不用关了
				if err.Error() != "EOF" {

					log.Print(uuid, " tcp read err: ", err)

				}
				deleteConn(uuid)
				return
			}
			return
		}

		// log.Print(uuid, " ws send: ", length)
		if length > 0 {
			// 因为tcpConn.Read会阻塞 所以要从connMap中获取最新的wsConn
			conn, haskey := getConn(uuid)
			if !haskey || conn.del {
				return
			}
			wsConn := conn.wsConn
			conn.t = time.Now().Unix()

			if wsConn == nil {
				rec := false

				//Wait for 10 seconds for the ws connection recovery
				for i := 0; i < 10; i++ {
					time.Sleep(1 * time.Second)
					conn, haskey = getConn(uuid)
					if !haskey || conn.del {
						return
					}

					wsConn = conn.wsConn
					conn.t = time.Now().Unix()

					if wsConn != nil {
						rec = true
						break
					}
				}

				if !rec {
					log.Print(uuid, " fail to get the reconnected ws ")
					deleteConn(uuid)
				}
			}

			//Wait for 10 seconds for the ws connection recovery
			suc := false
			for i := 0; i < 10; i++ {
				if wsConn == nil {
					break
				}

				if err = wsConn.WriteMessage(websocket.BinaryMessage, buf[:length]); err != nil {
					log.Print(uuid, " ws write err: ", err)
					// tcpConn.Close()
					wsConn.Close()

					time.Sleep(1 * time.Second)

					conn, haskey := getConn(uuid)
					if !haskey || conn.del {
						return
					}

					wsConn = conn.wsConn
					conn.t = time.Now().Unix()

				} else {
					suc = true
					break
				}
			}

			if !suc {
				log.Print(uuid, " fail to get the reconnected ws ")
				deleteConn(uuid)
			}
		}
	}
}

//Client Side: read tcp to ws connection
//If Tcp error, close the work
//If ws connection error, wait 10 seconds for the ws connection recovery
func readTcp2WsOnClient(uuid string) {
	defer func() {
		err := recover()
		if err != nil {
			log.Print(uuid, " tcp -> ws Boom!\n", err)
			// readTcp2Ws(uuid)
		}
	}()

	//Buffer 32K
	buf := make([]byte, 32768)

	for {
		conn, haskey := getConn(uuid)
		if !haskey {
			return
		}
		tcpConn := conn.tcpConn

		if conn.del || tcpConn == nil {
			return
		}
		var length int
		var err error

		length, err = tcpConn.Read(buf)

		if err != nil {
			if conn, haskey := getConn(uuid); haskey && !conn.del {
				// tcp中断 关闭所有连接 关过的就不用关了
				if err.Error() != "EOF" {
					log.Print(uuid, " tcp read err: ", err)
				}
				deleteConn(uuid)
				return
			} else {
				return
			}
		}
		// log.Print(uuid, " ws send: ", length)
		if length > 0 {
			// 因为tcpConn.Read会阻塞 所以要从connMap中获取最新的wsConn
			conn, haskey := getConn(uuid)
			if !haskey || conn.del {
				return
			}
			wsConn := conn.wsConn
			conn.t = time.Now().Unix()

			if wsConn == nil {
				rec := false

				//Wait 10 seconds for the ws connection recovery
				for i := 0; i < 10; i++ {
					time.Sleep(1 * time.Second)
					conn, haskey = getConn(uuid)
					if !haskey || conn.del {
						return
					}

					wsConn = conn.wsConn
					conn.t = time.Now().Unix()

					if wsConn != nil {
						rec = true
						break
					}
				}

				if !rec {
					log.Print(uuid, " fail to get the reconnected ws ")
					deleteConn(uuid)
				}
			}

			suc := false
			for i := 0; i < 10; i++ {
				if wsConn == nil {
					break
				}

				//Wait 10 seconds for the ws connection recovery
				if err = wsConn.WriteMessage(websocket.BinaryMessage, buf[:length]); err != nil {
					log.Print(uuid, " ws write err: ", err)
					// tcpConn.Close()
					wsConn.Close()

					time.Sleep(1 * time.Second)

					conn, haskey := getConn(uuid)
					if !haskey || conn.del {
						return
					}

					wsConn = conn.wsConn
					conn.t = time.Now().Unix()

				} else {
					suc = true
					break
				}
			}

			if !suc {
				log.Print(uuid, " fail to get the reconnected ws ")
				deleteConn(uuid)
			}
		}
	}
}

//This method forwards the tcp request to the local tcp channel
func readTcpRequest2TcpOnClient(uuid string) bool {
	defer func() {
		err := recover()
		if err != nil {
			log.Print(uuid, " tcp request -> tcp Boom!\n", err)
		}
	}()

	conn, haskey := getConn(uuid)
	if !haskey {
		return false
	}
	buf := make([]byte, 500000)
	tcpConn := conn.tcpConn
	for {
		if conn.del || tcpConn == nil {
			return false
		}
		var length int
		var err error

		length, err = tcpConn.Read(buf)

		if err != nil {
			if conn, haskey := getConn(uuid); haskey && !conn.del {
				// tcp中断 关闭所有连接 关过的就不用关了
				if err.Error() != "EOF" {
					log.Print(uuid, " tcp request read err: ", err)
				}
				deleteConn(uuid)
				return false
			}
			return false
		}
		// log.Print(uuid, " ws send: ", length)
		if length > 0 {
			// 因为tcpConn.Read会阻塞 所以要从connMap中获取最新的wsConn
			conn, haskey := getConn(uuid)
			if !haskey || conn.del {
				return false
			}

			tcpConn2 := conn.tcpConn2
			conn.t = time.Now().Unix()
			if tcpConn2 == nil {
				return false
			}

			if _, err = tcpConn2.Write(buf[:length]); err != nil {
				log.Print(uuid, " tcp request write err: ", err)
				tcpConn2.Close()
				conn.tcpConn2 = nil
			}
		}
	}
}

//This method forwards the tcp reply from the local channel to the request tcp
func readTcpReply2TcpOnClient(uuid string) bool {
	defer func() {
		err := recover()
		if err != nil {
			log.Print(uuid, " tcp reply -> tcp Boom!\n", err)
		}
	}()

	conn, haskey := getConn(uuid)
	if !haskey {
		return false
	}
	buf := make([]byte, 500000)
	tcpConn2 := conn.tcpConn2
	for {
		if conn.del || tcpConn2 == nil {
			return false
		}
		var length int
		var err error

		length, err = tcpConn2.Read(buf)

		if err != nil {
			if conn, haskey := getConn(uuid); haskey && !conn.del {
				// tcp中断 关闭所有连接 关过的就不用关了
				if err.Error() != "EOF" {
					log.Print(uuid, " tcp reply read err: ", err)
				}
				deleteConn(uuid)
				return false
			}
			return false
		}
		// log.Print(uuid, " ws send: ", length)
		if length > 0 {
			// 因为tcpConn.Read会阻塞 所以要从connMap中获取最新的wsConn
			conn, haskey := getConn(uuid)
			if !haskey || conn.del {
				return false
			}

			tcpConn := conn.tcpConn
			conn.t = time.Now().Unix()
			if tcpConn == nil {
				return false
			}

			if _, err = tcpConn.Write(buf[:length]); err != nil {
				log.Print(uuid, " tcp reply write err: ", err)
				tcpConn.Close()
				conn.tcpConn = nil
			}
		}
	}
}

//Client side: read the ws connection to the tcp
//If Tcp errors, close the work
//If ws connection error, make a ws reconnection. If successful, continue, otherwise, close the work
func readWs2TcpOnClient(uuid string, wsAddr string, token string, sbytes []byte) {
	defer func() {
		err := recover()
		if err != nil {
			log.Print(uuid, " client ws -> tcp Boom!\n", err)
		}
	}()

	conn, haskey := getConn(uuid)
	if !haskey {
		return
	}
	wsConn := conn.wsConn
	tcpConn := conn.tcpConn

	for {
		if conn.del || tcpConn == nil || wsConn == nil {
			return
		}

		t, buf, err := wsConn.ReadMessage()
		if err != nil || t == -1 {
			wsConn.Close()

			if conn, haskey := getConn(uuid); haskey && !conn.del {
				// 外部干涉导致中断 重连ws
				log.Print(uuid, " client ws read err: ", err)
				log.Print(uuid, " try to make a reconnection to ws")
				//reconnect to ws
				if dialNewWsOnClient(uuid, wsAddr, token, nil) {
					//update the relevant handler after a successful reconnection
					conn, haskey = getConn(uuid)
					if !haskey {
						return
					}
					wsConn = conn.wsConn
					tcpConn = conn.tcpConn
				} else {
					log.Print(uuid, " fail to reconnect to ws")
					deleteConn(uuid)
					return
				}
			}
		}

		// log.Print(uuid, " ws recv: ", len(buf))
		if len(buf) > 0 {
			conn.t = time.Now().Unix()
			if t == websocket.TextMessage {
				msg := string(buf)
				if msg == "tcp2wsSparkle" {
					log.Print(uuid, " heartbeat")
					continue
				} else if msg == "tcp2wsSparkleClose" {
					deleteConnUponCloseMessage(uuid)
					return
				} else {
					log.Print(uuid, " unknown text message: "+msg)
					continue
				}
			}

			if _, err = tcpConn.Write(buf); err != nil {
				log.Print(uuid, " tcp write err: ", err)
				deleteConn(uuid)
				return
			}
		}
	}
}

//Servier Side: read the ws connection to the Tcp
//If Tcp errors, close the work
//If the ws conneciton error, close the work and if the ws connection recovery is
//initialized from the client, a new thread will be created.
func readWs2TcpOnServer(uuid string) {
	defer func() {
		err := recover()
		if err != nil {
			log.Print(uuid, " server ws -> tcp Boom!\n", err)
		}
	}()

	conn, haskey := getConn(uuid)
	if !haskey {
		return
	}
	wsConn := conn.wsConn
	tcpConn := conn.tcpConn

	for {
		if conn.del || tcpConn == nil || wsConn == nil {
			return
		}
		t, buf, err := wsConn.ReadMessage()

		//If fail to read the ws message, return directly so that the thread is closed
		//and then the client will try to do the reconnection.
		if err != nil || t == -1 {
			// log.Print(uuid, " fail to read the ws ", err)
			wsConn.Close()
			return
		}

		// log.Print(uuid, " ws recv: ", len(buf))
		if len(buf) > 0 {
			conn.t = time.Now().Unix()
			if t == websocket.TextMessage {
				msg := string(buf)
				if msg == "tcp2wsSparkle" {
					log.Print(uuid, " heartbeat")
					continue
				} else if msg == "tcp2wsSparkleClose" {
					deleteConnUponCloseMessage(uuid)
					return
				} else {
					log.Print(uuid, " unknown text message: "+msg)
					continue
				}
			}

			if _, err = tcpConn.Write(buf); err != nil {
				log.Print(uuid, " tcp write err: ", err)
				deleteConn(uuid)
				return
			}

		}
	}
}

func meDial(network, address string) (net.Conn, error) {
	return net.DialTimeout(network, address, 5*time.Second)
}

// 服务端 tcp连接是客户端发过来的
func runServer(wsConn *websocket.Conn) {
	defer func() {
		err := recover()
		if err != nil {
			log.Print("server Boom!\n", err)
		}
	}()

	var tcpConn net.Conn
	var uuid string
	// read uuid to get from connMap
	t, buf, err := wsConn.ReadMessage()
	if err != nil || t == -1 || len(buf) == 0 {
		log.Print("ws uuid read err: ", err)
		wsConn.Close()
		return
	}
	if t == websocket.TextMessage {
		uuid = string(buf)
		if uuid == "" {
			log.Print("ws uuid read empty")
			return
		}
		if conn, haskey := getConn(uuid); haskey {
			// get
			tcpConn = conn.tcpConn
			conn.wsConn.Close()
			conn.wsConn = wsConn
		}
	}

	conn, haskey := getConn(uuid)

	if !haskey {
		// call new tcp
		log.Print("new tcp for ", uuid)
		us := strings.Split(uuid, " ")
		if len(us) == 1 {
			log.Print("Invalid uuid: ", uuid)
			return
		}

		//Extract TCP Addr from uuid
		mytcpAddr := us[1]

		tcpConn, err = net.DialTimeout("tcp", mytcpAddr, 5*time.Second)
		if err != nil {
			log.Print("connect to tcp err: ", err)
			wsConn.WriteMessage(websocket.TextMessage, []byte("tcp2wsSparkleClose"))
			wsConn.Close()
			return
		}

		// save
		setConn(uuid, &tcp2wsSparkle{tcpConn, nil, wsConn, uuid, false, nil, time.Now().Unix()})

		go readTcp2WsOnServer(uuid)
	} else {
		log.Print("uuid found ", uuid)

		//update the wsConn with the new one
		conn.wsConn = wsConn
	}

	go readWs2TcpOnServer(uuid)
}

// tcp客户端
func runClient(tcpConn net.Conn, uuid string, wsAddr string, token string, enableSniff bool, enableFilter bool) {
	defer func() {
		err := recover()
		if err != nil {
			log.Print("client Boom!\n", err)
		}
	}()

	var sbytes []byte
	ipaddr := ""
	inFilterList := false

	bufConn := bufio.NewReader(tcpConn)

	// Read the version byte
	version := []byte{0}
	if _, err := bufConn.Read(version); err != nil {
		log.Print("[ERR] socks: Failed to get version byte: ", err)
		return
	}

	// Ensure we are compatible
	if version[0] != uint8(5) {
		log.Print("Unsupported SOCKS version: ", version)
		return
	}

	_, err := readMethods(bufConn)
	if err != nil {
		log.Print("[ERR] socks: Failed to get methods: ", err)
		return
	}

	//Send the reply to the methond command from the client
	t, err := sendMethodReply(tcpConn)
	if err != nil {
		log.Print("[ERR] socks: Failed to get methods: ", t, err)
		return
	}

	// Read the version byte
	header := []byte{0, 0, 0}
	if _, err := io.ReadAtLeast(bufConn, header, 3); err != nil {
		log.Print("[ERR] Failed to get command version: ", err)
		return
	}

	// Ensure we are compatible
	if header[0] != uint8(5) {
		log.Print("Unsupported command version: ", header[0])
		return
	}

	//Support Connect command only
	if header[1] != uint8(1) {
		log.Print("Unsupported command: ", header[1])

		//Reply with unsupported command error
		err1 := sendReply(tcpConn, uint8(7), nil)
		if err1 != nil {
			log.Print("SendReply error: ", err1)
		}
		return
	}

	// Read in the destination address
	addrSpec, err := readAddrSpec(bufConn)
	if err != nil {
		log.Print("[ERR] Failed to get the AddrSpec")

		//Reply with unsupported command error
		err1 := sendReply(tcpConn, uint8(8), nil)
		if err1 != nil {
			log.Print("SendReply error: ", err1)
		}
		return
	}

	isip := false
	sniffDomain := ""
	if addrSpec.IP != nil {
		isip = true
		ipaddr = addrSpec.IP.String() + ":" + strconv.Itoa(addrSpec.Port)
	} else {
		ipaddr = addrSpec.FQDN + ":" + strconv.Itoa(addrSpec.Port)
	}

	//Send success reply
	err1 := sendReply(tcpConn, uint8(0), nil)
	if err1 != nil {
		log.Print("SendReply error: ", err1)
		return
	}

	//Sniff for ip only but not domain name
	//in socks5 proxy, it is possible to enforce the remote dns from the client,
	//that's why we only sniff for ip.
	if isip && enableSniff {
		//Try to read some bytes to sniff
		buf := make([]byte, 1024)
		length, err := tcpConn.Read(buf)
		if err != nil {
			log.Print("[ERR] socks: Failed to read the content data: ", err)
			return
		}

		sbytes = buf[0:length]

		//sniff http
		hsniff, err1 := httpsniff.SniffHTTP(sbytes)
		if err1 == nil {
			//sniff http success, get the domain
			sniffDomain = hsniff.Domain()
		} else {
			//sniff tls
			tsniff, err2 := tlssniff.SniffTLS(sbytes)
			if err2 == nil {
				ipa := strings.Split(ipaddr, ":")
				if len(ipa) == 1 {
					log.Print("Fail to find the tls port: ", ipaddr, "->", tsniff.Domain())
				} else {
					//sniff https success, get the domain
					sniffDomain = tsniff.Domain() + ":" + ipa[1]
				}
			} else {
				log.Print("Fail to sniff the host: ", ipaddr)
			}
		}
	}

	// Regarding ip address, iff Sniff is enabled, adjust the host name if filter is not enabled; ajust the host name in
	// the filter list when filter is enabled to reduce the DNS resolution for the hosts not in the fitler lists
	// Regarding the host name, no need to adjust it.
	if isip {
		if sniffDomain != "" {
			if enableFilter {
				if FastMatchDomain(sniffDomain) {
					inFilterList = true
					log.Print("adjust host ", ipaddr, "->", sniffDomain)
					ipaddr = sniffDomain
				}
			} else {
				log.Print("adjust host ", ipaddr, "->", sniffDomain)
				ipaddr = sniffDomain
			}
		}
	} else {
		if enableFilter && FastMatchDomain(ipaddr) {
			inFilterList = true
		}
	}

	uuid += " " + ipaddr

	// save conn
	setConn(uuid, &tcp2wsSparkle{tcpConn, nil, nil, uuid, false, nil, time.Now().Unix()})

	//Support filter
	if enableFilter {
		//If in the fitler list, go through the proxy, or use the local dial
		if inFilterList {
			if dialNewWsOnClient(uuid, wsAddr, token, sbytes) {
				// connect ok
				go readWs2TcpOnClient(uuid, wsAddr, token, sbytes)
				go readTcp2WsOnClient(uuid)

			} else {
				log.Print("reconnect to ws fail")
			}
		} else {
			if dialNewLocalTcpOnClient(uuid, sbytes) {
				go readTcpRequest2TcpOnClient(uuid)
				go readTcpReply2TcpOnClient(uuid)
			} else {
				log.Print(uuid, " fail on local connect")
				deleteConn(uuid)
			}
		}
	} else {
		//If not support filter, go through the proxy
		if dialNewWsOnClient(uuid, wsAddr, token, sbytes) {
			// connect ok
			go readWs2TcpOnClient(uuid, wsAddr, token, sbytes)
			go readTcp2WsOnClient(uuid)
		} else {
			log.Print("reconnect to ws fail")
		}
	}
}

//Send reply to the method command from the client
func sendMethodReply(w io.Writer) (int, error) {
	return w.Write([]byte{uint8(5), uint8(0)})
}

// sendReply is used to send a reply message
func sendReply(w io.Writer, resp uint8, addr *AddrSpec) error {
	// Format the address
	var addrType uint8
	var addrBody []byte
	var addrPort uint16
	switch {
	case addr == nil:
		addrType = ipv4Address
		addrBody = []byte{0, 0, 0, 0}
		addrPort = 0

	case addr.FQDN != "":
		addrType = fqdnAddress
		addrBody = append([]byte{byte(len(addr.FQDN))}, addr.FQDN...)
		addrPort = uint16(addr.Port)

	case addr.IP.To4() != nil:
		addrType = ipv4Address
		addrBody = []byte(addr.IP.To4())
		addrPort = uint16(addr.Port)

	case addr.IP.To16() != nil:
		addrType = ipv6Address
		addrBody = []byte(addr.IP.To16())
		addrPort = uint16(addr.Port)

	default:
		return fmt.Errorf("Failed to format address: %v", addr)
	}

	// Format the message
	msg := make([]byte, 6+len(addrBody))
	msg[0] = socks5Version
	msg[1] = resp
	msg[2] = 0 // Reserved
	msg[3] = addrType
	copy(msg[4:], addrBody)
	msg[4+len(addrBody)] = byte(addrPort >> 8)
	msg[4+len(addrBody)+1] = byte(addrPort & 0xff)

	// Send the message
	_, err := w.Write(msg)
	return err
}

// readMethods is used to read the number of methods
// and proceeding auth methods
func readMethods(r io.Reader) ([]byte, error) {
	header := []byte{0}
	if _, err := r.Read(header); err != nil {
		return nil, err
	}

	numMethods := int(header[0])
	methods := make([]byte, numMethods)
	_, err := io.ReadAtLeast(r, methods, numMethods)
	return methods, err
}

// readAddrSpec is used to read AddrSpec.
// Expects an address type byte, follwed by the address and port
func readAddrSpec(r io.Reader) (*AddrSpec, error) {
	d := &AddrSpec{}

	// Get the address type
	addrType := []byte{0}
	if _, err := r.Read(addrType); err != nil {
		return nil, err
	}

	// Handle on a per type basis
	switch addrType[0] {
	case ipv4Address:
		addr := make([]byte, 4)
		if _, err := io.ReadAtLeast(r, addr, len(addr)); err != nil {
			return nil, err
		}
		d.IP = net.IP(addr)

	case ipv6Address:
		addr := make([]byte, 16)
		if _, err := io.ReadAtLeast(r, addr, len(addr)); err != nil {
			return nil, err
		}
		d.IP = net.IP(addr)

	case fqdnAddress:
		if _, err := r.Read(addrType); err != nil {
			return nil, err
		}
		addrLen := int(addrType[0])
		fqdn := make([]byte, addrLen)
		if _, err := io.ReadAtLeast(r, fqdn, addrLen); err != nil {
			return nil, err
		}
		d.FQDN = string(fqdn)

	default:
		return nil, fmt.Errorf("Unrecognized address type")
	}

	// Read the port
	port := []byte{0, 0}
	if _, err := io.ReadAtLeast(r, port, 2); err != nil {
		return nil, err
	}
	d.Port = (int(port[0]) << 8) | int(port[1])

	return d, nil
}

// 响应ws请求
func wsHandlerServer(w http.ResponseWriter, r *http.Request) {
	forwarded := r.Header.Get("X-Forwarded-For")
	// 不是ws的请求返回index.html 假装是一个静态服务器
	if r.Header.Get("Upgrade") != "websocket" {
		if forwarded == "" {
			log.Print("not ws: ", r.RemoteAddr)
		} else {
			log.Print("not ws: ", forwarded)
		}
		_, err := os.Stat("index.html")
		if err == nil {
			http.ServeFile(w, r, "index.html")
		}
		return
	} else if r.Header.Get("Authorization") != ("Bearer " + serverToken) {
		log.Print("Invalid Authorization: ", r.Header.Get("Authorization"))
		_, err := os.Stat("index.html")
		if err == nil {
			http.ServeFile(w, r, "index.html")
		}
		return
	} else {
		if forwarded == "" {
			log.Print("new ws conn: ", r.RemoteAddr)
		} else {
			log.Print("new ws conn: ", forwarded)
		}
	}

	// ws协议握手
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Print("ws upgrade err: ", err)
		return
	}

	// 新线程hold住这条连接
	go runServer(conn)
}

// 响应tcp
func tcpHandler(listener net.Listener, wsAddr string, token string, enableSniff bool, enableFilter bool) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Print("tcp accept err: ", err)
			return
		}

		// log.Print("new tcp conn: ")

		// 新线程hold住这条连接
		// myuuid := uuid.New().String()[31:] + " " + tcpAddr
		go runClient(conn, uuid.New().String()[31:], wsAddr, token, enableSniff, enableFilter)
	}
}

// 启动ws服务
func startWsServer(listenPort string, isSsl bool, sslCrt string, sslKey string) {
	var err error = nil
	if isSsl {
		fmt.Println("use ssl cert: " + sslCrt + " " + sslKey)
		err = http.ListenAndServeTLS(listenPort, sslCrt, sslKey, nil)
	} else {
		err = http.ListenAndServe(listenPort, nil)
	}
	if err != nil {
		log.Fatal("tcp2ws Server Start Error: ", err)
	}
}

func startServerThread(listenHostPort string, token string, isSsl bool, sslCrt string, sslKey string) {
	serverToken = token
	// ws server
	http.HandleFunc("/", wsHandlerServer)
	go startWsServer(listenHostPort, isSsl, sslCrt, sslKey)
	if isSsl {
		log.Print("Server Started wss://" + listenHostPort)
	} else {
		log.Print("Server Started ws://" + listenHostPort)
	}
	fmt.Println("{\nproxy_read_timeout 3600;\nproxy_http_version 1.1;\nproxy_set_header Upgrade $http_upgrade;\nproxy_set_header Connection \"Upgrade\";\nproxy_set_header X-Forwarded-For $remote_addr;\naccess_log off;\n}")

	for {
		//heartbeat interval is 90 seconds as 100 seconds is the default timeout in cloudflare cdn
		time.Sleep(HEART_BEAT_INTERVAL * time.Second)
		monitorConnHeartbeat()
	}
}

func startClientThread(listenHostPort string, mywsAddr string, token string, enableSniff bool, enableFilter bool) {

	l, err := net.Listen("tcp", listenHostPort)
	if err != nil {
		log.Fatal("tcp2ws Client Start Error: ", err)
	}

	go tcpHandler(l, mywsAddr, token, enableSniff, enableFilter)

	log.Print("Client Started " + listenHostPort + " -> " + mywsAddr)
	log.Print("Enable Sniff: ", enableSniff)
	log.Print("Enable Filter: ", enableFilter)
}

func startClientMonitorThread() {
	for {
		// 按 ctrl + c 退出，会阻塞
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, os.Kill)
		<-c
		fmt.Println()
		log.Print("quit...")
		for k, _ := range connMap {
			deleteConn(k)
		}
		os.Exit(0)
	}
}

//This method parses the filter file
func ParseFilterFile(filename string) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	reader := bufio.NewReader(f)
	ruleMap = make(map[string]string)
	for {
		line, _, err := reader.ReadLine()
		if nil != err {
			break
		}
		str := strings.TrimSpace(string(line))
		if str != "" {
			ruleMap[str] = ""
		}
	}
	return nil
}

//Returns whether it is in the filter map
func FastMatchDomain(domain string) bool {
	if ruleMap == nil {
		return false
	}

	myDomain := domain
	ds := strings.Split(domain, ":")
	if len(ds) > 1 {
		myDomain = ds[0]
	}

	ds = strings.Split(myDomain, ".")

	num := len(ds)
	if num == 1 {
		return false
	} else if num == 2 {
		dm := myDomain
		_, flag := ruleMap[dm]
		return flag
	} else if num == 3 {
		dm := myDomain
		_, flag := ruleMap[dm]
		if flag {
			return true
		} else {
			dm := ds[num-2] + "." + ds[num-1]
			_, flag := ruleMap[dm]
			return flag
		}
	} else {
		dm := ds[num-4] + "." + ds[num-3] + "." + ds[num-2] + "." + ds[num-1]
		_, flag := ruleMap[dm]
		if flag {
			return true
		} else {
			dm := ds[num-3] + "." + ds[num-2] + "." + ds[num-1]
			_, flag := ruleMap[dm]
			if flag {
				return true
			} else {
				dm := ds[num-2] + "." + ds[num-1]
				_, flag := ruleMap[dm]
				return flag
			}
		}
	}
}

func main() {
	fmt.Println("socks5ws version: ", VERSION)

	arg_num := len(os.Args)

	if arg_num < 2 {
		fmt.Println("Socks5 Proxy Over HTTP/Websocket\nhttps://github.com/bingotang1981/socks5ws")
		fmt.Println("Client: client https://tcp2wsUrl localPort yourCustomizedBearerToken\nServer: server tcp2wsPort yourCustomizedBearerToken [s]\nUse wss: ip:port tcp2wsPort server.crt server.key")
		fmt.Println("Make ssl cert:\nopenssl genrsa -out server.key 2048\nopenssl ecparam -genkey -name secp384r1 -out server.key\nopenssl req -new -x509 -sha256 -key server.key -out server.crt -days 36500")
		os.Exit(0)
	}

	isserv := true

	//第一个参数是服务类型：client/server
	stype := os.Args[1]
	if stype == "server" {
		isserv = true
		if arg_num < 4 {
			fmt.Println("Socks5 Proxy Over HTTP/Websocket\nhttps://github.com/bingotang1981/socks5ws")
			fmt.Println("Client: client https://tcp2wsUrl localPort yourCustomizedBearerToken\nServer: server tcp2wsPort yourCustomizedBearerToken [s]\nUse wss: ip:port tcp2wsPort server.crt server.key")
			fmt.Println("Make ssl cert:\nopenssl genrsa -out server.key 2048\nopenssl ecparam -genkey -name secp384r1 -out server.key\nopenssl req -new -x509 -sha256 -key server.key -out server.crt -days 36500")
			os.Exit(0)
		}
	} else if stype == "client" {
		isserv = false
		if arg_num < 5 {
			fmt.Println("Socks5 Proxy Over HTTP/Websocket\nhttps://github.com/bingotang1981/socks5ws")
			fmt.Println("Client: client https://tcp2wsUrl localPort yourCustomizedBearerToken\nServer: server tcp2wsPort yourCustomizedBearerToken [s]\nUse wss: ip:port tcp2wsPort server.crt server.key")
			fmt.Println("Make ssl cert:\nopenssl genrsa -out server.key 2048\nopenssl ecparam -genkey -name secp384r1 -out server.key\nopenssl req -new -x509 -sha256 -key server.key -out server.crt -days 36500")
			os.Exit(0)
		}
	} else {
		fmt.Println("Socks5 Proxy Over HTTP/Websocket\nhttps://github.com/bingotang1981/socks5ws")
		fmt.Println("Client: client https://tcp2wsUrl localPort yourCustomizedBearerToken\nServer: server tcp2wsPort yourCustomizedBearerToken [s]\nUse wss: ip:port tcp2wsPort server.crt server.key")
		fmt.Println("Make ssl cert:\nopenssl genrsa -out server.key 2048\nopenssl ecparam -genkey -name secp384r1 -out server.key\nopenssl req -new -x509 -sha256 -key server.key -out server.crt -days 36500")
		os.Exit(0)
	}

	match := false

	if isserv {
		// 服务端
		listenPort := os.Args[2]
		token := os.Args[3]
		isSsl := false
		if arg_num == 5 {
			isSsl = os.Args[4] == "wss" || os.Args[4] == "https" || os.Args[4] == "ssl"
		}
		sslCrt := "server.crt"
		sslKey := "server.key"
		if arg_num == 6 {
			isSsl = true
			sslCrt = os.Args[4]
			sslKey = os.Args[5]
		}

		match, _ = regexp.MatchString(`^\d+$`, listenPort)
		listenHostPort := listenPort
		if match {
			// 如果没指定监听ip那就全部监听 省掉不必要的防火墙
			listenHostPort = "0.0.0.0:" + listenPort
		}

		startServerThread(listenHostPort, token, isSsl, sslCrt, sslKey)

	} else {

		serverUrl := os.Args[2]
		listenPort := os.Args[3]
		token := os.Args[4]
		eSniff := false
		eFilter := false

		if arg_num > 5 {
			if os.Args[5] == "s" {
				eSniff = true
			}
		}

		if arg_num > 6 {
			filename := os.Args[6]
			err := ParseFilterFile(filename)
			if err == nil {
				eFilter = true
			}
		}
		wsAddr := serverUrl

		if serverUrl[:5] == "https" {
			wsAddr = "wss" + serverUrl[5:]
		} else if serverUrl[:4] == "http" {
			wsAddr = "ws" + serverUrl[4:]
		}

		match, _ = regexp.MatchString(`^\d+$`, listenPort)
		listenHostPort := listenPort
		if match {
			// 如果没指定监听ip那就全部监听 省掉不必要的防火墙
			listenHostPort = "0.0.0.0:" + listenPort
		}
		startClientThread(listenHostPort, wsAddr, token, eSniff, eFilter)

		//Listen to Ctrl+C event
		startClientMonitorThread()
	}
}
