// interface.go で選択したインターフェースを用いて、プロキシサーバ(Squid) とパケットのやり取りを行う
package pkg

import (
	"fmt"
	"log"
	"net"
	"syscall"
)

// #############################
// 定数
// #############################
const SockPort = 1344

// #############################
// 主要な機能
// #############################
// プロキシサーバ(Squid) からの受信は、レイヤ4（TCP/IP）のTCPコネクションを受け取るため、IPv4のTCPソケットを作成する
func createTCPSocket() (int, error) {
	l4SockFD, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		return 0, fmt.Errorf("failed to create tcp socket: %w", err)
	}

	// SO_REUSEADDR：Socket再利用の設定
	// サーバ停止後も即座に同じポートに再バインドできるようにする
	if err := syscall.SetsockoptInt(l4SockFD, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		return 0, fmt.Errorf("failed to rebind the same port: %w", err)
	}

	return l4SockFD, nil
}

// プロキシサーバ(Squid) から転送されたデータがPOSTメソッドの場合、データを抽出する
func StartTCPConnection() error {
	// ユーザが利用可能なインターフェースから、プロキシサーバ(Squid) とパケットのやり取りを行うインターフェースを選択する
	intfData, err := UserSelectInterface()
	if err != nil {
		return fmt.Errorf("failed to process UserSelectInterface function: %w", err)
	}

	// TCPソケットを作成
	l4SockFD, err := createTCPSocket()
	if err != nil {
		return fmt.Errorf("failed to execution for createTCPSocket function: %w", err)
	}
	// リソースリーク防止
	defer syscall.Close(l4SockFD)

	// プロキシサーバ(Squid) からの接続を待ち受けるためのPortとIPアドレスを紐付ける
	sockAddr := syscall.SockaddrInet4{Port: SockPort, Addr: rangeIPaddr(intfData.IntfIPs)}
	if err := syscall.Bind(l4SockFD, &sockAddr); err != nil {
		return fmt.Errorf("failed to assign an ipaddress and port: %w", err)
	}

	// ソケットを接続待機の状態に設定し、プロキシサーバ(Squid) からの接続を待ち受ける
	// syscall.SOMAXCONN：システム側の接続要求キューの最大値
	if err := syscall.Listen(l4SockFD, syscall.SOMAXCONN); err != nil {
		return fmt.Errorf("failed to listen on socket: %w", err)
	}

	// POSTメソッドのデータを抽出する
	for {
		// syscall.ListenでICPAサーバからの接続要求待ちにしているキューを受け入れる
		cliFD, _, err := syscall.Accept(l4SockFD)
		if err != nil {
			log.Println("failed to accept the queue of pending connection requests", err)
			continue
		}

		// ICAPヘッダーを解析し、POSTメソッドの場合、データを抽出する
		go func(fd int) {
			if err := HTTPMessageHandle(fd); err != nil {
				log.Printf("failed to execute HttpMessageHandle: %v", err)
			}
		}(cliFD)
	}
}

// --------------------------------
// ヘルパー関数
// --------------------------------
// SockaddrInet4のAddr の型が「[4]byte」で、intfData.IntfIPs の型が「[]string」型となり型が違う
// そのため、rangeでIPアドレスを取得し、[]string > string > net.IP と型を変換し、copyで[4]byte型にIPアドレスを格納する
func rangeIPaddr(IntfIPs []string) [4]byte {
	var addr [4]byte

	for _, intfip := range IntfIPs {
		if ipaddr := net.ParseIP(intfip).To4(); ipaddr == nil {
			continue
		} else {
			copy(addr[:], ipaddr)
			return addr
		}
	}
	// 有効なIPアドレスがなければ 0.0.0.0 を返す
	return addr
}
