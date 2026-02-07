// ICAPサーバと接続できるインターフェースを選択する
package pkg

import (
	"bufio"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// #############################
// 構造体
// #############################
// 通信に利用するインターフェースを定義する
type InterfaceData struct {
	IntfName string   // インターフェース名
	IntfIPs  []string // IPアドレス
}

// #############################
// 主要な機能
// #############################
// ユーザが利用可能なインターフェースを選択する
func UserSelectInterface() (InterfaceData, error) {
	var selIntf InterfaceData

	// 利用可能なインターフェースの一覧を取得する
	availableIntfs, err := getAvailableInterfaces()
	if err != nil {
		return InterfaceData{}, fmt.Errorf("failed to process the getAvailableInterfaces function: %w", err)
	}

	fmt.Print("\033c") // CLI画面をクリアにする
	fmt.Println()
	fmt.Println(" リスト番号を入力してください")

	// TLS接続で暗号化パケットを宛先に送る際に、利用するインターフェースを選択する
	// 取得してきた利用可能なインターフェースをリスト番号で選択させる
	for {
		fmt.Println("--------------------------------")
		fmt.Print(" # 利用するインターフェースを選択してください\n\n")
		for index, availableIntf := range availableIntfs {
			joinIP := strings.Join(availableIntf.IntfIPs, ", ")
			fmt.Printf(" [%2d] %-9s: %s\n", index+1, availableIntf.IntfName, joinIP)
		}
		fmt.Println("--------------------------------")
		fmt.Print(" リスト番号: ")

		inputNumber, err := askForInput()
		if err != nil {
			return InterfaceData{}, fmt.Errorf("failed to process the askForInput function: %w", err)
		}

		// 入力値が無効な場合は、再度入力を実施させる
		// 入力値(リスト番号) の先頭と末尾の空白があれば取り除き、文字列から数値に型変換する
		// 入力値がインターフェース一覧の件数より多いか少ないかを検証する
		number, err := strconv.Atoi(strings.TrimSpace(inputNumber))
		if err != nil || number < 1 || number > len(availableIntfs) {
			fmt.Print("\033c") // CLI画面をクリアにする
			fmt.Println()
			fmt.Println(" 入力した値は無効な値です")
			fmt.Println(" リスト番号にある番号を入力してください")
			continue
		}
		fmt.Println()

		// 有効なリスト番号が選択された場合、インターフェース名とIPv4アドレスの情報を保持する
		selIntf = availableIntfs[number-1]

		return selIntf, nil
	}
}

// 利用可能なインターフェースに割り当てられたインターフェース名とIPv4アドレスを抽出する
func getAvailableInterfaces() ([]InterfaceData, error) {
	var availableIntfs []InterfaceData

	// 自身の全ネットワークインターフェース情報を取得する
	intfs, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve network interfaces :%w", err)
	}

	for _, intf := range intfs {
		// ループ事に新しいバッファを確保し、データ競合が発生しないようにする
		// 利用可能なインターフェースに割り当てられたIPv4アドレスを格納する
		var ipAddrs []string

		// 実際に通信が可能なインターフェースのみを対象とする
		// 無効(down) およびループバック(127.0.0.1など) を除外する
		if intf.Flags&net.FlagUp == 0 || intf.Flags&net.FlagLoopback != 0 {
			continue
		}

		// インターフェースに割り当てられたIPアドレス(IPv4/IPv6)を取得する
		// IPアドレス(IPv4/IPv6)が、1つでも割り当てられていない場合、無効なインターフェースとみなし処理をスキップする
		addrs, err := intf.Addrs()
		if err != nil {
			continue
		}

		// インターフェースに割り当てられたIPv4アドレスのみを抽出する
		// CIDR形式の解析に失敗した場合やIPv6アドレスの場合、
		// 該当IPアドレスの処理をスキップし、次のIPアドレスの解析に進む
		for _, addr := range addrs {
			parsePrefix, err := netip.ParsePrefix(addr.String())
			if err != nil || !parsePrefix.Addr().Is4() {
				continue
			}
			ipAddrs = append(ipAddrs, parsePrefix.Addr().String())
		}

		// IPv4アドレスが0個の場合、該当のインターフェースの処理をスキップする
		if len(ipAddrs) == 0 {
			continue
		}

		// インターフェース名とIPv4アドレスを構造体にまとめて追加する
		availableIntfs = append(availableIntfs, InterfaceData{
			IntfName: intf.Name,
			IntfIPs:  ipAddrs,
		})
	}
	return availableIntfs, nil
}

// --------------------------------
// ヘルパー関数
// --------------------------------
// 入力を要求する
func askForInput() (string, error) {
	scanner := bufio.NewScanner(os.Stdin)

	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return "", fmt.Errorf("input interrupted")
		}
	}
	return scanner.Text(), nil
}
