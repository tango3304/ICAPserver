// プロキシサーバ(Squid) から転送されたパケットを解析し、POSTメソッドの場合は、データの抽出を行う
package pkg

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// プロキシサーバ (Squid) から転送されたTCPソケットを解析する
func HTTPMessageHandle(cliFD int) error {
	// 接続要求を受け入れたキューを開放する
	defer syscall.Close(cliFD)

	var recvBuf []byte
	hdrDelimiter := []byte("\r\n\r\n")
	contentLength := 0
	encapsulatedOffsets := map[string]int{}

	// 受信したTCPソケットを解析し、OPTIONS応答またはペイロードを抽出する
	for {
		// プロキシサーバ(Squid) から転送れた連続したTCPデータを4K(4096 byte)単位で読み込む
		recvBufSize := make([]byte, 4096)
		numRead, err := syscall.Read(cliFD, recvBufSize)
		if err != nil {
			return fmt.Errorf("failed to read tcp data: %w", err)
		}

		// クライアントからの切断検知を判定する (連続したTCPデータにおける「EOF」や切断)
		if numRead == 0 {
			break
		}

		// 読み取った分のTCPデータを格納する
		recvBuf = append(recvBuf, recvBufSize[:numRead]...)

		// OPTIONSメソッドの処理
		// ICAPサーバ機能の確認で転送されたカプセル化されていないOPTIONSメソッドの場合、200 ステータスコードを送信する
		icapHdrEnd := bytes.Index(recvBuf, hdrDelimiter)
		if bytes.HasPrefix(bytes.ToUpper(recvBuf[:icapHdrEnd]), []byte("OPTIONS ")) {
			return sendHTTPCode200(cliFD)
		}

		//HTTPヘッダーの始点位置と終端位置を取得する
		httpHdrStart := icapHdrEnd + len(hdrDelimiter)
		httpHdrEnd := bytes.Index(recvBuf[httpHdrStart:], []byte("\r\n\r\n"))
		if httpHdrEnd == -1 {
			continue
		}
		httpHdrEnd += httpHdrStart

		// 抽出したICAPヘッダーを解析し、Encapsulatedヘッダーの「req-hdr、null-body、req-body」を抽出する
		icapHdr := recvBuf[:icapHdrEnd]
		for _, icapHdrLine := range bytes.Split(icapHdr, []byte("\r\n")) {
			if bytes.HasPrefix(bytes.ToLower(icapHdrLine), []byte("encapsulated: ")) {
				encapsulateds := bytes.TrimSpace(icapHdrLine[len("Encapsulated:"):])
				for _, encapsulated := range bytes.Split(encapsulateds, []byte(",")) {
					encapsulatedPairs := bytes.SplitN(bytes.TrimSpace(encapsulated), []byte("="), 2)
					length, _ := strconv.Atoi(strings.TrimSpace(string(encapsulatedPairs[1])))
					encapsulatedOffsets[strings.TrimSpace(string(encapsulatedPairs[0]))] = length
				}
			}
		}

		// 「null-body」がある場合、ペイロードがないので、204 ステータスコードを送信する
		_, hasNullBody := encapsulatedOffsets["null-body"]
		if hasNullBody {
			return sendHTTPCode204(cliFD)
		}

		// HTTPヘッダーの「Content-Length」を抽出する
		for _, httpHdrLine := range bytes.Split(recvBuf[httpHdrStart:httpHdrEnd], []byte("\r\n")) {
			if bytes.HasPrefix(bytes.ToLower(httpHdrLine), []byte("content-length: ")) {
				length, _ := strconv.Atoi(strings.TrimSpace(string(httpHdrLine[len("Content-Length:"):])))
				contentLength = length
			}
		}

		// スライスの範囲チェック
		if httpHdrEnd+len("\r\n\r\n")+contentLength > len(recvBuf) {
			continue
		}

		// ICAPサーバから転送されてきた「req-hdr」を抽出し、「req-hdr」があるか確認する
		_, hasHdr := encapsulatedOffsets["req-hdr"]
		if !hasHdr {
			return fmt.Errorf("req-hdr not found in encapsulated header")
		}

		// スライスの範囲チェック
		// ペイロードのチャンクの開始と終了の位置を検索し、チャンクを除いたペイロードを抽出する
		reqBodyLen, hasReqBody := encapsulatedOffsets["req-body"]
		payload := recvBuf[httpHdrStart+reqBodyLen:]

		// OPTIONSメソッド、GETメソッド、POSTメソッドの処理
		// ケース1：noll-body かつ POSTメソッドの場合、ペイロードが格納されていないため、204 ステータスコードを送信する
		// ケース2：req-body かつ POSTメソッドの場合、ペイロードを抽出してから、204 ステータスコードを送信する
		// ケース3：それ以外のメソッド（OPTIONS、GET、PUT、PATCH、HEAD）の場合、204 ステータスコードを送信する
		hasPost := bytes.HasPrefix(bytes.ToUpper(recvBuf[icapHdrEnd+len(hdrDelimiter):]), []byte("POST "))
		switch {
		case hasReqBody && hasPost:
			extractPostPayload(httpHdrStart, payload, recvBuf)
			return sendHTTPCode204(cliFD)
		default:
			return sendHTTPCode204(cliFD)
		}
	}
	return nil
}

// ICAPメッセージを解析し、POSTメソッドのペイロードを抽出する
func extractPostPayload(httpHdrStart int, payload, recvBuf []byte) error {
	// ペイロードのチャンクの開始と終了の位置を検索する
	noChunkStart := bytes.Index(payload, []byte("\r\n"))
	noChunkEnd := bytes.Index(payload, []byte("0\r\n\r\n"))
	if noChunkEnd == -1 {
		return nil
	}

	// content-Type と Referer を抽出する
	contentType := ""
	targetURL := ""
	for _, httpHdrLine := range bytes.Split(recvBuf[httpHdrStart:], []byte("\r\n")) {
		if bytes.HasPrefix(bytes.ToLower(httpHdrLine), []byte("content-type: ")) {
			contentType = string(bytes.TrimSpace(httpHdrLine[len("Content-Type:"):]))
		}
		if bytes.HasPrefix(bytes.ToLower(httpHdrLine), []byte("referer: ")) {
			targetURL = string(bytes.TrimSpace(httpHdrLine[len("Referer:"):]))
		}
	}
	if targetURL == "" {
		return nil
	}

	// URL および Key 判定
	hasURL := hasURLParameter(targetURL)
	hasKey := hasKeyParameter(string(payload[noChunkStart:noChunkEnd]))

	// POSTデータ抽出判定
	switch {
	case strings.Contains(contentType, "application/json"):
		if hasGetPostData(hasURL, hasKey) {
			if err := parseJsonAndTextBody(targetURL, payload[noChunkStart:noChunkEnd]); err != nil {
				log.Printf("failed to process parseJsonBody: %v", err)
				return nil
			}
		}
	case strings.Contains(contentType, "text/plain"):
		if hasGetPostData(hasURL, hasKey) {
			if err := parseJsonAndTextBody(targetURL, payload[noChunkStart:noChunkEnd]); err != nil {
				log.Printf("failed to process parseBody: %v", err)
				return nil
			}
		}
	case strings.Contains(contentType, "application/x-www-form-urlencoded"):
		if hasGetPostData(hasURL, hasKey) {
			if err := parseFormBody(targetURL, payload[noChunkStart:noChunkEnd]); err != nil {
				log.Printf("failed to process parseBody: %v", err)
				return nil
			}
		}
	default:
		return nil
	}
	return nil
}

// // --------------------------------
// // ヘルパー関数
// // --------------------------------
// HTTPステータスコード200を送信する
func sendHTTPCode200(cliFD int) error {
	httpCode200 := []byte("ICAP/1.0 200 OK\r\n" +
		"Server: Go-ICAP/1.0\r\n" +
		"Methods: REQMOD\r\n" +
		"ISTag: v1-local-1\r\n" +
		"Allow: 204\r\n" +
		"Encapsulated: null-body=0\r\n\r\n")
	writeLen := 0

	for writeLen < len(httpCode200) {
		numWrite, err := syscall.Write(cliFD, httpCode200[writeLen:])
		if err != nil {
			// プロキシサーバ(Squid) が、接続を切断またはRSTパケットを送信した場合、正常に終了する
			if err == syscall.EPIPE || err == syscall.ECONNRESET {
				log.Printf("Client disconnected during OPTIONS response write: %v", err)
				return nil
			}
			return fmt.Errorf("failed to OPTIONS write http code: %w", err)
		}
		writeLen += numWrite
	}
	return nil
}

// HTTPステータスコード204を送信する
func sendHTTPCode204(cliFD int) error {
	httpCode204 := []byte("ICAP/1.0 204 No Content\r\n\r\n")
	writeLen := 0

	for writeLen < len(httpCode204) {
		numWrite, err := syscall.Write(cliFD, httpCode204[writeLen:])
		if err != nil {
			// プロキシサーバ(Squid) が、接続を切断またはRSTパケットを送信した場合、正常に終了する
			if err == syscall.EPIPE || err == syscall.ECONNRESET {
				log.Printf("Client disconnected during response write: %v", err)
				return nil
			}
			return fmt.Errorf("failed to write http code: %w", err)
		}
		writeLen += numWrite
	}
	return nil
}

// 認証系やフォーム系に関するURLであるかを判定する
func hasURLParameter(targetURL string) bool {
	urlParameters := []string{
		// 認証や許可に関するキー
		"login", "signin", "auth", "register", "ap/", "account", "signup", "session", "oauth",
		// フォームや問い合わせに関するキー
		"form", "submit", "entry", "contact", "profile", "post", "feedback", "setting", "edit", "update",
	}

	for _, urlParameter := range urlParameters {
		if strings.Contains(targetURL, urlParameter) {
			return true
		}
	}
	return false
}

// 認証情報や個人情報に関するキーワードであるかを判定する
func hasKeyParameter(payload string) bool {
	keyParameters := []string{
		// ID・ユーザー
		"user_id", "userid", "username", "login_id",
		// パスワード
		"password", "passwd", "pwd", "pw",
		// 連絡先
		"email", "phone",
		// 認証情報
		"access_token", "session_id",
		// 個人情報
		"first_name", "last_name",
		// OAuth・APIキー
		"client_secret", "refresh_token", "bearer",
	}

	sensitiveKeyPattern := regexp.MustCompile(`\b(` + strings.Join(keyParameters, "|") + `)\b`)
	if sensitiveKeyPattern.MatchString(payload) {
		// matches := sensitiveKeyPattern.FindStringSubmatch(payload)
		// if len(matches) > 1 {
		// 	fmt.Println("Match Key: ", matches[1])
		// }
		return true
	}
	return false
}

// POSTデータの抽出を判定する
// 優先順位
// 1: URLあり & Keyあり (抽出)
// 2: URLあり & Keyなし (スキップ)
// 3: URLなし & Keyあり (抽出)
// 4: URLなし & Keyなし (スキップ)
func hasGetPostData(hasURL, hasKey bool) bool {
	switch {
	case hasURL && hasKey:
		return true
	case hasURL && !hasKey:
		return false
	case !hasURL && hasKey:
		return true
	default:
		return false
	}
}

// JSONデータ & テキストデータの処理
func parseJsonAndTextBody(targetURL string, payload []byte) error {
	// 中括弧 {} のネストレベルを数えるカウンタ変数
	noChunkedHttpBody := bytes.TrimSpace(payload)
	var jsonStart, jsonEnd int
	braceCount := 0
	for index, jsonValue := range noChunkedHttpBody {
		if jsonValue == '{' && braceCount == 0 {
			jsonStart = index
			braceCount = 1
		} else if jsonValue == '{' {
			braceCount++
		} else if jsonValue == '}' {
			braceCount--
			if braceCount == 0 && jsonStart >= 0 {
				jsonEnd = index + 1
				break
			}
		}
	}

	// }が見つからない場合、データ終端までをJSONとみなす
	if jsonEnd == 0 && jsonStart >= 0 {
		jsonEnd = len(noChunkedHttpBody)
	}
	if jsonStart < 0 || jsonEnd == 0 {
		return fmt.Errorf("no valid json data found")
	}

	// 抽出したJSON形式のペイロードを整形する
	jsonPayload := noChunkedHttpBody[jsonStart:jsonEnd]
	var postPayload map[string]interface{}
	if err := json.Unmarshal(jsonPayload, &postPayload); err != nil {
		return fmt.Errorf("failed to parse json: %w", err)
	}
	indentJSON, _ := json.MarshalIndent(postPayload, "", "  ")

	// ログファイルに書き込む
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	displayFormat := fmt.Sprintf(
		"[%s]\n"+
			"=====================================\n"+
			"1. TargetURL: %s\n"+
			"2. Payload\n"+
			"%s\n"+
			"=====================================\n\n",
		timestamp, targetURL, indentJSON,
	)
	logFileWrite(targetURL, displayFormat)

	return nil
}

// フォームデータの処理
func parseFormBody(targetURL string, payload []byte) error {
	postPayload, err := url.ParseQuery(strings.TrimSpace(string(payload)))
	if err != nil {
		return fmt.Errorf("failed to parse form or text payload: %w", err)
	}

	// ペイロードの出力フォーマットを整形する
	maxKeyLen := 0
	var payloadOutputFormatting string
	for key := range postPayload {
		if len(key) > maxKeyLen {
			maxKeyLen = len(key)
		}
	}
	for key, values := range postPayload {
		value := strings.Join(values, ", ")
		payloadOutputFormatting += fmt.Sprintf("%-*s | %s\n", maxKeyLen, key, value)
	}

	// ログファイルに書き込む
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	displayFormat := fmt.Sprintf(
		"[%s]\n"+
			"=====================================\n"+
			"1. TargetURL: %s\n\n"+
			"2. Payload\n"+
			"%s"+
			"=====================================\n\n",
		timestamp, targetURL, payloadOutputFormatting,
	)
	logFileWrite(targetURL, displayFormat)

	return nil
}

// POSTメソッドのペイロードをログファイルに書き込む
// func logFileWrite(targetURL, indentJSON, formatTyep string) {
func logFileWrite(targetURL, displayFormat string) {
	// ログ用ファイルを「読み書き＋存在しなければ作成＋末尾追記モード」で開く
	fileName := "payload.log"
	file, err := os.OpenFile(fileName, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Println("failed to process os.OpenFile")
	}
	// 関数終了時にファイルクローズ
	defer file.Close()

	if _, err = file.WriteString(displayFormat); err != nil {
		log.Println("failed to write %w: %w", fileName, err)
	}
}
