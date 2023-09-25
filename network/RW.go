package network

import (
	"bufio"
	"crypto/ecdsa"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"os"
	"p2p/crypt"
	"strings"
)

func Read(rw *bufio.ReadWriter, privateKey *ecdsa.PrivateKey, publicKeyString string, done chan struct{}) {
	exited := false
	for {
		rawString, err := rw.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				fmt.Printf("[%s] Соединение закрыто пиром\n", publicKeyString[:4])
			} else {
				fmt.Println("Ошибка чтения из потока:", err)
			}
			close(done)
			return
		}

		decodedString, err := base64.StdEncoding.DecodeString(rawString)
		if err != nil {
			fmt.Println("Ошибка декодирования:", err)
			close(done)
			return
		}
		if len(decodedString) == 0 {
			continue
		}

		decryptedString, err := crypt.Decrypt(privateKey, decodedString)
		str := string(decryptedString)
		if str == "" || err != nil {
			fmt.Println("Ошибка расшифровки:", err)
			close(done)
			return
		}

		if str != "\n" {
			if strings.TrimSpace(str) != "exit" && !exited {
				fmt.Printf("[%s]\x1b[35m%s\x1b[0m| ", publicKeyString[:4], str)
			} else {
				fmt.Printf("[%s] Пир отключился\n", publicKeyString[:4])
				exited = true
				close(done)
				return
			}
		}
	}
}

func Write(rw *bufio.ReadWriter, publicKey *ecdsa.PublicKey, privKey *ecdsa.PrivateKey, done chan struct{}) {
	stdReader := bufio.NewReader(os.Stdin)
	for {
		select {
		case <-done:
			return
		default:
			fmt.Print("| ")
			data, err := stdReader.ReadString('\n')
			if err != nil {
				fmt.Println("Ошибка чтения из stdin:", err)
				close(done)
				return
			}
			sendingData, err := crypt.Encrypt(publicKey, privKey, []byte(data))
			if err != nil {
				fmt.Println("Ошибка шифрования:", err)
				close(done)
				return
			}
			rw.WriteString(fmt.Sprintf("%s\n", base64.StdEncoding.EncodeToString(sendingData)))
			rw.Flush()
		}
	}
}

func GetPublicKey(bytes []byte) *ecdsa.PublicKey {
	var X, Y big.Int
	xBytes := bytes[:32]
	yBytes := bytes[32:]
	X.SetBytes(xBytes)
	Y.SetBytes(yBytes)
	peerPublicKey := ecdsa.PublicKey{
		Curve: crypt.Curve(),
		X:     &X,
		Y:     &Y,
	}

	return &peerPublicKey
}
