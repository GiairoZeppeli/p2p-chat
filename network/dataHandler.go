package network

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"github.com/libp2p/go-libp2p/core/network"
	"log"
	"p2p/crypt"
)

func HandleStream(s network.Stream) {
	log.Println("Новое соединение")
	rw := bufio.NewReadWriter(bufio.NewReader(s), bufio.NewWriter(s))

	sessionPrivateKey, err := ecdsa.GenerateKey(crypt.Curve(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	sessionPublicKey := &sessionPrivateKey.PublicKey
	serialPublicKey := append(sessionPublicKey.X.Bytes(), sessionPublicKey.Y.Bytes()...)

	publicKeyString := base64.StdEncoding.EncodeToString(serialPublicKey) + "\n"
	rw.WriteString(publicKeyString)
	rw.Flush()

	serialPeerPublicKey, err := rw.ReadString('\n')
	if err != nil {
		log.Fatal(err)
	}
	bytesPublicKey, err := base64.StdEncoding.DecodeString(serialPeerPublicKey)
	if err != nil {
		log.Fatal(err)
	}

	peerPublicKey := GetPublicKey(bytesPublicKey)

	done := make(chan struct{})
	go Read(rw, sessionPrivateKey, serialPeerPublicKey, done)
	go Write(rw, peerPublicKey, sessionPrivateKey, done)
}
