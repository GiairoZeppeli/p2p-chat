package network

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/multiformats/go-multiaddr"
	"log"
	"p2p/crypt"
)

func HandleLocalHost(host host.Host) {
	host.SetStreamHandler("/chat/1.0.0", HandleStream)

	port, err := findLocalPort(host)
	if err != nil {
		panic("Не удалось найти актуальный локальный порт")
	}

	fmt.Printf("Строка подключения -connection /ip4/127.0.0.1/tcp/%v/p2p/%s\n", port, host.ID())
	fmt.Printf("\nОжидание подключений\n\n")
	<-make(chan struct{})
}

func findLocalPort(host host.Host) (string, error) {
	for _, addresses := range host.Network().ListenAddresses() {
		if p, err := addresses.ValueForProtocol(multiaddr.P_TCP); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("Не удалось найти актуальный локальный порт")
}

func HandleRemoteHost(host host.Host, dest *string) {
	fmt.Println("Мультиадрес узла:")
	for _, la := range host.Addrs() {
		fmt.Printf(" - %v\n", la)
	}
	fmt.Println()

	maddr, err := multiaddr.NewMultiaddr(*dest)
	if err != nil {
		log.Fatalln(err)
	}

	info, err := peer.AddrInfoFromP2pAddr(maddr)
	if err != nil {
		log.Fatalln(err)
	}

	addPeerAddresses(host, info)

	s, err := host.NewStream(context.Background(), info.ID, "/chat/1.0.0")
	if err != nil {
		log.Fatal(err)
	}
	rw := bufio.NewReadWriter(bufio.NewReader(s), bufio.NewWriter(s))

	sessionPrivateKey, err := ecdsa.GenerateKey(crypt.Curve(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	sessionPublicKey := sessionPrivateKey.PublicKey
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
	go Read(rw, sessionPrivateKey, *dest, done)
	go Write(rw, peerPublicKey, sessionPrivateKey, done)
	select {}
}

func addPeerAddresses(host host.Host, info *peer.AddrInfo) {
	host.Peerstore().AddAddrs(info.ID, info.Addrs, peerstore.PermanentAddrTTL)
}
