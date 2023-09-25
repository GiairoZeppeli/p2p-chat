package main

import (
	"crypto/rand"
	"fmt"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/multiformats/go-multiaddr"
	"log"
	"os"
	"p2p/cli"
	"p2p/crypt"
	"p2p/network"
)

func createP2pHost(port *int, prvKey crypto.PrivKey) (host.Host, error) {
	sourceMultiAddr, _ := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", *port))
	host, err := libp2p.New(
		libp2p.ListenAddrs(sourceMultiAddr),
		libp2p.Identity(prvKey),
	)
	if err != nil {
		log.Fatal(err)
	}
	return host, err
}

func main() {
	port, conn := cli.ParseCommandLineFlags()

	r := rand.Reader
	privatKey := crypt.GeneratePrivateKey(r)

	host, err := createP2pHost(port, privatKey)
	if err != nil {
		os.Exit(1)
	}
	defer host.Close()

	if *conn == "" {
		network.HandleLocalHost(host)
	} else {
		network.HandleRemoteHost(host, conn)
	}
}
