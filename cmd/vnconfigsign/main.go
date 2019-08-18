package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/golang/protobuf/proto"
	"github.com/losfair/vnet/protocol"
	"io/ioutil"
	"log"
	"math/big"
	"net/url"
	"path"
	"time"
)

func main() {
	caCertPath := flag.String("ca-cert", "", "Path to CA certificate")
	caKeyPath := flag.String("ca-key", "", "Path to CA private key")
	configFilePath := flag.String("config", "", "Path to config file")
	outDir := flag.String("out-dir", "distributed-config", "Output directory")
	flag.Parse()

	configRaw, err := ioutil.ReadFile(*configFilePath)
	if err != nil {
		log.Fatal(err)
	}

	caKeypair, err := tls.LoadX509KeyPair(*caCertPath, *caKeyPath)
	if err != nil {
		log.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caKeypair.Certificate[0])
	if err != nil {
		log.Fatal(err)
	}

	configHash := sha256.Sum256(configRaw)
	configUrl, err := url.Parse("vnet-conf://" + hex.EncodeToString(configHash[:]))
	if err != nil {
		log.Fatal(err)
	}

	currentTime := time.Now().UTC()

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(0),
		NotBefore:    currentTime,
		NotAfter:     currentTime.AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		URIs:         []*url.URL{configUrl},
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	pub := &priv.PublicKey

	signedCert, err := x509.CreateCertificate(rand.Reader, cert, caCert, pub, caKeypair.PrivateKey)
	if err != nil {
		log.Fatal(err)
	}

	output := &protocol.DistributedConfig{
		Version:     1,
		Certificate: signedCert,
		Content:     configRaw,
	}
	outputRaw, err := proto.Marshal(output)
	if err != nil {
		log.Fatal(err)
	}

	outputName := fmt.Sprintf(
		"dconf-%d-%02d-%02d-%02d-%02d-%02d.bin",
		currentTime.Year(), currentTime.Month(), currentTime.Day(),
		currentTime.Hour(), currentTime.Minute(), currentTime.Second(),
	)

	err = ioutil.WriteFile(path.Join(*outDir, outputName), outputRaw, 0644)
	if err != nil {
		log.Fatal(err)
	}
}
