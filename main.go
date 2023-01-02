package main

import (
	"crypto/tls"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	selfsigned "github.com/wolfeidau/golang-self-signed-tls"
)

// Settings
var remoteAddr string

const listenAddr = "0.0.0.0:443"
const nlogPath = "/opt/logs.txt"

var logPath string
var wlogPath = "john\\Desktop\\logs.txt"

// Hanlder function for all requests, forward to remoteAddr
func handleRequest(proxy *httputil.ReverseProxy) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		log.Println(req.Method, "from", req.RemoteAddr, "to", remoteAddr)

		proxy.ServeHTTP(w, req)
	}
}

func generateCerts() ([]byte, []byte) {
	log.Println("generating ssl certificates")
	result, err := selfsigned.GenerateCert(
		selfsigned.Hosts([]string{"127.0.0.1", "localhost"}),
		selfsigned.RSABits(4096),
		selfsigned.ValidFor(365*24*time.Hour),
	)
	if err != nil {
		log.Fatal("failed to generate ssl certificates", err)
	}
	return result.PrivateKey, result.PublicCert
}

func main() {
	if runtime.GOOS == "windows" {
		udir, err := os.UserHomeDir()
		if err != nil {
			log.Println(err)
		}
		logPath = strings.Replace(wlogPath, "john", udir, 1)
	} else {
		logPath = nlogPath
	}
	remoteAddr = os.Args[1]
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	file, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatal("unable to open logfile", err)
	}
	log.SetOutput(file)

	url, err := url.Parse(remoteAddr)
	if err != nil {
		log.Fatal("unable to parse remote address")
	}

	log.Println("creating reverse proxy to", remoteAddr)
	proxy := httputil.NewSingleHostReverseProxy(url)

	http.HandleFunc("/", handleRequest(proxy))

	var privKey, pubCert []byte
	if len(os.Args) == 4 {
		var err error
		if strings.Contains(os.Args[2], "key") {
			privKey, err = os.ReadFile(os.Args[2])
		} else if strings.Contains(os.Args[2], "cer") {
			pubCert, err = os.ReadFile(os.Args[2])
		}
		if strings.Contains(os.Args[3], "key") {
			privKey, err = os.ReadFile(os.Args[3])
		} else if strings.Contains(os.Args[3], "cer") {
			pubCert, err = os.ReadFile(os.Args[3])
		}
		if err != nil {
			log.Println("Error reading given KEY/CERT files")
			log.Println(err)
			log.Println("Will automatically generate new certificates to be used this session")
			privKey, pubCert = generateCerts()
		}
	} else {
		privKey, pubCert = generateCerts()
	}
	cert, err := tls.X509KeyPair(pubCert, privKey)
	if err != nil {
		log.Fatal("failed to generate x509 keypair")
	}

	srv := &http.Server{
		Addr:         listenAddr,
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
	}

	log.Println("listening on", listenAddr)
	log.Fatal(srv.ListenAndServeTLS("", ""))
}
