// Copyright (c) 2020 Richard Youngkin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"time"
)

func main() {
	help := flag.Bool("help", false, "Optional, prints usage info")
	srvhost := flag.String("srvhost", "localhost", "The server's host name")
	caCertFile := flag.String("cacert", "", "Required, the name of the CA that signed the server's certificate")
	clientCertFile := flag.String("clientcert", "", "Required, the name of the client's certificate file")
	clientKeyFile := flag.String("clientkey", "", "Required, the file name of the clients's private key file")
	port := flag.String("port", "8443", "Required, the port to connect to for the srvhost")
	dnsServer := flag.String("dnsserver", "127.0.0.1:53", "Required, the dns server to resolve srvhost")
	flag.Parse()

	usage := `usage:
	
client -clientcert <clientCertificateFile> -cacert <caFile> -clientkey <clientPrivateKeyFile> [-host <srvHostName> -help]
	
Options:
  -help       Optional, Prints this message
  -srvhost    Optional, the server's hostname, defaults to 'localhost'
  -clientcert Required, the name the clients's certificate file
  -clientkey  Required, the name the client's key certificate file
  -cacert     Required, the name of the CA that signed the server's certificate
  -port       Required, the port to connect to for the srvhost
  -dnsserver  Required, dnsserver used to resolve the srvhost
 `

	if *help == true {
		fmt.Println(usage)
		return
	}
	if *caCertFile == "" {
		log.Fatalf("caCert is required but missing:\n%s", usage)
	}

	var cert tls.Certificate
	var err error
	if *clientCertFile != "" && *clientKeyFile != "" {
		cert, err = tls.LoadX509KeyPair(*clientCertFile, *clientKeyFile)
		if err != nil {
			log.Fatalf("Error creating x509 keypair from client cert file %s and client key file %s", *clientCertFile, *clientKeyFile)
		}
	}

	log.Printf("CAFile: %s", *caCertFile)
	caCert, err := ioutil.ReadFile(*caCertFile)
	if err != nil {
		log.Fatalf("Error opening cert file %s, Error: %s", *caCertFile, err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	var (
		dnsResolverIP        = *dnsServer // DNS resolver.
		dnsResolverProto     = "udp"      // Protocol to use for the DNS resolver
		dnsResolverTimeoutMs = 5000       // Timeout (ms) for the DNS resolver (optional)
	)

	dialer := &net.Dialer{
		Resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: time.Duration(dnsResolverTimeoutMs) * time.Millisecond,
				}
				return d.DialContext(ctx, dnsResolverProto, dnsResolverIP)
			},
		},
	}

	dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, addr)
	}

	t := &http.Transport{
		DialContext: dialContext,
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      caCertPool,
		},
	}

	client := http.Client{Transport: t, Timeout: 15 * time.Second}
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://%s:%s", *srvhost, *port), bytes.NewBuffer([]byte("Ciccio")))
	if err != nil {
		log.Fatalf("unable to create http request due to error %s", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		switch e := err.(type) {
		case *url.Error:
			log.Fatalf("url.Error received on http request: %s", e)
		default:
			log.Fatalf("Unexpected error received: %s", err)
		}
	}

	body, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		log.Fatalf("unexpected error reading response body: %s", err)
	}

	fmt.Printf("\nResponse from server: \n\tHTTP status: %s\n\tBody: %s\n", resp.Status, body)
}
