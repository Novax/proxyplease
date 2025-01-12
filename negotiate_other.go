//go:build !windows
// +build !windows

package proxyplease

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"net"
	"net/http"
	"net/url"
)

func dialNegotiate(p Proxy, addr string, baseDial func() (net.Conn, error)) (net.Conn, error) {
	debugf("negotiate> Attempting to authenticate")

	conn, err := baseDial()
	if err != nil {
		debugf("negotiate> Could not call dial context with proxy: %s", err)
		return conn, err
	}

	h := p.URL.Hostname()
	spn := "HTTP/" + h

	cfg, err := config.Load("/etc/krb5.conf")
	if err != nil {
		debugf("negotiate> Error loading krb5.conf: %s", err)
		return conn, err
	}

	kt, err := keytab.Load(p.Keytab)
	if err != nil {
		debugf("negotiate> Error loading keytab: %s", err)
		return conn, err
	}
	cl := client.NewWithKeytab(p.Username, p.Domain, kt, cfg)

	spnegoCl := spnego.SPNEGOClient(cl, spn)

	err = spnegoCl.AcquireCred()
	if err != nil {
		debugf("negotiate> could not acquire client credential: %v", err)
		return conn, err
	}

	st, err := spnegoCl.InitSecContext()
	if err != nil {
		debugf("negotiate> could not initialize context: %v", err)
		return conn, err
	}

	nb, err := st.Marshal()
	if err != nil {
		debugf("negotiate> could not marshal SPENEGO: %v", err)
		return conn, err
	}

	defer cl.Destroy()

	head := p.Headers.Clone()
	head.Set("Proxy-Authorization", fmt.Sprintf("Negotiate %s", base64.StdEncoding.EncodeToString(nb)))
	head.Set("Proxy-Connection", "Keep-Alive")
	connect := &http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Opaque: addr},
		Host:   addr,
		Header: head,
	}
	if err := connect.Write(conn); err != nil {
		debugf("negotiate> Could not write token message to proxy: %s", err)
		return conn, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, connect)
	if err != nil {
		debugf("negotiate> Could not read token response from proxy: %s", err)
		return conn, err
	}

	if resp.StatusCode != http.StatusOK {
		debugf("negotiate> Expected %d as return status, got: %d", http.StatusOK, resp.StatusCode)
		return conn, errors.New(http.StatusText(resp.StatusCode))
	}

	resp.Body.Close()

	debugf("negotiate> Successfully injected Negotiate::Kerberos to connection")
	return conn, nil
}
