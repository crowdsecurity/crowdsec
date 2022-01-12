// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in https://raw.githubusercontent.com/golang/go/master/LICENSE
// auth.go file is a modification of smtp golang package what is frozen and is not accepting new features.

package mail

import (
	"crypto/hmac"
	"crypto/md5"
	"errors"
	"fmt"
	"strings"
)

// auth is implemented by an SMTP authentication mechanism.
type auth interface {
	// start begins an authentication with a server.
	// It returns the name of the authentication protocol
	// and optionally data to include in the initial AUTH message
	// sent to the server. It can return proto == "" to indicate
	// that the authentication should be skipped.
	// If it returns a non-nil error, the SMTP client aborts
	// the authentication attempt and closes the connection.
	start(server *serverInfo) (proto string, toServer []byte, err error)

	// next continues the authentication. The server has just sent
	// the fromServer data. If more is true, the server expects a
	// response, which next should return as toServer; otherwise
	// next should return toServer == nil.
	// If next returns a non-nil error, the SMTP client aborts
	// the authentication attempt and closes the connection.
	next(fromServer []byte, more bool) (toServer []byte, err error)
}

// serverInfo records information about an SMTP server.
type serverInfo struct {
	name string   // SMTP server name
	tls  bool     // using TLS, with valid certificate for Name
	auth []string // advertised authentication mechanisms
}

type plainAuth struct {
	identity, username, password string
	host                         string
}

// plainAuthfn returns an auth that implements the PLAIN authentication
// mechanism as defined in RFC 4616. The returned Auth uses the given
// username and password to authenticate to host and act as identity.
// Usually identity should be the empty string, to act as username.
//
// plainAuthfn will only send the credentials if the connection is using TLS
// or is connected to localhost. Otherwise authentication will fail with an
// error, without sending the credentials.
func plainAuthfn(identity, username, password, host string) auth {
	return &plainAuth{identity, username, password, host}
}

func (a *plainAuth) start(server *serverInfo) (string, []byte, error) {
	// Must have TLS, or else localhost server. Unencrypted connection is permitted here too but is not recommended
	// Note: If TLS is not true, then we can't trust ANYTHING in serverInfo.
	// In particular, it doesn't matter if the server advertises PLAIN auth.
	// That might just be the attacker saying
	// "it's ok, you can trust me with your password."
	if server.name != a.host {
		return "", nil, errors.New("wrong host name")
	}
	resp := []byte(a.identity + "\x00" + a.username + "\x00" + a.password)
	return "PLAIN", resp, nil
}

func (a *plainAuth) next(fromServer []byte, more bool) ([]byte, error) {
	if more {
		// We've already sent everything.
		return nil, errors.New("unexpected server challenge")
	}
	return nil, nil
}

/*
loginAuthfn authentication implements LOGIN Authentication, is the same PLAIN
but username and password are sent in different commands
*/

type loginAuth struct {
	identity, username, password string
	host                         string
}

func loginAuthfn(identity, username, password, host string) auth {
	return &loginAuth{identity, username, password, host}
}

func (a *loginAuth) start(server *serverInfo) (string, []byte, error) {
	if server.name != a.host {
		return "", nil, errors.New("wrong host name")
	}
	resp := []byte(a.username)
	return "LOGIN", resp, nil
}

func (a *loginAuth) next(fromServer []byte, more bool) ([]byte, error) {
	if more {
		if strings.Contains(string(fromServer), "Username") {
			resp := []byte(a.username)
			return resp, nil
		}

		if strings.Contains(string(fromServer), "Password") {
			resp := []byte(a.password)
			return resp, nil
		}

		// We've already sent everything.
		return nil, errors.New("unexpected server challenge")
	}
	return nil, nil
}

type cramMD5Auth struct {
	username, secret string
}

// cramMD5Authfn returns an Auth that implements the CRAM-MD5 authentication
// mechanism as defined in RFC 2195.
// The returned Auth uses the given username and secret to authenticate
// to the server using the challenge-response mechanism.
func cramMD5Authfn(username, secret string) auth {
	return &cramMD5Auth{username, secret}
}

func (a *cramMD5Auth) start(server *serverInfo) (string, []byte, error) {
	return "CRAM-MD5", nil, nil
}

func (a *cramMD5Auth) next(fromServer []byte, more bool) ([]byte, error) {
	if more {
		d := hmac.New(md5.New, []byte(a.secret))
		d.Write(fromServer)
		s := make([]byte, 0, d.Size())
		return []byte(fmt.Sprintf("%s %x", a.username, d.Sum(s))), nil
	}
	return nil, nil
}
