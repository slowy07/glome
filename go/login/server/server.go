// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package backend implements GLOME-login server framework.
package server

import (
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"sync"

	"github.com/google/glome/go/glome"
	"github.com/gorilla/mux"
)

const (
	// MaxResponseSize is the maximum size in characaters of the response token
	MaxResponseSize = 44 // 32bytes base64 encoded
)

var (
	// ErrInvalidResponseLen denotes that response length provided is invalid
	ErrInvalidResponseLen = fmt.Errorf("invalid response length provided")

	// This error are hypothesis on what will be provided by the glome login lib

	// ErrFailedHandshake denotes that GLOME handshake has failed.
	ErrFailedHandshake = fmt.Errorf("400 bad request: failed handshake")
	// ErrVersionNotSupported denotes that a version of GLOME handshake is not supported.
	ErrVersionNotSupported = fmt.Errorf("400 bad request: version not supported")
	// ErrInvalidPrefixType denotes that a prefix type is invalid.
	ErrInvalidPrefixType = fmt.Errorf("400 bad request: invalid prefix type")
	// ErrInvalidPrefix7 denotes that a prefix7 is invalid.
	ErrInvalidPrefix7 = fmt.Errorf("404 Not Found: prefix7 not found")
	// ErrInvalidEph denotes that a ephemeral is invalid.
	ErrInvalidEph = fmt.Errorf("400 bad request: invalid ephemeral Key")
	// ErrIncorrectTag denotes that received tag is incorrect
	ErrIncorrectTag = fmt.Errorf("invalid Tag")
)

// Authorizer responds to an authorization request. The method
// Allow returns whether an user is allowed to run an action in a host.
//
// Some considerations need to be held while implementing this interface:
// - Allow should accept an empty string as command, denoting that
// an empty action is passed in the request.
// - If no user can be obtained from request metadata, an empty string is to be
// passed as default value.
// - Both hostIDType and hostID can be empty. Whether this refer to a default value
// or not is to be user configurable.
type Authorizer interface {
	GrantLogin(user string, hostID string, hostIDType string, action string) (bool, error)
}

// AuthorizerFunc type is an adapter to allow the use of ordinary functions as Authorizers.
type AuthorizerFunc func(user string, hostID string, hostIDType string, action string) (bool, error)

// GrantLogin calls a(user, action, host)
func (a AuthorizerFunc) GrantLogin(user string, hostID string, hostIDType string, action string) (bool, error) {
	return a(user, hostID, hostIDType, action)
}

// LoginServer is a framework for programming glome-login servers, that will be
// useful for most use-cases. Creation of the object is managed via the NewLoginServer
// method. To create one it is necessary to provide an authorizer. Optionally, a series
// of options can be added at creation.
type LoginServer struct {
	// Keys manages the keys used by the server.
	Keys *KeyManager

	// Unexported fields.
	auth     Authorizer
	authLock sync.RWMutex
	router   *mux.Router

	responseLen uint8
	userHeader  string
}

// ServeHTTP implements http.Handler interface.
func (s *LoginServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

// Authorizer sets Authorizer function for LoginServer in a concurrentsafe way.
func (s *LoginServer) Authorizer(a Authorizer) {
	s.authLock.Lock()
	s.auth = a
	s.authLock.Unlock()
}

// NewServer creates a new server with provided Authorizer and, optionally, selected options
func NewLoginServer(a Authorizer, options ...func(*LoginServer) error) (*LoginServer, error) {
	srv := LoginServer{
		auth:        a,
		Keys:        NewKeyManager(),
		responseLen: MaxResponseSize,
	}
	srv.router = srv.newRouter()

	for _, option := range options {
		if err := option(&srv); err != nil {
			return nil, err
		}
	}

	return &srv, nil
}

// ResponseLen is an option to be provided to NewServer on creation. Its sets response len to
// n characters long response.
func ResponseLen(n uint8) func(srv *LoginServer) error {
	return func(srv *LoginServer) error {
		if !(0 < n && n <= MaxResponseSize) {
			return ErrInvalidResponseLen
		}
		srv.responseLen = n
		return nil
	}
}

// UserHeader is an option to be provided to NewServer on creation. Its sets UserHeader to s.
func UserHeader(s string) func(srv *LoginServer) error {
	return func(srv *LoginServer) error {
		srv.userHeader = s
		return nil
	}
}

//----- code onwards will be deprecated as soon as integration with go-glome-login is done -----
func (s *LoginServer) newRouter() *mux.Router { // Review Error Message
	r := mux.NewRouter().UseEncodedPath()

	handler := func(w http.ResponseWriter, r *http.Request) {
		params := mux.Vars(r)

		user := r.Header.Get(s.userHeader)

		if err := handleVersion(params["V"]); err != nil {
			log.Printf(err.Error())
			fmt.Fprintln(w, err.Error())
			return
		}

		dialog, tag, err := s.handleHandshakeV1(params["handshake"])
		if err != nil {
			log.Printf(err.Error())
			fmt.Fprintln(w, err.Error())
			return
		}

		hostID, err := readHost(params["hostID"])
		if err != nil {
			log.Printf(err.Error())
			fmt.Fprintln(w, err.Error())
			return
		}

		action, err := readAction(params)
		if err != nil {
			log.Printf(err.Error())
			fmt.Fprintln(w, err.Error())
			return
		}

		msg, err := readMessage(hostID, action)
		if err != nil {
			log.Printf(err.Error())
			fmt.Fprintln(w, err.Error())
			return
		}

		if err = verifyReceivedTag(dialog, tag, msg); err != nil {
			log.Printf(err.Error())
			fmt.Fprintln(w, err.Error())
			return
		}

		hostIDType := ""
		s.printToken(w, dialog, hostID, hostIDType, action, msg, user)
	}

	r.Path("/v{V:[0-9]+}/{handshake}/{hostID}/").HandlerFunc(handler)
	r.Path("/v{V:[0-9]+}/{handshake}/{hostID}/{action:[a-zA-Z0-9+/=%]+}/").
		HandlerFunc(handler)

	return r
}

func handleVersion(V string) error {
	switch i, err := strconv.Atoi(V); {
	case err != nil:
		return err
	case i != 1:
		return ErrVersionNotSupported
	}
	return nil
}

func (s *LoginServer) handleHandshakeV1(h string) (*glome.Dialog, []byte, error) {
	data, err := base64.URLEncoding.DecodeString(h)
	if err != nil {
		return nil, nil, err
	}

	if len(data) < 32 { //handshake must have 66 bytes (2 prefixtype+prefix7, 32 eph, 32 prefixN)
		return nil, nil, ErrFailedHandshake
	}

	prefixtype := data[0] >> 7 // Read first bit
	if prefixtype != 0 {
		return nil, nil, ErrInvalidPrefixType
	}

	prefix7 := (data[0] & 127) // Read first byte but fist bit
	server, found := s.Keys.Read(prefix7)
	if !found {
		return nil, nil, ErrInvalidPrefix7
	}

	client, err := glome.PublicKeyFromSlice(data[1:33])
	if err != nil {
		return nil, nil, err
	}

	dialog, err := server.TruncatedExchange(client, 1)
	if err != nil {
		return nil, nil, err
	}

	return dialog, data[33:], nil // PrefixN currently stores the message tag.
}

func readHost(hostID string) (string, error) {
	return url.QueryUnescape(hostID)
}

func readAction(params map[string]string) (string, error) {
	action, ok := params["action"]
	if !ok {
		return "", nil
	}

	return url.QueryUnescape(action)
}

func readMessage(hostID string, action string) ([]byte, error) {
	msgAux, err := url.QueryUnescape(hostID + "/" + action)
	if err != nil {
		return nil, err
	}

	msg := []byte(msgAux) // If we do []byte(hostID + "/" + action) percent notation remain unescaped.

	return msg, nil
}

func verifyReceivedTag(d *glome.Dialog, tag []byte, msg []byte) error {
	if len(tag) > 0 { // It might be possible that the user decide not to send his tag
		if !d.Check(tag, msg, 0) {
			return ErrIncorrectTag
		}
	}
	return nil
}

//This function is to be redone after the glome-login-lib is integrated
func (s *LoginServer) printToken(w http.ResponseWriter, d *glome.Dialog, hostID string, hostIDType string,
	action string, msg []byte, user string) {
	s.authLock.RLock()
	allowed, err := s.auth.GrantLogin(user, hostID, hostIDType, action)
	s.authLock.RUnlock()

	if !allowed {
		if err != nil {
			fmt.Fprintf(w, "User '%v' is not authorized to run action '%v' in host '%v:%v' because %v \n",
				user, action, hostIDType, hostID, err)
			log.Printf("User '%v' is not authorized to run action '%v' in host '%v:%v' because %v \n",
				user, action, hostIDType, hostID, err)
		}
		fmt.Fprintf(w, "403 Forbidden: User '%v' is not authorized to run action '%v' in host '%v'. \n",
			user, action, hostID)
		log.Printf("403 Forbidden: User '%v' is denied to run action '%v' in host '%v'. \n",
			user, action, hostID)
		return
	}

	responseToken := base64.URLEncoding.EncodeToString(d.Tag(msg, 0))[:s.responseLen]
	fmt.Fprintln(w, responseToken)
	log.Printf("User '%v' is allowed to run action '%v' in host '%v'. \n", user, action, hostID)
}
