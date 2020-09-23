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

	"../../login" // Modify when it is pushed
	"github.com/google/glome/go/glome"
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

	responseLen uint8
	userHeader  string
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

// maybe a better name should be used
func (s *LoginServer) newGlomeLoginLibServer() {
	return login.Server{KeyFetcher: k.keyFetcher()}
}

func printResponse(w http.ResponseWriter, s string) {
	fmt.Fprintf(w, s)
	log.Printf(s)
}

// ServeHTTP implements http.Handler interface.
func (s *LoginServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	user := r.Header.Get(s.userHeader)
	loginParser := newGlomeLoginLibServer

	// get url somehow
	response, err := loginParser.ParseURLResponse(url)
	if err != nil {
		printResponse(w, err.Error())
		return
	}

	if err := handleVersion(response.V); err != nil {
		printResponse(w, err.Error())
		return
	}

	s.printToken(w, response)
}

// Verify if provided version is accepted by the server
func handleVersion(V byte) error {
	if i != 1 {
		return ErrVersionNotSupported
	}
	return nil
}

func (s *LoginServer) printToken(w http.ResponseWriter, r *URLResponse) {
	s.authLock.RLock()
	allowed, err := s.auth.GrantLogin(user, hostID, hostIDType, action)
	s.authLock.RUnlock()

	if !allowed {
		if err != nil {
			printResponse(w, err.Error())
		}
		printResponse(w, "Unauthorized action")

		return
	}

	responseToken := r.GetEncToken()
	fmt.Fprintln(w, responseToken)
	log.Printf("User '%v' is allowed to run action '%v' in host '%v'. \n", user, action, hostID)
}
