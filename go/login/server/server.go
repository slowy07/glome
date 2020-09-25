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

// Package server implements GLOME-login server framework.
package server

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"sync"

	"../../login" // Modify when it is pushed
)

const (
	// MaxResponseSize is the maximum size in characaters of the response token
	MaxResponseSize = 44 // 32bytes base64 encoded
)

var (
	// ErrInvalidResponseLen denotes that response length provided is invalid
	ErrInvalidResponseLen = fmt.Errorf("invalid response length provided")
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
	auth        Authorizer
	authLock    sync.RWMutex
	loginParser *login.Server

	responseLen uint8
	userHeader  string
}

// Authorizer sets Authorizer function for LoginServer in a concurrentsafe way.
func (s *LoginServer) Authorizer(a Authorizer) {
	s.authLock.Lock()
	s.auth = a
	s.authLock.Unlock()
}

// NewLoginServer creates a new server with provided Authorizer and, optionally, selected options
func NewLoginServer(a Authorizer, options ...func(*LoginServer) error) (*LoginServer, error) {
	srv := LoginServer{
		auth:        a,
		Keys:        NewKeyManager(),
		responseLen: MaxResponseSize,
	}
	srv.loginParser = srv.newLoginParser()

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
func (s *LoginServer) newLoginParser() *login.Server {
	return &login.Server{KeyFetcher: s.Keys.keyFetcher()}
}

// ServeHTTP implements http.Handler interface.
func (s *LoginServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, r.URL.Path)
	if r.URL.Path == "/" {
		s.printServerKeys(w)
		return
	}

	user := r.Header.Get(s.userHeader)

	path := r.URL.RawPath
	if path == "" {
		path = r.URL.Path
	}

	response, err := s.loginParser.ParseURLResponse(path)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	s.printToken(w, response, user)
}

func (s *LoginServer) printToken(w http.ResponseWriter, r *login.URLResponse, user string) {
	s.authLock.RLock()
	allowed, err := s.auth.GrantLogin(user, r.Msg.HostID, r.Msg.HostIDType,
		r.Msg.Action)
	s.authLock.RUnlock()

	if !allowed {
		if err != nil {
			http.Error(w, err.Error(), 403)
		}
		http.Error(w, "Unauthorized action", 403)

		return
	}

	responseToken := r.GetEncToken()[:s.responseLen]
	fmt.Fprintln(w, responseToken)
}

func (s *LoginServer) printServerKeys(w http.ResponseWriter) {
	fmt.Fprintf(w, "Index\tValue\n")
	for _, key := range s.Keys.ServiceKeys() {
		fmt.Fprintf(w, "%v\t%v\n", key.Index, hex.EncodeToString(key.Value[:]))
	}
}
