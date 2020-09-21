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

package login

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/glome/go/glome"
)

const (
	// Minimal acceptable length of a handshake. 1 byte for the prefix, 32 bytes for the key
	minHandshakeLen = 1 + glome.PublicKeySize
)

var (
	// ErrFailedHandshake denotes that the URL has a wrong format.
	ErrInvalidURLFormat = fmt.Errorf("URL is malformed")
	// ErrFailedHandshake denotes that the handshake is too short.
	ErrInvalidHandshakeLen = fmt.Errorf("handshake length is small: should be at least %d", minHandshakeLen)
	// ErrVersionNotSupported denotes that the version of glome-login URL format is not supported.
	ErrVersionNotSupported = fmt.Errorf("version not supported")
	// ErrInvalidPrefixType denotes that the prefix type is invalid.
	ErrInvalidPrefixType = fmt.Errorf("invalid prefix type")
	// ErrIncorrectTag denotes that received tag is incorrect.
	ErrIncorrectTag = fmt.Errorf("invalid tag")
)

var (
	validURLPrefix = regexp.MustCompile(`/(?P<v>v[1-9][0-9]*)/(?P<handshake>[\w=-]+)/`)
)

// Message struct represents the context required for authorization.
// It contains HostIDType - type of identity, HostID - identity of the target (e.g. hostname, serial number, etc.),
// Action - action that is being authorized.
type Message struct {
	HostIDType string
	HostID     string
	Action     string
}

// Constructs a Message according to the structure: [<hostid-type>:]<hostid>[/<action>].
func (m *Message) Construct() []byte {
	msg := ""
	if m.HostIDType != "" {
		msg += escape(m.HostIDType) + ":"
	}
	msg += fmt.Sprintf("%s", escape(m.HostID))

	if m.Action != "" {
		msg += fmt.Sprintf("/%s", m.Action)
	}
	return []byte(msg)
}

// Escapes the string so it can be safely placed inside a URL path segment,
// replacing "/#?" special characters and not replacing "!*'();:@&=+$,[]" special characters.
func escape(s string) string {
	res := url.PathEscape(s)
	for _, c := range "!*'();:@&=+$,[]" {
		st := string(c)
		strings.Replace(res, url.PathEscape(st), st, -1)
	}
	return res
}

// Handshake struct represents the context required for constructing the handshake.
// It contains Prefix - either service key or its id, UserKey - user's public ephemeral key,
// MsgTagPrefix - tag calculated under Message.
type Handshake struct {
	Prefix       byte
	UserKey      glome.PublicKey
	MsgTagPrefix []byte
}

// URLResponse struct represents the context required for the URL constructing.
// It contains V - URL format version (currently always 1), HandshakeInfo - handshake info,
// Msg - message info, d - glome.Dialog for the tag managing.
type URLResponse struct {
	V             byte
	HandshakeInfo Handshake
	Msg           Message
	d             *glome.Dialog
}

func NewResponse(serviceKeyId uint8, serviceKey glome.PublicKey, userKey glome.PrivateKey,
	V byte, hostIdType string, hostId string, action string) (*URLResponse, error) {
	var prefix byte
	var r URLResponse

	r.V = V

	d, err := userKey.TruncatedExchange(&serviceKey, 1) // TODO: receive m as param?
	if err != nil {
		return nil, err
	}
	r.d = d

	r.Msg = Message{hostIdType, hostId, action}

	if serviceKeyId == 0 {
		// If no key ID was specified, send the first key byte as the ID.
		prefix = serviceKey[0] & 0x7f
	} else {
		prefix = serviceKeyId & 0x7f
	}
	userPublic, err := userKey.Public()
	if err != nil {
		return nil, err
	}
	HandshakeInfo := Handshake{prefix, *userPublic, r.GetTag()}
	r.HandshakeInfo = HandshakeInfo

	return &r, nil
}

// Validates if the received tag corresponding to the base64-url encoded message constructed from the Message.
// Returns true if the received tag is empty.
func (r *URLResponse) ValidateAuthCode(tag []byte) bool {
	if len(tag) == 0 {
		return true
	}
	return r.d.Check(tag, r.Msg.Construct(), 0)
}

// Returns the tag corresponding to the Msg.
func (r *URLResponse) GetTag() []byte {
	u, _ := url.PathUnescape(string(r.Msg.Construct())) // ignore error as it is correctly escaped in r.Msg.Construct()
	return r.d.Tag([]byte(u), 0)
}

// Returns a base64-encoded response token.
func (r *URLResponse) GetEncToken() string {
	return base64.URLEncoding.EncodeToString(r.GetTag())
}

// Client side login-lib handler.
type Client struct {
	ServiceKey   glome.PublicKey
	UserKey      glome.PrivateKey
	ServiceKeyId uint8
	response     *URLResponse
}

// Client constructor. Sets Client.ServiceKey, Client.UserKey, Client.ServiceKeyId to the corresponding values
// and Client.response to nil.
func NewClient(sk glome.PublicKey, uk glome.PrivateKey, sId uint8) *Client {
	return &Client{sk, uk, sId, nil}
}

// Constructs a request to the server according to the structure: /v<V>/<glome-handshake>[/<message>]/.
func (c *Client) Construct(V byte, hostIdType string, hostId string, action string) (string, error) {
	r, err := NewResponse(c.ServiceKeyId, c.ServiceKey, c.UserKey, V, hostIdType, hostId, action)
	if err != nil {
		return "", nil
	}
	c.response = r

	var handshake = c.constructHandshake()
	var msg = c.response.Msg.Construct()
	var u = fmt.Sprintf("v%d/%s/", c.response.V, handshake)
	if len(msg) > 0 {
		u += fmt.Sprintf("%s/", msg)
	}
	return "", nil
}

func (c *Client) constructHandshake() string {
	var handshake []byte
	r := c.response

	handshake = append(handshake, r.d.User[:]...)
	handshake = append(handshake, r.GetTag()[:]...)
	return base64.URLEncoding.EncodeToString(handshake[:])
}

// Validates if the received tag corresponding to the base64-url encoded message constructed from the Message.
func (c *Client) ValidateAuthCode(tag string) bool {
	dTag, err := base64.URLEncoding.DecodeString(completeBase64S(tag))
	if err != nil {
		return false
	}
	return c.response.ValidateAuthCode(dTag)
}

// Completes the base64 string with padding if it was truncated and couldn't be correctly decoded.
func completeBase64S(s string) string {
	n := len(s)
	switch n % 4 {
	case 0:
		return s
	case 1:
		return s[:n-1]
	case 2:
		return s + "=="
	case 3:
		return s + "="
	default:
		panic("math fail")
	}
}

func (c *Client) getResponse() *URLResponse {
	return c.response
}

// Server side glome-login lib handler. Receives the server's private key fetcher function.
type Server struct {
	KeyFetcher func(uint8) glome.PrivateKey
}

// Parses the url, checks whether it is formed correctly and validates the client's tag, received from the URL.
func (s *Server) ParseURLResponse(url string) (*URLResponse, error) {
	response := URLResponse{}

	names := validURLPrefix.SubexpNames()[1:]        // as "The name for the first sub-expression is names[1].."
	parsed := validURLPrefix.FindStringSubmatch(url) // save first element (full substring) to be trimmed later in url
	if parsed == nil {
		return nil, ErrInvalidURLFormat
	}
	reqParts := map[string]string{}
	for i := 0; i < len(names); i++ {
		reqParts[names[i]] = parsed[i+1]
	}

	v, err := parseVersion(reqParts["v"])
	if err != nil {
		return nil, err
	}
	response.V = v

	handshake, err := parseHandshake(reqParts["handshake"])
	if err != nil {
		return nil, err
	}
	response.HandshakeInfo = *handshake
	serverPrivKey := s.KeyFetcher(response.HandshakeInfo.Prefix)
	response.d, err = serverPrivKey.TruncatedExchange(&response.HandshakeInfo.UserKey, 1) // TODO: receive m as param?
	if err != nil {
		return nil, err
	}

	url = strings.TrimPrefix(url, parsed[0])
	if url == "" { // <message> is empty
		if response.ValidateAuthCode(response.HandshakeInfo.MsgTagPrefix) != true {
			return nil, ErrIncorrectTag
		}
		return &response, nil
	}
	if url[len(url)-1] == '/' { // check last slash
		url = strings.TrimSuffix(url, "/")
		hostAndAction := strings.SplitN(url, "/", 2)

		msg, err := parseMsg(hostAndAction)
		if err != nil {
			return nil, err
		}
		response.Msg = *msg

		if response.ValidateAuthCode(response.HandshakeInfo.MsgTagPrefix) != true {
			return nil, ErrIncorrectTag
		}
		return &response, nil
	} else {
		return nil, ErrInvalidURLFormat
	}
}

// Returns the parsed version of the URL format version. Returns ErrVersionNotSupported error,
// if the parsed version is not supported.
func parseVersion(v string) (byte, error) {
	num, _ := strconv.Atoi(v[1:])
	if num != 1 { // current version
		return 0, ErrVersionNotSupported
	}

	return byte(num), nil
}

// Returns the parsed version of the URL handshake.
// The handshake should satisfy the following format:
//		glome-handshake := base64url(
//    		<prefix-type>
//    		<prefix7>
//    		<eph-key>
//    		[<prefixN>]
//  	).
func parseHandshake(handshake string) (*Handshake, error) {
	dHandshake, err := base64.URLEncoding.DecodeString(handshake)
	if err != nil {
		return nil, err
	}
	if len(dHandshake) < minHandshakeLen {
		return nil, ErrInvalidHandshakeLen
	}

	prefix := dHandshake[0]
	if prefix>>7 != 0 { // check prefix-type
		return nil, ErrInvalidPrefixType
	}

	userKey, err := glome.PublicKeyFromSlice(dHandshake[1:minHandshakeLen])
	if err != nil {
		return nil, err
	}

	msgTagPrefix := dHandshake[minHandshakeLen:]
	if len(msgTagPrefix) > glome.MaxTagSize {
		return nil, glome.ErrInvalidTagSize
	}

	return &Handshake{prefix, *userKey, msgTagPrefix}, nil
}

// Returns the parsed version of the URL message.
// The message should satisfy the following format: [<hostid-type>:]<hostid>[/<action>].
func parseMsg(m []string) (*Message, error) {
	var hostIDType, hostID, action string
	u, err := url.QueryUnescape(m[0])
	if err != nil {
		return nil, err
	}

	var host = strings.SplitN(u, ":", 2)
	if len(host) == 2 { // <hostid-type> is present
		hostIDType = host[0]
		hostID = host[1]
	} else {
		hostID = host[0]
	}

	if len(m) == 2 { // <action> is not empty
		action = m[1]
	}

	return &Message{hostIDType, hostID, action}, nil
}
