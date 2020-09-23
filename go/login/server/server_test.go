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

package server

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http/httptest"
	"testing"

	"github.com/google/glome/go/glome"
)

type testVector struct {
	kbp         []byte
	index       uint8
	ka          []byte
	Request     string
	Response    string
	ResponseLen uint8
}

func (t *testVector) SeverKey() glome.PrivateKey {
	p, err := glome.PrivateKeyFromSlice(t.kbp)
	if err != nil {
		panic(fmt.Sprintf("Glome rejected %v:%#v", t.kbp, err))
	}
	return *p
}

func (t testVector) ClientKey() glome.PublicKey {
	p, err := glome.PublicKeyFromSlice(t.ka)
	if err != nil {
		panic(fmt.Sprintf("Glome rejected %v:%#v", t.ka, err))
	}
	return *p
}

func decodeString(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(fmt.Sprintf("Invalid hexadecimal string %v input in test", s))
	}
	return b
}

func serverTests() map[string]testVector {
	return map[string]testVector{
		"test vector 1": {
			kbp:         decodeString("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"),
			index:       1,
			Request:     "/v1/AYUg8AmJMKdUdIt93LQ-91oNvzoNJjga9OukqY6qm05q0PU=/my-server.local/shell/root/",
			Response:    "lyHuaHuCck\n",
			ResponseLen: 10,
		},
		"test vector 2": {
			kbp:         decodeString("b105f00db105f00db105f00db105f00db105f00db105f00db105f00db105f00d"),
			index:       0x51,
			Request:     "/v1/UYcvQ1u4uJ0OOtYqouURB07hleHDnvaogAFBi-ZW48N2/serial-number:1234567890=ABCDFGH%2F%23%3F/reboot/",
			Response:    "p8M_BUKj7zXBVM2JlQhNYFxs4J-DzxRAps83ZaNDquY=\n",
			ResponseLen: MaxResponseSize,
		},
	}
}

func auth(user string, hostID string, hostIDType string, action string) (bool, error) {
	return true, nil
}

func TestServer(t *testing.T) {
	for name, tv := range serverTests() {
		name := name
		tv := tv

		t.Run(name, func(t *testing.T) {
			// for _, k := range []struct {
			// 	in   bool
			// 	want bool
			// }{
			// 	{in: true, o: b},
			// } {
			r := httptest.NewRequest("GET", tv.Request, nil)
			w := httptest.NewRecorder()

			login, err := NewLoginServer(AuthorizerFunc(auth), ResponseLen(tv.ResponseLen))
			if err != nil {
				t.Fatalf("test %v, unexpected error: %v ", name, err.Error())
			}

			login.Keys.Add(tv.SeverKey(), tv.index)

			login.ServeHTTP(w, r)

			resp := w.Result()
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("test %v, unexpected error: %v ", name, err.Error())
			}
			if string(body) != tv.Response {
				t.Errorf("test $v, got %#v, want %#v", string(body), tv.Response)
			}
			// Everything working - now its time to use whatever w has stored
		})
	}
}
