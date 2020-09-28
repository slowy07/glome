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
	"encoding/hex"
	"fmt"
	"strconv"
	"testing"

	"github.com/google/glome/go/glome"
)

const (
	tvsCnt = 2
)

var serviceKeyIds = []uint8{1, 0}

func handleError(e error, t *testing.T) {
	if e != nil {
		t.Fatalf("Unexpected Error: " + e.Error())
	}
}

type testVector struct {
	kap        []byte
	ka         []byte
	kbp        []byte
	kb         []byte
	ks         []byte
	prefix     byte
	hostIdType string
	hostId     string
	action     string
	msg        []byte
	url        string
	prefixN    []byte
	tag        []byte
	token      string
}

type KeyPair struct {
	priv glome.PrivateKey
	pub  glome.PublicKey
}

func decodeString(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(fmt.Sprintf("Invalid hexadecimal string %v input in test", s))
	}
	return b
}

func keys(t *testing.T, kp []byte, k []byte) *KeyPair {
	aPriv, err := glome.PrivateKeyFromSlice(kp)
	handleError(err, t)
	aPub, err := glome.PublicKeyFromSlice(k)
	handleError(err, t)
	return &KeyPair{*aPriv, *aPub}
}

func (tv *testVector) Dialog(t *testing.T) (*glome.Dialog, *glome.Dialog) {
	clientKP := keys(t, tv.kap, tv.ka)
	serverKP := keys(t, tv.kbp, tv.kb)

	sending, err := clientKP.priv.Exchange(&serverKP.pub)
	handleError(err, t)
	receiving, err := serverKP.priv.Exchange(&clientKP.pub)
	handleError(err, t)

	return sending, receiving
}

func testVectors() []testVector {
	prefix1, _ := strconv.Atoi("1")
	prefix2, _ := strconv.Atoi("0x51")

	return []testVector{
		{
			kap:        decodeString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"),
			ka:         decodeString("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"),
			kbp:        decodeString("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"),
			kb:         decodeString("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"),
			ks:         decodeString("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"),
			prefix:     byte(prefix1),
			hostIdType: "",
			hostId:     "my-server.local",
			action:     "shell/root",
			msg:        []byte("my-server.local/shell/root"),
			url:        "/v1/AYUg8AmJMKdUdIt93LQ-91oNvzoNJjga9OukqY6qm05q0PU=/my-server.local/shell/root/",
			prefixN:    decodeString("d0f59d0b17cb155a1b9cd2b5cdea3a17f37a200e95e3651af2c88e1c5fc8108e"),
			tag:        decodeString("9c44389f462d35d0672faf73a5e118f8b9f5c340bbe8d340e2b947c205ea4fa3"),
			token:      "lyHuaHuCck",
		},

		{
			kap:        decodeString("b105f00db105f00db105f00db105f00db105f00db105f00db105f00db105f00d"),
			ka:         decodeString("d1b6941bba120bcd131f335da15778d9c68dadd398ae61cf8e7d94484ee65647"),
			kbp:        decodeString("fee1deadfee1deadfee1deadfee1deadfee1deadfee1deadfee1deadfee1dead"),
			kb:         decodeString("872f435bb8b89d0e3ad62aa2e511074ee195e1c39ef6a88001418be656e3c376"),
			ks:         decodeString("4b1ee05fcd2ae53ebe4c9ec94915cb057109389a2aa415f26986bddebf379d67"),
			prefix:     byte(prefix2),
			hostIdType: "serial-number",
			hostId:     "1234567890=ABCDFGH/#?",
			action:     "reboot",
			msg:        []byte("serial-number:1234567890=ABCDFGH/#?/reboot"),
			url:        "/v1/UYcvQ1u4uJ0OOtYqouURB07hleHDnvaogAFBi-ZW48N2/serial-number:1234567890=ABCDFGH%2F%23%3F/reboot/",
			prefixN:    decodeString("dff5aae753a8bdce06038a20adcdb26c7be19cb6bd05a7850fae542f4af29720"),
			tag:        decodeString("06476f1f314b06c7f96e5dc62b2308268cbdb6140aefeeb55940731863032277"),
			token:      "p8M_BUKj7zXBVM2JlQhNYFxs4J-DzxRAps83ZaNDquY=",
		},
	}
}

func ClientsAndServers(t *testing.T) ([]Client, []Server) {
	tvs := testVectors()
	var keyPairs [tvsCnt][]KeyPair
	for i, tv := range tvs {
		keyPairs[i] = append(keyPairs[i], *keys(t, tv.kap, tv.ka), *keys(t, tv.kbp, tv.kb))
	}

	var clients []Client
	var servers []Server
	for tv := 0; tv < tvsCnt; tv++ {
		clients = append(clients, *NewClient(keyPairs[tv][1].pub, keyPairs[tv][0].priv, serviceKeyIds[tv]))
		sPrivKey := keyPairs[tv][1].priv
		servers = append(servers,
			Server{func(u uint8) (glome.PrivateKey, error) {
				return sPrivKey, nil
			}})
	}
	return clients, servers
}

func TestCheckCorrectURLs(t *testing.T) {
	_, servers := ClientsAndServers(t)
	var responses []URLResponse
	tvs := testVectors()

	for i, tv := range tvs {
		t.Run("Test vector "+fmt.Sprint(i+1), func(t *testing.T) {
			resp, err := servers[i].ParseURLResponse(tv.url)
			if err != nil {
				t.Fatalf("TestCheckCorrectURLs failed for test vector %d. Expected: parsed URL, got: %v", i, err)
			}

			responses = append(responses, *resp)
		})
	}

	for i, tv := range tvs {
		t.Run("Test vector "+fmt.Sprint(i+1), func(t *testing.T) {
			for _, k := range []struct {
				expected string
				got      string
			}{
				{expected: tv.hostIdType, got: responses[i].Msg.HostIDType},
				{expected: tv.hostId, got: responses[i].Msg.HostID},
				{expected: tv.action, got: responses[i].Msg.Action},
			} {
				if k.expected != k.got {
					t.Fatalf("TestCheckCorrectURLs failed for test vector %d. Expected: %v, got: %v", i, k.expected, k.got)
				}
			}
		})
	}
}
