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

package cmd

import (
	"encoding/hex"
	"io/ioutil"
	"log"

	"../../../server"

	lua "github.com/Shopify/go-lua"
	"github.com/google/glome/go/glome"
	"gopkg.in/yaml.v2"
)

func decodeString(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		log.Fatalf(err.Error())
	}
	return b
}

// yamlkey is an auxiliary type for communication with go-yaml library.
type yamlkey struct {
	Key   string
	Index uint8
}

// readKeys reads keys from provided package
func readKeys(filename string) map[string]yamlkey {
	yamlFile, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatalf("Error loading key file: %v", err.Error())
	}

	keys := make(map[string]yamlkey)
	err = yaml.Unmarshal([]byte(yamlFile), &keys)
	if err != nil {
		log.Fatalf("Error reading key file: %v", err.Error())
	}

	return keys
}

// updateKeys update the keys read by readKeys
func updateKeys(unformatedKeys map[string]yamlkey, b *server.LoginServer) {
	var formatedKeys []server.PrivateKey
	for _, k := range unformatedKeys {
		p, err := glome.PrivateKeyFromSlice(decodeString(k.Key))
		if err != nil {
			log.Fatalf(err.Error())
		}
		formatedKeys = append(formatedKeys, server.PrivateKey{Value: *p, Index: k.Index})
	}
	b.Keys.DropAllReplace(formatedKeys)
}

func openLua(filename string) server.AuthorizerFunc {
	return server.AuthorizerFunc(func(user string, hostID string, hostIDType string, action string) bool {
		L := lua.NewState()

		lua.OpenLibraries(L)
		if err := lua.DoFile(L, filename); err != nil {
			log.Fatalf("Error loading file: %s", err)
		}

		L.Global("auth")
		defer L.Remove(-1)

		if !L.IsFunction(-1) {
			log.Fatalf("Provided file %v does not contains function auth", filename)
		}

		L.PushString(user)
		L.PushString(hostID)
		L.PushString(hostIDType)
		L.PushString(action)
		if err := L.ProtectedCall(4, 1, 0); err != nil {
			log.Fatalf("Lua error in auth function: %#v\n", err)
		}

		result := L.ToBoolean(-1)
		return result
	})
}
