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
	"bytes"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"os/exec"
	"strings"

	"../../../../glome"
	"../../../server"

	lua "github.com/Shopify/go-lua"
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

func executeBinary(path string) server.AuthorizerFunc {
	return server.AuthorizerFunc(func(user string, hostID string, hostIDType string, action string) (bool, error) {
		p, err := exec.LookPath(path)
		if err != nil {
			log.Fatalf("Could not find binary in %#v", path)
		}

		cmd := exec.Command(p, user, hostID, hostIDType, action)
		cmd.Stdin = strings.NewReader("")

		var out bytes.Buffer
		cmd.Stdout = &out

		err = cmd.Run()
		if err != nil {
			log.Fatal(err)
		}

		if out.String() == "1" {
			return true, nil
		} else {
			return false, nil
		}
	})
}
