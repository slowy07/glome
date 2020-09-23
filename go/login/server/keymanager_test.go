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
	"reflect"
	"testing"

	"github.com/google/glome/go/glome"
)

func tests() map[string]*KeyManager {
	k := map[string]*KeyManager{
		"empty":   NewKeyManager(),
		"DropAll": NewKeyManager(),
		"Add":     NewKeyManager(),
	}

	k["DropAll"].DropAllReplace(
		[]PrivateKey{
			PrivateKey{
				Value: glome.PrivateKey([32]byte{49, 244, 125, 133, 0, 40, 7,
					192, 7, 90, 5, 208, 234, 104, 66, 68, 251, 237, 187, 132,
					67, 236, 108, 164, 162, 199, 41, 89, 128, 95, 26, 190}),
				Index: 122,
			},
			PrivateKey{
				Value: glome.PrivateKey([32]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
					1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
					1, 1}),
				Index: 123,
			},
		})

	k["Add"].Add(glome.PrivateKey([32]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1}), 123)

	return k
}

func Contains(list []PublicKey, pub PublicKey) bool {
	for _, b := range list {
		if b == pub {
			return true
		}
	}
	return false
}

func TestKeyAdd(t *testing.T) {
	for name, manager := range tests() {
		name := name
		manager := manager

		t.Run(name, func(t *testing.T) {
			for _, k := range []struct {
				priv  glome.PrivateKey
				index uint8
			}{
				{
					priv:  glome.PrivateKey([32]byte{}),
					index: 0,
				}, {
					priv: glome.PrivateKey([32]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
						1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
						1, 1}),
					index: 12,
				}, {
					priv: glome.PrivateKey([32]byte{49, 244, 125, 133, 0, 40, 7,
						192, 7, 90, 5, 208, 234, 104, 66, 68, 251, 237, 187, 132,
						67, 236, 108, 164, 162, 199, 41, 89, 128, 95, 26, 190}),
					index: 23,
				},
			} {
				if err := manager.Add(k.priv, k.index); err != nil {
					t.Fatalf("test %v, unexpected error: %v ", name, err.Error())
				}

				if manager.indexToPriv[k.index] != k.priv {
					t.Errorf("test %v: private key %v was not added in index %v",
						name, k.priv, k.index)
				}

				pub, err := k.priv.Public()
				if err != nil {
					t.Fatalf("test %v, unexpected error: %v ", name, err.Error())
				}

				if !Contains(manager.publicKeys, PublicKey{Value: *pub, Index: k.index}) {
					t.Errorf("test %v: public key %v was not added in index %v",
						name, pub, k.index)
				}
			}
		})
	}
}

func TestKeyAddExceptions(t *testing.T) {
	for name, manager := range tests() {
		name := name
		manager := manager

		type input struct {
			priv  glome.PrivateKey
			index uint8
		}

		t.Run(name, func(t *testing.T) {
			for _, k := range []struct {
				in   input
				want error
			}{
				{in: input{priv: glome.PrivateKey([32]byte{}), index: 0}, want: nil},
				{in: input{priv: glome.PrivateKey([32]byte{}), index: 0}, want: ErrOverloadedIndex{index: 0}},
				{in: input{priv: glome.PrivateKey([32]byte{}), index: 129}, want: ErrInvalidIndex{index: 129}},
			} {
				if err := manager.Add(k.in.priv, k.in.index); err != k.want {
					t.Errorf("%v failed; got %#v, want %#v", name, err, k.want)
				}
			}
		})
	}
}

func TestKeyRead(t *testing.T) {
	for name, manager := range tests() {
		name := name
		manager := manager

		type input struct {
			priv  glome.PrivateKey
			index uint8
		}
		type output struct {
			priv  glome.PrivateKey
			found bool
		}

		t.Run(name, func(t *testing.T) {
			for _, k := range []struct {
				in   input
				want output
			}{
				{
					in:   input{priv: glome.PrivateKey([32]byte{}), index: 0},
					want: output{priv: glome.PrivateKey([32]byte{}), found: true},
				}, {
					in: input{
						priv: glome.PrivateKey([32]byte{49, 244, 125, 133, 0, 40, 7,
							192, 7, 90, 5, 208, 234, 104, 66, 68, 251, 237, 187, 132,
							67, 236, 108, 164, 162, 199, 41, 89, 128, 95, 26, 190}),
						index: 111,
					},
					want: output{
						priv: glome.PrivateKey([32]byte{49, 244, 125, 133, 0, 40, 7,
							192, 7, 90, 5, 208, 234, 104, 66, 68, 251, 237, 187, 132,
							67, 236, 108, 164, 162, 199, 41, 89, 128, 95, 26, 190}),
						found: true,
					},
				},
			} {
				if _, found := manager.Read(k.in.index); found {
					t.Errorf("%v failed; found key on index %v", name, k.in.index)
				}
				if err := manager.Add(k.in.priv, k.in.index); err != nil {
					t.Fatalf("test %v, unexpected error: %v ", name, err.Error())
				}
				if key, found := manager.Read(k.in.index); key != k.want.priv || found != k.want.found {
					t.Errorf("%v failed; want %v, got %v,%v", name, k.want, key, found)
				}
			}
		})
	}
}

func TestDropAllReplace(t *testing.T) {
	for name, manager := range tests() {
		name := name
		manager := manager

		t.Run(name, func(t *testing.T) {
			for _, k := range []struct {
				in   []PrivateKey
				want map[uint8]glome.PrivateKey
			}{
				{
					in: []PrivateKey{
						PrivateKey{Value: glome.PrivateKey([32]byte{}), Index: 0},
						PrivateKey{
							Value: glome.PrivateKey([32]byte{49, 244, 125, 133, 0, 40, 7,
								192, 7, 90, 5, 208, 234, 104, 66, 68, 251, 237, 187, 132,
								67, 236, 108, 164, 162, 199, 41, 89, 128, 95, 26, 190}),
							Index: 1,
						},
					},
					want: map[uint8]glome.PrivateKey{
						0: glome.PrivateKey([32]byte{}),
						1: glome.PrivateKey([32]byte{49, 244, 125, 133, 0, 40, 7,
							192, 7, 90, 5, 208, 234, 104, 66, 68, 251, 237, 187, 132,
							67, 236, 108, 164, 162, 199, 41, 89, 128, 95, 26, 190}),
					},
				},
			} {
				manager.DropAllReplace(k.in)
				if !reflect.DeepEqual(manager.indexToPriv, k.want) {
					t.Errorf("%v failed; got %#v, want %#v", name, manager.indexToPriv, k.want)
				}
			}
		})
	}

}
