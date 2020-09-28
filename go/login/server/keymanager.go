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
	"fmt"
	"sync"

	"../../glome"
)

// ErrInvalidKeyIndex denotes that provided index is invalid for a key. Only
// indexes in range 0-127 are valid.
type ErrInvalidKeyIndex struct {
	Index uint8
}

func (e ErrInvalidKeyIndex) Error() string {
	return fmt.Sprintf("key index should be in range 0-127, found: %v", e.Index)
}

// ErrOverloadedKeyIndex denotes that provided index is already in use, so no
// new keys can be assigned to it.
type ErrOverloadedKeyIndex struct {
	Index uint8
}

func (e ErrOverloadedKeyIndex) Error() string {
	return fmt.Sprintf("key index already in use, found: %v", e.Index)
}

// ErrKeyIndexNotFound denotes that an index was not found, so no key can be
// returned from it.
type ErrKeyIndexNotFound struct {
	Index uint8
}

func (e ErrKeyIndexNotFound) Error() string {
	return fmt.Sprintf("key index %v not found", e.Index)
}

// A PrivateKey represent a Private key for the login server. It is a pair composed of a private key
// and its pairing index.
type PrivateKey struct {
	Value glome.PrivateKey
	Index uint8
}

// A PublicKey represent a Service key for the login server. It is a pair composed of a public key
// and its pairing index.
type PublicKey struct {
	Value glome.PublicKey
	Index uint8
}

// KeyManager performs key maneger task in a concurrent-safe way. It allows for constant
// time search of keys by index.
type KeyManager struct {
	indexToPriv map[uint8]glome.PrivateKey
	publicKeys  []PublicKey
	lock        sync.RWMutex
}

func (k *KeyManager) asyncAdd(key glome.PrivateKey, index uint8) error {
	if index > 127 { // Maybe having a constant in the login library to store this (?)
		return ErrInvalidKeyIndex{Index: index}
	}
	if _, ok := k.indexToPriv[index]; ok {
		return ErrOverloadedKeyIndex{Index: index}
	}

	pub, err := key.Public()
	if err != nil {
		return err
	}

	k.indexToPriv[index] = key
	k.publicKeys = append(k.publicKeys, PublicKey{Value: *pub, Index: index})
	return nil
}

// Add adds provided key and index to the key manager. Raises ErrInvalidindex
// if index provided is not in range 0-127 and ErrOverloadedIndex if index
// provided was already in use.
func (k *KeyManager) Add(key glome.PrivateKey, index uint8) error {
	k.lock.Lock()
	defer k.lock.Unlock()
	return k.asyncAdd(key, index)
}

// Read returns the PrivateKey stored in the KeyManager for a index, or a
// zero-value PrivateKey if no PrivateKey is present. The ok result indicates
// whether value was found in the KeyManager.
func (k *KeyManager) Read(index uint8) (glome.PrivateKey, bool) {
	k.lock.RLock()
	defer k.lock.RUnlock()

	key, ok := k.indexToPriv[index]
	return key, ok
}

// DropAllReplace drops all stored keys and replace them with the new ones provided.
// This operation is done in a atomic way (no other call to the struct will be handled
// while DropAllReplace is).
func (k *KeyManager) DropAllReplace(keys []PrivateKey) error {
	k.lock.Lock()
	defer k.lock.Unlock()

	k.indexToPriv = make(map[uint8]glome.PrivateKey)
	k.publicKeys = make([]PublicKey, 0)

	for _, key := range keys {
		if err := k.asyncAdd(key.Value, key.Index); err != nil {
			return err
		}
	}
	return nil
}

// ServiceKeys returns a copy slice of the public Keys being at use at this moment by
// the key manager.
func (k *KeyManager) ServiceKeys() []PublicKey {
	serviceKey := make([]PublicKey, len(k.publicKeys))
	copy(serviceKey, k.publicKeys)
	return serviceKey
}

// Return a function that implements key fetching. This returned function
// returns ErrInvalidKeyIndex if index is not in range 0-127, and ErrIndexNotFound
// if provided index does not match any key.
func (k *KeyManager) keyFetcher() func(uint8) (glome.PrivateKey, error) {
	return func(index uint8) (glome.PrivateKey, error) {
		if !(0 <= index && index <= 127) {
			return glome.PrivateKey{}, ErrInvalidKeyIndex{Index: index}
		}

		key, found := k.Read(index)
		if !found {
			return glome.PrivateKey{}, ErrKeyIndexNotFound{Index: index}
		}

		return key, nil
	}
}

// NewKeyManager returns a new key manager.
func NewKeyManager() *KeyManager {
	return &KeyManager{
		indexToPriv: make(map[uint8]glome.PrivateKey),
		publicKeys:  make([]PublicKey, 0),
	}
}
