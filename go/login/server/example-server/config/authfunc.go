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

// This package shows a simple configuration based on the use of sets to
// decide if a user has access to a machine, following some simple rules:
//   - A special user can run functions from the command table in either a special machine or a general machine.
//   - A general user can run functions from the command table only in a general machine.
//   - All other commands are blocked.
package main

import (
	"flag"
	"fmt"
)

var (
	GeneralMachines = Set("my-server.local")
	SpecialMachines = Set("serial-number:1234567890=ABCDFGH/#?")
	GeneralUser     = Set("", "pedro")
	SpecialUser     = Set("admin")
	Commands        = Set("shell/root", "reboot")

	user       string
	hostID     string
	hostIDType string
	action     string
)

// Sugar syntax for set
func Set(strs ...string) map[string]bool {
	set := make(map[string]bool)
	for _, str := range strs {
		set[str] = true
	}
	return set
}

// Authotization Function
// Note that, in the example, empty action is not allowed, but empty user is.
// This means that default user is allow, while default action isn't. It ignores host_id_type
func auth(user string, hostID string, hostIDType string, action string) bool {
	if Commands[action] {
		if SpecialUser[user] && (GeneralMachines[hostID] || SpecialMachines[hostID]) {
			return true
		} else if GeneralUser[user] && GeneralMachines[hostID] {
			return true
		}
	}
	return false
}

// init function initializes flags
func init() {
	flag.StringVar(&user, "u", "", "name of the user to authorize")
	flag.StringVar(&hostID, "h", "", "id of the host to authorize")
	flag.StringVar(&hostIDType, "ht", "", "type of the host to authorize")
	flag.StringVar(&action, "a", "", "action to authorize")
}

func main() {
	if auth(user, hostID, hostIDType, action) {
		fmt.Print("1")
	} else {
		fmt.Print("0")
	}
}
