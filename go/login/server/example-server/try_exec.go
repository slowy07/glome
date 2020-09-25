// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"os"
	"os/exec"

	"../../server"
)

func executeBinary(path string) func() string {
	path, err := exec.LookPath(path)
	if err != nil {
		log.Fatalf("Could not find binary in %#v", path)
	}

	cmd.exec(path)
	cmd.Stdin = strings.NewReader("some input")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("in all caps: %q\n", out.String())
}

func main() {

}
