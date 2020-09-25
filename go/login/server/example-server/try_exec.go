// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"fmt"
	"log"
	"os/exec"
	"strings"
)

func executeBinary(path string) func() string {
	p, err := exec.LookPath(path)
	if err != nil {
		log.Fatalf("Could not find binary in %#v", path)
	}

	cmd := exec.Command(p)
	cmd.Stdin = strings.NewReader("some input")
	var out bytes.Buffer
	cmd.Stdout = &out
	err = cmd.Run()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("in all caps: %q\n", out.String())

	return func() string { return "" }
}

func main() {
	executeBinary("./config/helloworld")
}
