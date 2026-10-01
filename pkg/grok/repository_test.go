//
// Copyright (c) 2016-2017 Konstanin Ivanov <kostyarin.ivanov@gmail.com>.
// All rights reserved. This program is free software. It comes without
// any warranty, to the extent permitted by applicable law. You can
// redistribute it and/or modify it under the terms of the Do What
// The Fuck You Want To Public License, Version 2, as published by
// Sam Hocevar. See LICENSE file for more details or see below.
//

//
//        DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
//                    Version 2, December 2004
//
// Copyright (C) 2004 Sam Hocevar <sam@hocevar.net>
//
// Everyone is permitted to copy and distribute verbatim or modified
// copies of this license document, and changing it is allowed as long
// as the name is changed.
//
//            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
//   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION
//
//  0. You just DO WHAT THE FUCK YOU WANT TO.
//

package grok

import (
	"io/ioutil"
	fp "path/filepath"
	"testing"
)

const repository = "patterns"

func repoPath(pth string) string {
	return fp.Join(repository, pth)
}

func Test_repository(t *testing.T) {
	fis, err := ioutil.ReadDir(repository)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	h := NewBase()
	for _, fi := range fis {
		t.Log("REPO:", fi.Name())
		err := h.AddFromFile(repoPath(fi.Name()))
		if err != nil {
			t.Error(err)
		}
	}
}

func Test_ngaccess(t *testing.T) {
	h := NewBase()
	err := h.AddFromFile(repoPath("nginx"))
	if err != nil {
		t.Error(err)
	}
	line := `127.0.0.1 - - [28/Jan/2016:14:19:36 +0300] "GET /zero.html HTTP/1.1" 200 398 "-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.111 Safari/537.36"`
	p, err := h.Compile("%{NGINXACCESS}")
	if err != nil {
		t.Error(err)
	}
	mss := p.Parse(line)
	if len(mss) == 0 {
		t.Error("nginx access not matched")
	}
	t.Log(mss)
}
