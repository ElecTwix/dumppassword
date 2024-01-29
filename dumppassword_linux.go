//go:build linux

package main

import (
	"fmt"

	"github.com/ElecTwix/dumppassword/pkg/dumper/linux"
	"github.com/ElecTwix/dumppassword/pkg/model/mlogin"
)

func main() {
	var (
		loginDatas []mlogin.LoginData
		err        error
	)
	loginDatas, err = linux.Run()
	if err != nil {
		panic(err)
	}

	for _, login := range loginDatas {
		fmt.Print(login)
	}
}
