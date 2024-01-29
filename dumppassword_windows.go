//go:build windows

package main

import (
	"fmt"

	"github.com/ElecTwix/dumppassword/pkg/dumper/windows"
	"github.com/ElecTwix/dumppassword/pkg/model/mlogin"
)

func main() {
	var (
		loginDatas []mlogin.LoginData
		err        error
	)
	loginDatas, err = windows.Run()
	if err != nil {
		panic(err)
	}

	for _, login := range loginDatas {
		fmt.Print(login)
	}
}
