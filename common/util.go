package common

import (
	"fmt"
	"github.com/pkg/errors"
	"io"
	"io/ioutil"
	"os/exec"
	"strings"
)

func GenerateDomainStubs(domain string) []string {
	if len(domain) == 0 {
		return nil
	}
	stubs := strings.Split(domain, ".")
	{
		segs := make([]string, 0)
		for _, stub := range stubs {
			if len(stub) > 0 {
				segs = append(segs, stub)
			}
		}
		stubs = segs
	}

	len := len(stubs)
	for i := len - 2; i >= 0; i-- {
		stubs[i] = fmt.Sprintf("%s.%s", stubs[i], stubs[i+1])
	}
	return stubs
}


func PipeCommand(cmds... *exec.Cmd) (output []byte, err error){

	length := len(cmds)

	if length == 0{
		err = errors.New("No command to exec")
		return
	}
	preCmd := cmds[0]
	for i := 1; i < length ; i++{
		cmd := cmds[i]
		if cmd.Stdin, err = preCmd.StdoutPipe(); err != nil{
			return
		}
		if err = preCmd.Start(); err != nil{
			return
		}
		preCmd = cmd
	}
	var finalOut io.ReadCloser
	if finalOut, err = preCmd.StdoutPipe(); err != nil{
		return
	}
	if err = preCmd.Start(); err != nil{
		return
	}

	output, err = ioutil.ReadAll(finalOut)

	for i := 0; i < length; i++{
		if err = cmds[i].Wait(); err != nil{
			return
		}
	}


	return
}