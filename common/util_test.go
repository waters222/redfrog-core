package common

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"
)

func TestPipeCommand(t *testing.T) {
	if output, err := PipeCommand(exec.Command("printf", "nameserver 127.0.0.1\nnameserver 8.8.8.8\nnothing haha\n"),
		exec.Command("grep", "-i", "^nameserver"),
		exec.Command("head", "-n5"),
		exec.Command("cut", "-d", " ", "-f2")); err != nil {
		t.Errorf("Pipe command failed: %s", err.Error())
		t.Fail()
	} else {
		if len(output) == 0 {
			t.Errorf("Output is empty")
			t.Fail()
		}
		t.Logf("output is:\n%s", output)
	}
}

func TestExtractAddr(t *testing.T) {
	servers := []string{"127.0.0.1", "8.8.8.8"}

	serversBytes := []byte(strings.Join(servers, "\n"))
	stubs := bytes.Split(serversBytes, []byte{'\n'})

	for i, stub := range stubs {
		if len(stub) > 0 {
			stub = bytes.TrimSpace(stub)
			if string(stub[:]) != servers[i] {
				t.Fail()
			}
		}
	}
}

func TestExtractAddrExtraLine(t *testing.T) {
	servers := []string{" 127.0.0.1", " ", "8.8.8.8 "}

	serversBytes := []byte(strings.Join(servers, "\n"))
	stubs := bytes.Split(serversBytes, []byte{'\n'})

	for i, stub := range stubs {
		if len(stub) > 0 {
			stub = bytes.TrimSpace(stub)
			if string(stub[:]) != strings.TrimSpace(servers[i]) {
				t.Logf("Extract addr {%s} != {%s}", stub, servers[i])
				t.Fail()
			}
		}
	}
}
