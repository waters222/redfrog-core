package common

import (
	"fmt"
	"strings"
)

func GenerateDomainStubs(domain string) []string{
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
