package network

import "testing"

func TestParseIPv4(t *testing.T) {
	if socketAddr, err := ParseIPv4("192.168.0.1:100"); err != nil {
		t.Errorf("Parse ipv4 failed %s", err.Error())
	} else {
		t.Logf("Parse ipv4 successful, %v:%d", socketAddr.Addr, socketAddr.Port)
	}
}

func TestParseIPv6(t *testing.T) {
	if socketAddr, err := ParseIPv6("[2001:db8:1f70::999:de8:7648:6e8]:100"); err != nil {
		t.Errorf("Parse ipv6 failed %s", err.Error())
	} else {
		t.Logf("Parse ipv6 successful, %v:%d", socketAddr.Addr, socketAddr.Port)
	}
}
