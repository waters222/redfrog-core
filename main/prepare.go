package main

import (
	"github.com/pkg/errors"
	"github.com/weishi258/go-iptables/iptables"
	"os/exec"
)

const (
	MAX_FILE_DESCRIPTOR = "1048576"
	TABLE_FILTER        = "filter"
	TABlE_NAT           = "nat"
	CHAIN_INPUT         = "INPUT"
	CHAIN_FORWARD       = "FORWARD"
	CHAIN_POSTROUTING   = "POSTROUTING"

	TPROXY_TABLE_NUM = "100"
)

func PrepareGateway(mark string) (err error) {
	if err = IncreaseFileDescriptor(); err != nil {
		return
	}
	if err = enableForward(); err != nil {
		return
	}
	if err = enableRouting(false); err != nil {
		err = errors.Wrap(err, "Enable ipv4 routing failed")
	}
	if err = enableRouting(true); err != nil {
		err = errors.Wrap(err, "Enable ipv6 routing failed")
	}

	if err = addTProxyRouting(mark); err != nil {
		err = errors.Wrap(err, "Enable TProxy failed")
	}
	return
}

func IncreaseFileDescriptor() (err error) {
	cmd := exec.Command("ulimit", "-Hn", MAX_FILE_DESCRIPTOR)
	if err = cmd.Run(); err != nil {
		err = errors.Wrap(err, "Increase hard file descriptor failed")
	}

	cmd = exec.Command("ulimit", "-Sn", MAX_FILE_DESCRIPTOR)
	if err = cmd.Run(); err != nil {
		err = errors.Wrap(err, "Increase soft file descriptor failed")
	}
	return
}

func enableForward() (err error) {
	cmd := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1")
	if err = cmd.Run(); err != nil {
		err = errors.Wrap(err, "Enable ipv4 forward failed")
	}

	cmd = exec.Command("sysctl", "-w", "net.ipv6.conf.all.forwarding=1")
	if err = cmd.Run(); err != nil {
		err = errors.Wrap(err, "Enable ipv6 forward failed")
	}
	return
}

func enableRouting(isIPv6 bool) (err error) {
	var iptble *iptables.IPTables
	if !isIPv6 {
		if iptble, err = iptables.New(); err != nil {
			return err
		}
	} else {
		if iptble, err = iptables.NewWithProtocol(iptables.ProtocolIPv6); err != nil {
			return err
		}
	}

	if err = iptble.FlushChain(TABLE_FILTER, CHAIN_INPUT); err != nil {
		return
	}
	if err = iptble.Append(TABLE_FILTER, CHAIN_INPUT, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"); err != nil {
		return
	}
	if err = iptble.Append(TABLE_FILTER, CHAIN_INPUT, "-p", "udp", "--dport", "53", "-j", "ACCEPT"); err != nil {
		return
	}

	if err = iptble.FlushChain(TABLE_FILTER, CHAIN_FORWARD); err != nil {
		return
	}
	if err = iptble.Append(TABLE_FILTER, CHAIN_FORWARD, "-j", "ACCEPT"); err != nil {
		return
	}
	if err = iptble.Append(TABLE_FILTER, CHAIN_FORWARD, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"); err != nil {
		return
	}

	if err = iptble.FlushChain(TABlE_NAT, CHAIN_POSTROUTING); err != nil {
		return
	}
	if err = iptble.Append(TABlE_NAT, CHAIN_POSTROUTING, "-j", "MASQUERADE"); err != nil {
		return
	}

	return nil
}

func addTProxyRouting(mark string) (err error) {
	cmd := exec.Command("ip", "rule", "list", "fwmark", mark, "lookup", TPROXY_TABLE_NUM)
	var response []byte
	if response, err = cmd.Output(); err != nil {
		return
	}
	if len(response) == 0 {
		// need to add new
		cmd = exec.Command("ip", "rule", "add", "fwmark", mark, "lookup", TPROXY_TABLE_NUM)
		if err = cmd.Run(); err != nil {
			return
		}
	}

	cmd = exec.Command("ip", "route", "0.0.0.0/0", "dev", "lo", "table", TPROXY_TABLE_NUM)
	if response, err = cmd.Output(); err != nil {
		return
	}
	if len(response) == 0 {
		// need to add new
		cmd = exec.Command("ip", "route", "replace", "local", "0.0.0.0/0", "dev", "lo", "table", TPROXY_TABLE_NUM)
		if err = cmd.Run(); err != nil {
			return
		}
	}

	return
}
