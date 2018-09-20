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
	//if err = IncreaseFileDescriptor(); err != nil {
	//	return
	//}
	//if err = enableForward(); err != nil {
	//	return
	//}
	//if err = enableRouting(interfaceIn, interfaceOut, false); err != nil {
	//	err = errors.Wrap(err, "Enable ipv4 routing failed")
	//}
	//if err = enableRouting(interfaceIn, interfaceOut, true); err != nil {
	//	err = errors.Wrap(err, "Enable ipv6 routing failed")
	//}

	if err = addTProxyRoutingIPv4(mark); err != nil {
		err = errors.Wrap(err, "Enable TProxy failed")
	}
	if err = addTProxyRoutingIPv6(mark); err != nil {
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

func enableRouting(interfaceIn string, interfaceOut string, isIPv6 bool) (err error) {
	var iptble *iptables.IPTables
	if !isIPv6{
		if iptble, err = iptables.New(); err != nil{
			return err
		}
	}else{
		if iptble, err = iptables.NewWithProtocol(iptables.ProtocolIPv6); err != nil{
			return err
		}
	}

	if err = iptble.FlushChain(TABLE_FILTER, CHAIN_INPUT); err != nil{
		return
	}
	if err = iptble.Append(TABLE_FILTER, CHAIN_INPUT, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"); err != nil{
		return
	}
	if err = iptble.Append(TABLE_FILTER, CHAIN_INPUT, "-i", interfaceIn, "-p", "udp", "--dport", "53", "-j", "ACCEPT"); err != nil{
		return
	}

	if err = iptble.FlushChain(TABLE_FILTER, CHAIN_FORWARD); err != nil{
		return
	}
	if err = iptble.Append(TABLE_FILTER, CHAIN_FORWARD, "-i", interfaceIn, "-o", interfaceOut, "-j", "ACCEPT"); err != nil{
		return
	}
	if err = iptble.Append(TABLE_FILTER, CHAIN_FORWARD, "-i", interfaceOut, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"); err != nil{
		return
	}


	if err = iptble.FlushChain(TABlE_NAT, CHAIN_POSTROUTING); err != nil{
		return
	}
	if err = iptble.Append(TABlE_NAT, CHAIN_POSTROUTING,  "-o", interfaceOut, "-j", "MASQUERADE"); err != nil{
		return
	}


	return nil
}

