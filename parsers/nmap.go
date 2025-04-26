package parsers

import (
	"fmt"
	"io"
	"slices"

	"github.com/shelld3v/aquatone/core"

	"github.com/lair-framework/go-nmap"
)

type NmapParser struct{}

func NewNmapParser() *NmapParser {
	return &NmapParser{}
}

func (p *NmapParser) Parse(r io.Reader, allowedPorts []int) ([]string, error) {
	var targets []string
	bytes, err := io.ReadAll(r)
	if err != nil {
		return targets, nil
	}
	scan, err := nmap.Parse(bytes)

	if err != nil {
		return targets, nil
	}

	for _, host := range scan.Hosts {
        var openAllowedPorts []nmap.Port
		for _, port := range host.Ports {
			if port.State.State == "open" && slices.Contains(allowedPorts, port.PortId) {
                openAllowedPorts = append(openAllowedPorts, port)
			}
		}

        if len(openAllowedPorts) > 0 {
            urls := p.hostToURLs(host, openAllowedPorts)
            targets = append(targets, urls...)
        }
	}

	return targets, nil
}

func (p *NmapParser) hostToURLs(host nmap.Host, ports []nmap.Port) []string {
	var urls []string
	for _, port := range ports {
		var protocol string
		if port.Protocol == "tcp" {
			if port.Service.Tunnel == "ssl" || port.Service.Name == "https" {
				protocol = "https"
			} else {
				protocol = "http"
			}
		} else {
			continue
		}

		if len(host.Hostnames) > 0 {
			for _, hostname := range host.Hostnames {
				urls = append(urls, core.HostAndPortToURL(hostname.Name, port.PortId, protocol))
			}
		}
		for _, address := range host.Addresses {
			if address.AddrType == "mac" {
				continue
			}
			urls = append(urls, core.HostAndPortToURL(address.Addr, port.PortId, protocol))
		}
	}

	return urls
}
