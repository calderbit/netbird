//go:build scion && cgo && (linux || darwin) && !android && !ios

package scion

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

const scionDiscoveryName = "_sciondiscovery._tcp"

type dnsBootstrapResolver interface {
	LookupSRV(context.Context, string, string, string) (string, []*net.SRV, error)
	LookupTXT(context.Context, string) ([]string, error)
}

func discoverBootstrapURL(ctx context.Context) (string, error) {
	domain, err := localSearchDomain()
	if err != nil {
		return "", err
	}
	return discoverBootstrapURLForDomain(ctx, net.DefaultResolver, domain)
}

func discoverBootstrapURLForDomain(ctx context.Context, resolver dnsBootstrapResolver, domain string) (string, error) {
	domain = strings.TrimSuffix(strings.TrimSpace(domain), ".")
	if domain == "" {
		return "", fmt.Errorf("no DNS search domain")
	}
	_, records, err := resolver.LookupSRV(ctx, "sciondiscovery", "tcp", domain)
	if err != nil {
		return "", fmt.Errorf("lookup %s.%s: %w", scionDiscoveryName, domain, err)
	}
	if len(records) == 0 {
		return "", fmt.Errorf("lookup %s.%s returned no records", scionDiscoveryName, domain)
	}
	host := strings.TrimSuffix(records[0].Target, ".")
	port := records[0].Port
	if host == "" || port == 0 {
		return "", fmt.Errorf("lookup %s.%s returned invalid target", scionDiscoveryName, domain)
	}
	if txts, txtErr := resolver.LookupTXT(ctx, scionDiscoveryName+"."+domain); txtErr == nil {
		for _, txt := range txts {
			value, ok := strings.CutPrefix(txt, "x-sciondiscovery=")
			if !ok {
				continue
			}
			parsed, parseErr := strconv.ParseUint(value, 10, 16)
			if parseErr == nil && parsed > 0 {
				port = uint16(parsed)
			}
			break
		}
	}
	return "http://" + net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

func localSearchDomain() (string, error) {
	if data, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(strings.SplitN(line, "#", 2)[0])
			if len(fields) >= 2 && (fields[0] == "search" || fields[0] == "domain") {
				return strings.TrimSuffix(fields[1], "."), nil
			}
		}
	}
	hostname, err := os.Hostname()
	if err == nil {
		if _, domain, ok := strings.Cut(hostname, "."); ok && domain != "" {
			return domain, nil
		}
	}
	return "", fmt.Errorf("no DNS search domain")
}
