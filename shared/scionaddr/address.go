// Package scionaddr parses the dependency-free SCION addresses exchanged by clients and management.
package scionaddr

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

const maxAddressLength = 256

// Address is a canonical SCION ISD-AS and UDP host address.
type Address struct {
	IA   string
	Host netip.AddrPort
}

// Parse validates and canonicalizes an address in ISD-AS,[IP]:port form.
func Parse(value string) (Address, error) {
	if value == "" || len(value) > maxAddressLength {
		return Address{}, fmt.Errorf("SCION address length must be between 1 and %d bytes", maxAddressLength)
	}
	iaText, hostText, ok := strings.Cut(value, ",")
	if !ok || strings.Contains(hostText, ",") {
		return Address{}, fmt.Errorf("SCION address must contain one comma")
	}
	ia, err := parseIA(iaText)
	if err != nil {
		return Address{}, err
	}
	if !strings.HasPrefix(hostText, "[") {
		return Address{}, fmt.Errorf("SCION host IP must be bracketed")
	}
	end := strings.LastIndex(hostText, "]:")
	if end < 0 {
		return Address{}, fmt.Errorf("invalid SCION host")
	}
	ip, err := netip.ParseAddr(hostText[1:end])
	if err != nil {
		return Address{}, fmt.Errorf("invalid SCION host IP: %w", err)
	}
	port, err := strconv.ParseUint(hostText[end+2:], 10, 16)
	if err != nil || port == 0 {
		return Address{}, fmt.Errorf("invalid SCION host port")
	}
	if ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() {
		return Address{}, fmt.Errorf("invalid SCION host address")
	}
	return Address{IA: ia, Host: netip.AddrPortFrom(ip.Unmap(), uint16(port))}, nil
}

func parseIA(value string) (string, error) {
	isdText, asText, ok := strings.Cut(value, "-")
	if !ok || isdText == "" || asText == "" || strings.Contains(asText, "-") {
		return "", fmt.Errorf("invalid SCION IA")
	}
	isd, err := strconv.ParseUint(isdText, 10, 16)
	if err != nil {
		return "", fmt.Errorf("invalid SCION ISD: %w", err)
	}
	if strings.Contains(asText, ":") {
		parts := strings.Split(asText, ":")
		if len(parts) != 3 {
			return "", fmt.Errorf("SCION AS must have three hexadecimal components")
		}
		canonical := make([]string, 3)
		for i, part := range parts {
			if part == "" || len(part) > 4 {
				return "", fmt.Errorf("invalid SCION AS component")
			}
			v, err := strconv.ParseUint(part, 16, 16)
			if err != nil {
				return "", fmt.Errorf("invalid SCION AS component: %w", err)
			}
			canonical[i] = strconv.FormatUint(v, 16)
		}
		return strconv.FormatUint(isd, 10) + "-" + strings.Join(canonical, ":"), nil
	}
	as, err := strconv.ParseUint(asText, 10, 32)
	if err != nil {
		return "", fmt.Errorf("invalid SCION AS: %w", err)
	}
	return strconv.FormatUint(isd, 10) + "-" + strconv.FormatUint(as, 10), nil
}

func (a Address) String() string {
	return fmt.Sprintf("%s,[%s]:%d", a.IA, a.Host.Addr().Unmap(), a.Host.Port())
}
