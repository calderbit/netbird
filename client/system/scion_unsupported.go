//go:build !scion || !cgo || (!linux && !darwin) || android || ios

package system

// ScionSupported reports whether this binary contains the SCION transport.
func ScionSupported() bool { return false }
