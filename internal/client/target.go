package client

import (
	"net"
	"regexp"
	"strconv"

	"github.com/inovacc/sentinel/internal/datadir"
	"github.com/inovacc/sentinel/internal/settings"
)

// deviceIDPattern matches a Syncthing-style device ID: base32 (A-Z, 2-7) groups
// separated by dashes (e.g. ABCDEFGH-IJKLMNOP-...).
var deviceIDPattern = regexp.MustCompile(`^[A-Z2-7]{7,8}(-[A-Z2-7]{4,8}){4,}$`)

// LooksLikeTarget reports whether s is a connection target — a device ID or a
// host:port address — rather than the start of a command or a path. This lets
// the leading argument of client commands be an optional target.
func LooksLikeTarget(s string) bool {
	if deviceIDPattern.MatchString(s) {
		return true
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil || host == "" {
		return false
	}
	_, perr := strconv.Atoi(port) // require a numeric port to avoid matching "npm:run"
	return perr == nil
}

// SplitTarget separates an optional leading target from the remaining args.
// When args[0] is not a target, target is "" (meaning the local daemon) and all
// args are returned as the remainder.
func SplitTarget(args []string) (target string, rest []string) {
	if len(args) > 0 && LooksLikeTarget(args[0]) {
		return args[0], args[1:]
	}
	return "", args
}

// ResolveAddress turns a target into a dialable address:
//
//	""  or "local" -> the local daemon (127.0.0.1:<configured gRPC port>)
//	"host:port"    -> used directly
//	<device-id>    -> looked up in the local fleet registry
func ResolveAddress(target string) (string, error) {
	if target == "" || target == "local" {
		return LocalAddr(), nil
	}
	if _, _, err := net.SplitHostPort(target); err == nil {
		return target, nil
	}
	return ResolveDevice(target, datadir.DBPath())
}

// LocalAddr returns the loopback address of this machine's daemon, using the
// gRPC port from the config (default 7400).
func LocalAddr() string {
	port := "7400"
	if cfg, err := settings.Load(datadir.ConfigPath()); err == nil {
		if _, p, err := net.SplitHostPort(cfg.Listen.GRPC); err == nil && p != "" && p != "0" {
			port = p
		}
	}
	return net.JoinHostPort("127.0.0.1", port)
}
