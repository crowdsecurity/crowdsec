package main

import (
	"net"
	"net/http"
	"net/http/pprof"
	"strconv"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
)

// servePprof exposes the Go pprof profiling endpoints on their own listener.
// pprof is enabled by default but bound to 127.0.0.1 (see the csconfig
// defaults), so profiling data stays available for "cscli support dump" and
// ad-hoc debugging without being reachable from the network unless the
// operator explicitly changes pprof.listen_addr.
func servePprof(config *csconfig.PProfCfg) {
	if config == nil || config.Enabled == nil || !*config.Enabled {
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	addr := net.JoinHostPort(config.ListenAddr, strconv.Itoa(config.ListenPort))
	log.Infof("Serving pprof on %s", addr)

	if err := http.ListenAndServe(addr, mux); err != nil {
		log.WithError(err).Warning("serving pprof")
	}
}
