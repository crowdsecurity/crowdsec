// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build windows

package main

import (
	"fmt"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
)

type crowdsec_winservice struct {
	config *csconfig.Config
}

func (m *crowdsec_winservice) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}
	tick := time.Tick(500 * time.Millisecond)
	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	go func() {
	loop:
		for {
			select {
			case <-tick:

			case c := <-r:
				switch c.Cmd {
				case svc.Interrogate:
					changes <- c.CurrentStatus
				case svc.Stop, svc.Shutdown:
					changes <- svc.Status{State: svc.StopPending}
					err := shutdown(nil, m.config)
					if err != nil {
						log.Errorf("Error while shutting down: %s", err)
						// don't return, we still want to notify windows that we are stopped ?
					}
					break loop
				default:
					log.Errorf("unexpected control request #%d", c)
				}
			}
		}
	}()

	err := WindowsRun()
	changes <- svc.Status{State: svc.Stopped}
	if err != nil {
		log.Fatal(err)
	}
	return
}

func runService(name string) error {
	// All the calls to logging before the logger is configured are pretty much useless, but we keep them for clarity
	err := eventlog.InstallAsEventCreate("CrowdSec", eventlog.Error|eventlog.Warning|eventlog.Info)
	if err != nil {
		if errno, ok := err.(syscall.Errno); ok {
			if errno == windows.ERROR_ACCESS_DENIED {
				log.Warnf("Access denied when installing event source, running as non-admin ?")
			} else {
				log.Warnf("Failed to install event log: %s (%d)", err, errno)
			}
		} else {
			log.Warnf("Failed to install event log: %s", err)
		}
	}

	// Let's use our source even if we could not install it:
	// - It could have been created earlier
	// - No permission to create it (e.g. running as non-admin when working on crowdsec)
	// It will still work, windows will just display some additional errors in the event log
	evtlog, err := eventlog.Open("CrowdSec")

	if err == nil {
		// Send panic and fatal to event log, as they can happen before the logger is configured.
		log.AddHook(&EventLogHook{
			LogLevels: []log.Level{
				log.PanicLevel,
				log.FatalLevel,
			},
			evtlog: evtlog,
		})
	} else {
		log.Warnf("Failed to open event log: %s", err)
	}

	cConfig, err := LoadConfig(flags.ConfigFile, flags.DisableAgent, flags.DisableAPI, false)
	if err != nil {
		return err
	}

	log.Infof("starting %s service", name)
	winsvc := crowdsec_winservice{config: cConfig}

	if err := svc.Run(name, &winsvc); err != nil {
		return fmt.Errorf("%s service failed: %w", name, err)
	}

	log.Infof("%s service stopped", name)
	return nil
}
