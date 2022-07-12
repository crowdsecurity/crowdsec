// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build windows
// +build windows

package main

import (
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows/svc"
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
						//don't return, we still want to notify windows that we are stopped ?
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
		log.Fatalf(err.Error())
	}
	return
}

func runService(name string) error {
	cConfig, err := csconfig.NewConfig(flags.ConfigFile, flags.DisableAgent, flags.DisableAPI)
	if err != nil {
		return err
	}

	if err := LoadConfig(cConfig); err != nil {
		return err
	}

	// Configure logging
	if err := types.SetDefaultLoggerConfig(cConfig.Common.LogMedia, cConfig.Common.LogDir, *cConfig.Common.LogLevel,
		cConfig.Common.LogMaxSize, cConfig.Common.LogMaxFiles, cConfig.Common.LogMaxAge, cConfig.Common.CompressLogs, cConfig.Common.ForceColorLogs); err != nil {
		return err
	}

	log.Infof("starting %s service", name)
	winsvc := crowdsec_winservice{config: cConfig}

	if err := svc.Run(name, &winsvc); err != nil {
		return errors.Wrapf(err, "%s service failed", name)
	}

	log.Infof("%s service stopped", name)
	return nil
}
