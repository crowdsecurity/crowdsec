package database

import (
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
)

const bouncerPullUpdateFrequency time.Duration = time.Minute

type BouncerKey struct {
	ID   int    // bouncer ID in DB
	Name string // Bouncer's human readable name
}

type BouncerPullUpdator struct {
	sync.Mutex
	bouncerPullTime map[BouncerKey]time.Time
}

func NewBouncerPullUpdator() *BouncerPullUpdator {
	return &BouncerPullUpdator{
		bouncerPullTime: make(map[BouncerKey]time.Time),
	}
}

func (lpt *BouncerPullUpdator) UpdateBouncerPullEntry(bouncer BouncerKey) {
	lpt.Lock()
	defer lpt.Unlock()
	lpt.bouncerPullTime[bouncer] = time.Now().UTC()
}

func (lpt *BouncerPullUpdator) RunDBUpdator(dbClient *Client, t *tomb.Tomb) {
	log.Info("Running db updator")
	ticker := time.NewTicker(bouncerPullUpdateFrequency)
	stop := func() {
		ticker.Stop()
		log.Info("Stopping BouncerPullUpdator")
	}
	for {
		select {
		case <-ticker.C:
			lpt.Lock()
			for bouncer, pullTime := range lpt.bouncerPullTime {
				if err := dbClient.UpdateBouncerLastPull(pullTime.UTC(), bouncer.ID); err != nil {
					log.Errorf("unable to update bouncer '%s' pull: %v", bouncer.Name, err)
				} else {
					log.Debugf("Updated pull for %s bouncer", bouncer.ID)
				}
			}
			lpt.Unlock()
			lpt.ResetPullTimes()
		case <-t.Dying():
			stop()
			return
		case <-t.Dead():
			stop()
			return
		}
	}
}

func (lpt *BouncerPullUpdator) ResetPullTimes() {
	lpt.Lock()
	defer lpt.Unlock()
	lpt.bouncerPullTime = make(map[BouncerKey]time.Time)
}
