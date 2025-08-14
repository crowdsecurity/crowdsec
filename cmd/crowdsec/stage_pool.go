package main

import (
	"time"

	log "github.com/sirupsen/logrus"
	tomb "gopkg.in/tomb.v2"
)

// StagePool is a minimal scaffold to manage a pool of workers for a stage and a monitor to autoscale.
type StagePool struct {
	name         string
	tomb         *tomb.Tomb
	inLen        func() (int, int) // returns len and cap of the input queue
	min          int
	max          int
	launchWorker func()
	requestStop  func() bool // ask one worker to stop, returns true if a worker was signaled

	// autoscale tuning
	upThresh     int // percent
	downThresh   int // percent
	upCooldown   time.Duration
	downCooldown time.Duration

	logger *log.Entry
}

func NewStagePool(name string, t *tomb.Tomb, inLen func() (int, int), min, max int, launchWorker func(), logger *log.Entry) *StagePool {
	return &StagePool{
		name:         name,
		tomb:         t,
		inLen:        inLen,
		min:          min,
		max:          max,
		launchWorker: launchWorker,
		upThresh:     70,
		downThresh:   20,
		upCooldown:   time.Second,
		downCooldown: 5 * time.Second,
		logger:       logger,
	}
}

// Start launches initial workers and, if enabled, a monitor goroutine.
// If enableAutoscale is false, only the initial workers are started.
func (p *StagePool) Start(initial int, enableAutoscale bool) {
	if initial < 1 {
		initial = 1
	}
	if p.max < p.min {
		p.max = p.min
	}
	// ensure we never scale below the initial number of workers
	if p.min < initial {
		p.min = initial
	}

	// launch initial workers
	for range initial {
		p.launchWorker()
	}

	if !enableAutoscale {
		return
	}

	p.tomb.Go(func() error {
		// monitor and scale
		current := initial
		var hotCount, coldCount int
		lastUp := time.Time{}
		lastDown := time.Time{}
		ticker := time.NewTicker(300 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-p.tomb.Dying():
				return nil
			case <-ticker.C:
				llen, capn := p.inLen()
				if capn == 0 {
					continue
				}
				usage := (llen * 100) / capn
				if usage >= p.upThresh && current < p.max {
					hotCount++
					coldCount = 0
					if hotCount >= 3 && time.Since(lastUp) >= p.upCooldown {
						p.launchWorker()
						current++
						lastUp = time.Now()
						p.logger.Infof("autoscale(%s): scale up to %d (queue %d/%d)", p.name, current, llen, capn)
					}
				} else if usage <= p.downThresh && current > p.min {
					coldCount++
					hotCount = 0
					if coldCount >= 10 && time.Since(lastDown) >= p.downCooldown {
						// attempt to gracefully stop one worker
						stopped := false
						if p.requestStop != nil {
							stopped = p.requestStop()
						}
						if stopped {
							current--
							lastDown = time.Now()
							p.logger.Infof("autoscale(%s): scale down to %d (queue %d/%d)", p.name, current, llen, capn)
						} else {
							p.logger.Debugf("autoscale(%s): no idle worker available to stop", p.name)
						}
					}
				} else {
					hotCount = 0
					coldCount = 0
				}
			}
		}
	})
}
