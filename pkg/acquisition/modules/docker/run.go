package dockeracquisition

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	backoff "github.com/cenkalti/backoff/v5"
	dockerContainer "github.com/moby/moby/api/types/container"
	dockerTypesEvents "github.com/moby/moby/api/types/events"
	dockerTypesSwarm "github.com/moby/moby/api/types/swarm"
	"github.com/moby/moby/client"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"github.com/containerd/errdefs"
	"gopkg.in/tomb.v2"

	"github.com/crowdsecurity/dlog"

	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

type BackOffFactory func() backoff.BackOff

func newDockerBackOffFactory() BackOffFactory {
    return func() backoff.BackOff {
        exp := backoff.NewExponentialBackOff()
        exp.InitialInterval = 2 * time.Second
        exp.Multiplier = 2.5
        exp.MaxInterval = 2 * time.Minute
        exp.RandomizationFactor = 0.5

        return exp
    }
}

// OneShotAcquisition reads a set of file and returns when done
func (d *Source) OneShotAcquisition(ctx context.Context, out chan pipeline.Event, t *tomb.Tomb) error {
	d.logger.Debug("In oneshot")

	runningContainers, err := d.Client.ContainerList(ctx, client.ContainerListOptions{})
	if err != nil {
		return err
	}

	foundOne := false

	for _, container := range runningContainers.Items {
		if _, ok := d.runningContainerState.Get(container.ID); ok {
			d.logger.Debugf("container with id %s is already being read from", container.ID)
			continue
		}

		if containerConfig := d.EvalContainer(ctx, container); containerConfig != nil {
			d.logger.Infof("reading logs from container %s", containerConfig.Name)
			d.logger.Debugf("logs options: %+v", *d.containerLogsOptions)

			dockerReader, err := d.Client.ContainerLogs(ctx, containerConfig.ID, *d.containerLogsOptions)
			if err != nil {
				d.logger.Errorf("unable to read logs from container: %+v", err)
				return err
			}

			// we use this library to normalize docker API logs (cf. https://ahmet.im/blog/docker-logs-api-binary-format-explained/)
			foundOne = true

			var scanner *bufio.Scanner

			if containerConfig.Tty {
				scanner = bufio.NewScanner(dockerReader)
			} else {
				reader := dlog.NewReader(dockerReader)
				scanner = bufio.NewScanner(reader)
			}

			for scanner.Scan() {
				select {
				case <-t.Dying():
					d.logger.Infof("Shutting down reader for container %s", containerConfig.Name)
				default:
					line := scanner.Text()
					if line == "" {
						continue
					}

					l := pipeline.Line{}
					l.Raw = line
					l.Labels = d.Config.Labels
					l.Time = time.Now().UTC()
					l.Src = containerConfig.Name
					l.Process = true
					l.Module = d.GetName()

					if d.metricsLevel != metrics.AcquisitionMetricsLevelNone {
						metrics.DockerDatasourceLinesRead.With(prometheus.Labels{"source": containerConfig.Name, "acquis_type": l.Labels["type"], "datasource_type": ModuleName}).Inc()
					}

					evt := pipeline.MakeEvent(true, pipeline.LOG, true)
					evt.Line = l
					evt.Process = true
					evt.Type = pipeline.LOG

					out <- evt

					d.logger.Debugf("Sent line to parsing: %+v", evt.Line.Raw)
				}
			}

			err = scanner.Err()
			if err != nil {
				d.logger.Errorf("Got error from docker read: %s", err)
			}

			d.runningContainerState.Set(container.ID, containerConfig)
		}
	}

	t.Kill(nil)

	if !foundOne {
		return fmt.Errorf("no container found named: %s, can't run one shot acquisition", d.Config.ContainerName[0])
	}

	return nil
}

func (d *Source) EvalContainer(ctx context.Context, container dockerContainer.Summary) *ContainerConfig {
	// fixed params
	newConfig := func(name string, labels map[string]string) *ContainerConfig {
		return NewContainerConfig(d.containerLogsOptions, container.ID, name, labels, d.getContainerTTY(ctx, container.ID))
	}

	// ID match

	if slices.Contains(d.Config.ContainerID, container.ID) {
		return newConfig(container.Names[0], d.Config.Labels)
	}

	// name match

	for _, containerName := range d.Config.ContainerName {
		for _, name := range container.Names {
			if strings.HasPrefix(name, "/") && name != "" {
				name = name[1:]
			}

			if name == containerName {
				return newConfig(name, d.Config.Labels)
			}
		}
	}

	// regex ID match

	for _, cont := range d.compiledContainerID {
		if matched := cont.MatchString(container.ID); matched {
			return newConfig(container.Names[0], d.Config.Labels)
		}
	}

	// regex name match

	for _, cont := range d.compiledContainerName {
		for _, name := range container.Names {
			if matched := cont.MatchString(name); matched {
				return newConfig(name, d.Config.Labels)
			}
		}
	}

	// label match

	if d.Config.UseContainerLabels {
		parsedLabels := d.getContainerLabels(ctx, container.ID)

		labels, err := d.processCrowdsecLabels(parsedLabels, container.ID, "container")
		if err != nil {
			return nil
		}

		return newConfig(container.Names[0], labels)
	}

	return nil
}

func (d *Source) EvalService(_ context.Context, service dockerTypesSwarm.Service) *ContainerConfig {
	// fixed params
	newConfig := func(labels map[string]string) *ContainerConfig {
		// Services don't use TTY
		return NewContainerConfig(d.containerLogsOptions, service.ID, service.Spec.Name, labels, false)
	}

	// service ID match

	if slices.Contains(d.Config.ServiceID, service.ID) {
		return newConfig(d.Config.Labels)
	}

	// service name match

	if slices.Contains(d.Config.ServiceName, service.Spec.Name) {
		return newConfig(d.Config.Labels)
	}

	// service ID regex match

	for _, svc := range d.compiledServiceID {
		if matched := svc.MatchString(service.ID); matched {
			return newConfig(d.Config.Labels)
		}
	}

	// service name regex match

	for _, svc := range d.compiledServiceName {
		if matched := svc.MatchString(service.Spec.Name); matched {
			return newConfig(d.Config.Labels)
		}
	}

	// labels if enabled

	if d.Config.UseServiceLabels {
		parsedLabels := parseLabels(service.Spec.Labels)

		labels, err := d.processCrowdsecLabels(parsedLabels, service.ID, "service")
		if err != nil {
			return nil
		}

		return newConfig(labels)
	}

	return nil
}

func (d *Source) checkServices(ctx context.Context, monitChan chan *ContainerConfig, deleteChan chan *ContainerConfig) error {
	// Track current running services for garbage collection
	runningServicesID := make(map[string]bool)

	services, err := d.Client.ServiceList(ctx, client.ServiceListOptions{})
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "cannot connect to the docker daemon at") {
			d.logger.Errorf("cannot connect to docker daemon for service monitoring: %v", err)

			// Kill all running service monitoring if we can't connect
			for id, service := range d.runningServiceState.GetAll() {
				if service.t.Alive() {
					d.logger.Infof("killing tail for service %s", service.Name)
					service.t.Kill(nil)

					if err := service.t.Wait(); err != nil {
						d.logger.Infof("error while waiting for death of %s : %s", service.Name, err)
					}
				}

				d.runningServiceState.Delete(id)
			}
		} else {
			d.logger.Errorf("service list err: %s", err)
		}

		return err
	}

	for _, service := range services.Items {
		runningServicesID[service.ID] = true

		// Don't need to re-eval an already monitored service
		if _, ok := d.runningServiceState.Get(service.ID); ok {
			continue
		}

		if serviceConfig := d.EvalService(ctx, service); serviceConfig != nil {
			monitChan <- serviceConfig
		}
	}

	// Send deletion notifications for services that are no longer running
	for serviceStateID, serviceConfig := range d.runningServiceState.GetAll() {
		if _, ok := runningServicesID[serviceStateID]; !ok {
			deleteChan <- serviceConfig
		}
	}

	d.logger.Tracef("Reading logs from %d services", d.runningServiceState.Len())

	return nil
}

func (d *Source) checkContainers(ctx context.Context, monitChan chan *ContainerConfig, deleteChan chan *ContainerConfig) error {
	// to track for garbage collection
	runningContainersID := make(map[string]bool)

	runningContainers, err := d.Client.ContainerList(ctx, client.ContainerListOptions{})
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "cannot connect to the docker daemon at") {
			for id, container := range d.runningContainerState.GetAll() {
				if container.t.Alive() {
					d.logger.Infof("killing tail for container %s", container.Name)
					container.t.Kill(nil)

					if err := container.t.Wait(); err != nil {
						d.logger.Infof("error while waiting for death of %s : %s", container.Name, err)
					}
				}

				d.runningContainerState.Delete(id)
			}
		} else {
			log.Errorf("container list err: %s", err)
		}

		return err
	}

	for _, container := range runningContainers.Items {
		runningContainersID[container.ID] = true

		// don't need to re eval an already monitored container
		if _, ok := d.runningContainerState.Get(container.ID); ok {
			continue
		}

		if containerConfig := d.EvalContainer(ctx, container); containerConfig != nil {
			monitChan <- containerConfig
		}
	}

	for containerStateID, containerConfig := range d.runningContainerState.GetAll() {
		if _, ok := runningContainersID[containerStateID]; !ok {
			deleteChan <- containerConfig
		}
	}

	d.logger.Tracef("Reading logs from %d containers", d.runningContainerState.Len())

	return nil
}

type subscription struct {
    events <-chan dockerTypesEvents.Message
    errs   <-chan error
}

func (d *Source) trySubscribeEvents(ctx context.Context) (*subscription, error) {
	filters := client.Filters{
		"type": {
			"container": true,
			"service":   d.isSwarmManager,
		},
	}

	opts := client.EventsListOptions{
		Filters: filters,
	}

	result := d.Client.Events(ctx, opts)

	// Is there an immediate error (proxy/daemon unavailable) ?
	select {
	case err := <-result.Err:
		if err != nil {
			return nil, fmt.Errorf("docker events connection failed: %w", err)
		}
	default:
	}

	return &subscription{events: result.Messages, errs: result.Err}, nil
}

// subscribeEvents will loop until it can successfully call d.Client.Events()
// without immediately receiving an error. It applies exponential backoff on failures.
// Returns the new (eventsChan, errChan) pair or an error if context/tomb is done.
func (d *Source) subscribeEvents(ctx context.Context) (*subscription, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-d.t.Dying():
		return nil, errors.New("connection aborted, shutting down docker watcher")
	default:
	}

	d.logger.Infof("Subscribing to Docker events")

	operation := func() (*subscription, error) {
		select {
		case <-ctx.Done():
			return nil, backoff.Permanent(ctx.Err())
		case <-d.t.Dying():
			return nil, backoff.Permanent(errors.New("connection aborted, shutting down docker watcher"))
		default:
		}

		return d.trySubscribeEvents(ctx)
	}

	notify := func(err error, wait time.Duration) {
		d.logger.Warnf("failed to subscribe to Docker events: %v; retrying in %s", err, wait)
	}

	bo := d.backoffFactory()

	sub, err := backoff.Retry(ctx, operation, backoff.WithBackOff(bo), backoff.WithNotify(notify))
	if err != nil {
		return nil, err
	}

	d.logger.Info("successfully subscribed to Docker events")

	return sub, nil
}

func (d *Source) Watch(ctx context.Context, containerChan chan *ContainerConfig, containerDeleteChan chan *ContainerConfig, serviceChan chan *ContainerConfig, serviceDeleteChan chan *ContainerConfig) error {
	err := d.checkContainers(ctx, containerChan, containerDeleteChan)
	if err != nil {
		return err
	}

	if d.isSwarmManager {
		err = d.checkServices(ctx, serviceChan, serviceDeleteChan)
		if err != nil {
			return err
		}
	}

	sub, err := d.subscribeEvents(ctx)
	if err != nil {
		return err
	}

	for {
		select {
		case <-d.t.Dying():
			d.logger.Infof("stopping container watcher")
			return nil

		case event := <-sub.events:
			d.logger.Tracef("Received event: %+v", event)

			if event.Type == dockerTypesEvents.ServiceEventType && (event.Action == dockerTypesEvents.ActionCreate || event.Action == dockerTypesEvents.ActionRemove) {
				if err := d.checkServices(ctx, serviceChan, serviceDeleteChan); err != nil {
					d.logger.Warnf("Failed to check services: %v", err)
				}
			}

			if event.Type == dockerTypesEvents.ContainerEventType && (event.Action == dockerTypesEvents.ActionStart || event.Action == dockerTypesEvents.ActionDie) {
				if err := d.checkContainers(ctx, containerChan, containerDeleteChan); err != nil {
					d.logger.Warnf("Failed to check containers: %v", err)
				}
			}
		case err := <-sub.errs:
			if err == nil {
				continue
			}

			d.logger.Errorf("Docker events error: %v", err)

			// try to reconnect, replacing our channels on success. They are never nil if err is nil.
			newSub, recErr := d.subscribeEvents(ctx)
			if recErr != nil {
				return recErr
			}

			sub = newSub

			d.logger.Info("Successfully reconnected to Docker events")

			// We check containers after a reconnection because the docker daemon might have restarted
			// and the container tombs may have self deleted
			if err := d.checkContainers(ctx, containerChan, containerDeleteChan); err != nil {
				d.logger.Warnf("Failed to check containers: %v", err)
			}

			if d.isSwarmManager {
				if err := d.checkServices(ctx, serviceChan, serviceDeleteChan); err != nil {
					d.logger.Warnf("Failed to check services: %v", err)
				}
			}
		}
	}
}

func (d *Source) StreamingAcquisition(ctx context.Context, out chan pipeline.Event, t *tomb.Tomb) error {
	d.t = t
	containerChan := make(chan *ContainerConfig)
	containerDeleteChan := make(chan *ContainerConfig)
	serviceChan := make(chan *ContainerConfig)
	serviceDeleteChan := make(chan *ContainerConfig)

	d.logger.Infof("Starting docker acquisition")

	t.Go(func() error {
		return d.ContainerManager(ctx, containerChan, containerDeleteChan, out)
	})

	if d.isSwarmManager {
		t.Go(func() error {
			return d.ServiceManager(ctx, serviceChan, serviceDeleteChan, out)
		})
	}

	return d.Watch(ctx, containerChan, containerDeleteChan, serviceChan, serviceDeleteChan)
}

func ReadTailScanner(scanner *bufio.Scanner, out chan string, t *tomb.Tomb) error {
	for scanner.Scan() {
		out <- scanner.Text()
	}

	return scanner.Err()
}

// isContainerStillRunning checks if a container is still running via Docker API
func (d *Source) isContainerStillRunning(ctx context.Context, container *ContainerConfig) bool {
	if ctx.Err() != nil {
		container.logger.Debugf("context canceled while checking container")
		return false
	}

	containerInfo, err := d.Client.ContainerInspect(ctx, container.ID, client.ContainerInspectOptions{})
	if err != nil {
		if errdefs.IsNotFound(err) {
			container.logger.Debugf("container no longer exists")
			return false
		}

		// Other errors (connection issues, etc.) - assume container is still running
		container.logger.Debugf("failed to inspect: %v (assuming still running)", err)

		return true
	}

	if containerInfo.Container.State == nil {
		container.logger.Warnf("inspect returned nil state (assuming not running)")
		return false
	}

	isRunning := containerInfo.Container.State.Running
	container.logger.Debugf("running status: %v", isRunning)

	return isRunning
}

// isServiceStillRunning checks if a service still exists via Docker API
func (d *Source) isServiceStillRunning(ctx context.Context, service *ContainerConfig) bool {
	if ctx.Err() != nil {
		service.logger.Debugf("context canceled while checking service")
		return false
	}

	_, err := d.Client.ServiceInspect(ctx, service.ID, client.ServiceInspectOptions{})
	if err != nil {
		if errdefs.IsNotFound(err) {
			service.logger.Debugf("service no longer exists")
			return false
		}

		// Other errors (connection issues, etc.) - assume service still exists
		service.logger.Debugf("failed to inspect: %v (assuming still running)", err)

		return true
	}

	service.logger.Debugf("service %s still exists", service.Name)

	return true
}

func (d *Source) TailContainer(ctx context.Context, container *ContainerConfig, outChan chan pipeline.Event, deleteChan chan *ContainerConfig) error {
	container.logger.Info("start monitoring")

	// we'll use just the interval generator, won't call backoff.Retry()
	bo := d.backoffFactory()
	firstRetry := true

	for {
		err := d.tailContainerAttempt(ctx, container, outChan, bo)
		if err == nil {
			// Successful completion - container was stopped gracefully
			return nil
		}

		// Check container health to determine if we should retry or give up
		containerHealthy := d.isContainerStillRunning(ctx, container)
		if !containerHealthy {
			// Container is dead/stopped - don't retry, remove from monitoring
			container.logger.Infof("container no longer running, removing from monitoring: %v", err)
			deleteChan <- container
			return err
		}

		// Container is still running, so this is likely a temporary network/proxy issue
		// Update the Since timestamp to avoid re-reading logs from before the failure
		container.logOptions.Since = time.Now().UTC().Format(time.RFC3339)

		// retry immediately, the tail may have failed due to idle disconnection from a proxy
		if firstRetry {
			firstRetry = false
			container.logger.Debugf("tail failed but container is (presumed) healthy: %v, retrying immediately", err)
			continue
		}

		wait := bo.NextBackOff()

		container.logger.Debugf("tail failed but container is (presumed) healthy: %v, retrying in %s", err, wait)

		select {
		case <-time.After(wait):
		case <-container.t.Dying():
			container.logger.Infof("tail stopped")
			return nil
		}
	}
}

func (d *Source) tailContainerAttempt(ctx context.Context, container *ContainerConfig, outChan chan pipeline.Event, bo backoff.BackOff) error {
	dockerReader, err := d.Client.ContainerLogs(ctx, container.ID, *container.logOptions)
	if err != nil {
		return fmt.Errorf("unable to read logs from container %s: %w", container.Name, err)
	}

	// Log connection (both initial and reconnections)
	container.logger.Info("connected to container logs")

	// reset backoff so for the next disconnect, the interval doesn't start from 30sec
	bo.Reset()

	var scanner *bufio.Scanner
	// we use this library to normalize docker API logs (cf. https://ahmet.im/blog/docker-logs-api-binary-format-explained/)
	if container.Tty {
		scanner = bufio.NewScanner(dockerReader)
	} else {
		reader := dlog.NewReader(dockerReader)
		scanner = bufio.NewScanner(reader)
	}

	readerChan := make(chan string)
	readerTomb := &tomb.Tomb{}
	readerTomb.Go(func() error {
		return ReadTailScanner(scanner, readerChan, readerTomb)
	})

	for {
		select {
		case <-container.t.Dying():
			readerTomb.Kill(nil)
			return nil
		case line := <-readerChan:
			if line == "" {
				continue
			}

			l := pipeline.Line{}
			l.Raw = line
			l.Labels = container.Labels
			l.Time = time.Now().UTC()
			l.Src = container.Name
			l.Process = true
			l.Module = d.GetName()
			evt := pipeline.MakeEvent(d.Config.UseTimeMachine, pipeline.LOG, true)
			evt.Line = l

			if d.metricsLevel != metrics.AcquisitionMetricsLevelNone {
				metrics.DockerDatasourceLinesRead.With(prometheus.Labels{"source": container.Name, "datasource_type": ModuleName, "acquis_type": evt.Line.Labels["type"]}).Inc()
			}

			outChan <- evt

			d.logger.Debugf("Sent line to parsing: %+v", evt.Line.Raw)
		case <-readerTomb.Dying():
			// This case is to handle temporarily losing the connection to the docker socket
			// The only known case currently is when using docker-socket-proxy (and maybe a docker daemon restart)
			container.logger.Debugf("readerTomb dying, connection lost")
			readerTomb.Kill(nil)

			return fmt.Errorf("reader connection lost for container %s", container.Name)
		}
	}
}

func (d *Source) TailService(ctx context.Context, service *ContainerConfig, outChan chan pipeline.Event, deleteChan chan *ContainerConfig) error {
	service.logger.Info("start monitoring")

	// we'll use just the interval generator, won't call backoff.Retry()
	bo := d.backoffFactory()
	firstRetry := true

	for {
		err := d.tailServiceAttempt(ctx, service, outChan, bo)
		if err == nil {
			// Successful completion - service was stopped gracefully
			return nil
		}

		// Check service health to determine if we should retry or give up
		serviceHealthy := d.isServiceStillRunning(ctx, service)

		if !serviceHealthy {
			// Service was removed - don't retry, remove from monitoring
			service.logger.Infof("service no longer exists, removing from monitoring: %v", err)
			deleteChan <- service
			return err
		}

		// Service still exists, so this is likely a temporary network/proxy issue
		// Update the Since timestamp to avoid re-reading logs from before the failure
		service.logOptions.Since = time.Now().UTC().Format(time.RFC3339)

		// retry immediately, the tail may have failed due to idle disconnection from a proxy
		if firstRetry {
			firstRetry = false
			service.logger.Debugf("tail failed but service is (presumed) healthy: %v, retrying immediately", err)
			continue
		}

		wait := bo.NextBackOff()

		service.logger.Debugf("tail failed but service is (presumed) healthy: %v, retrying in %s", err, wait)

		select {
		case <-time.After(wait):
		case <-service.t.Dying():
			service.logger.Infof("tail stopped")
			return nil
		}
	}
}

func (d *Source) tailServiceAttempt(ctx context.Context, service *ContainerConfig, outChan chan pipeline.Event, bo backoff.BackOff) error {
	// For services, we need to get the service logs using the service logs API
	// Docker service logs aggregates logs from all running tasks of the service
	logOptions := client.ServiceLogsOptions{
		ShowStdout: service.logOptions.ShowStdout,
		ShowStderr: service.logOptions.ShowStderr,
		Since:      service.logOptions.Since,
		Until:      service.logOptions.Until,
		Timestamps: service.logOptions.Timestamps,
		Follow:     service.logOptions.Follow,
		Tail:       service.logOptions.Tail,
		Details:    service.logOptions.Details,
	}
	dockerReader, err := d.Client.ServiceLogs(ctx, service.ID, logOptions)
	if err != nil {
		return fmt.Errorf("unable to read logs from service %s: %w", service.Name, err)
	}

	// Log connection (both initial and reconnections)
	service.logger.Info("connected to service logs")

	bo.Reset()

	// Service logs don't use TTY, so we always use the dlog reader
	reader := dlog.NewReader(dockerReader)
	scanner := bufio.NewScanner(reader)

	readerChan := make(chan string)
	readerTomb := &tomb.Tomb{}
	readerTomb.Go(func() error {
		return ReadTailScanner(scanner, readerChan, readerTomb)
	})

	for {
		select {
		case <-service.t.Dying():
			readerTomb.Kill(nil)
			return nil
		case line := <-readerChan:
			if line == "" {
				continue
			}

			l := pipeline.Line{}
			l.Raw = line
			l.Labels = service.Labels
			l.Time = time.Now().UTC()
			l.Src = service.Name
			l.Process = true
			l.Module = d.GetName()
			evt := pipeline.MakeEvent(d.Config.UseTimeMachine, pipeline.LOG, true)
			evt.Line = l

			if d.metricsLevel != metrics.AcquisitionMetricsLevelNone {
				metrics.DockerDatasourceLinesRead.With(prometheus.Labels{"source": service.Name, "acquis_type": l.Labels["type"], "datasource_type": ModuleName}).Inc()
			}

			outChan <- evt

			d.logger.Debugf("Sent line to parsing: %+v", evt.Line.Raw)
		case <-readerTomb.Dying():
			// Handle connection loss similar to containers
			service.logger.Debugf("readerTomb dying, connection lost")
			readerTomb.Kill(nil)

			return fmt.Errorf("reader connection lost for service %s", service.Name)
		}
	}
}

func (d *Source) ContainerManager(ctx context.Context, in chan *ContainerConfig, deleteChan chan *ContainerConfig, outChan chan pipeline.Event) error {
	d.logger.Info("Container Manager started")

	for {
		select {
		case newContainer := <-in:
			if _, ok := d.runningContainerState.Get(newContainer.ID); !ok {
				newContainer.logger = d.logger.WithField("container_name", newContainer.Name)
				newContainer.t.Go(func() error {
					return d.TailContainer(ctx, newContainer, outChan, deleteChan)
				})

				d.runningContainerState.Set(newContainer.ID, newContainer)
			}
		case containerToDelete := <-deleteChan:
			if containerConfig, ok := d.runningContainerState.Get(containerToDelete.ID); ok {
				log.Infof("container acquisition stopped for container '%s'", containerConfig.Name)
				containerConfig.t.Kill(nil)
				d.runningContainerState.Delete(containerToDelete.ID)
			}
		case <-d.t.Dying():
			for _, container := range d.runningContainerState.GetAll() {
				if container.t.Alive() {
					d.logger.Infof("killing tail for container %s", container.Name)
					container.t.Kill(nil)

					if err := container.t.Wait(); err != nil {
						d.logger.Infof("error while waiting for death of %s : %s", container.Name, err)
					}
				}
			}

			d.runningContainerState = nil
			d.logger.Debugf("routine cleanup done, return")

			return nil
		}
	}
}

func (d *Source) ServiceManager(ctx context.Context, in chan *ContainerConfig, deleteChan chan *ContainerConfig, outChan chan pipeline.Event) error {
	d.logger.Info("Service Manager started")

	for {
		select {
		case newService := <-in:
			if _, ok := d.runningServiceState.Get(newService.ID); !ok {
				newService.logger = d.logger.WithField("service_name", newService.Name)
				newService.t.Go(func() error {
					return d.TailService(ctx, newService, outChan, deleteChan)
				})

				d.runningServiceState.Set(newService.ID, newService)
			}
		case serviceToDelete := <-deleteChan:
			if serviceConfig, ok := d.runningServiceState.Get(serviceToDelete.ID); ok {
				d.logger.Infof("service acquisition stopped for service '%s'", serviceConfig.Name)
				serviceConfig.t.Kill(nil)
				d.runningServiceState.Delete(serviceToDelete.ID)
			}
		case <-d.t.Dying():
			for _, service := range d.runningServiceState.GetAll() {
				if service.t.Alive() {
					d.logger.Infof("killing tail for service %s", service.Name)
					service.t.Kill(nil)

					if err := service.t.Wait(); err != nil {
						d.logger.Infof("error while waiting for death of %s : %s", service.Name, err)
					}
				}
			}

			d.runningServiceState = nil
			d.logger.Debugf("service manager cleanup done, return")

			return nil
		}
	}
}
