package kubernetes

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

func podRef(p *corev1.Pod) string {
	if p == nil {
		return "<nil pod>"
	}
	return fmt.Sprintf("%s/%s uid=%s phase=%s rv=%s node=%s",
		p.Namespace,
		p.Name,
		p.UID,
		p.Status.Phase,
		p.ResourceVersion,
		p.Spec.NodeName,
	)
}

func (s *Source) initClient() error {
	cfg, err := s.config.buildClientConfig(s.logger)
	if err != nil {
		return fmt.Errorf("building kubernetes client config for namespace=%q selector=%q: %w", s.config.Namespace, s.config.Selector, err)
	}

	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("can't create a kubernetes client for namespace=%q selector=%q: %w", s.config.Namespace, s.config.Selector, err)
	}

	s.client = client

	return nil
}

func (s *Source) Stream(ctx context.Context, out chan pipeline.Event) error {
	var wg sync.WaitGroup

	s.logger.WithFields(log.Fields{
		"namespace": s.config.Namespace,
		"selector":  s.config.Selector,
	}).Info("starting kubernetes acquisition")

	err := s.initClient()
	if err != nil {
		return err
	}

	informerCtx, cancelInformer := context.WithCancel(ctx)
	defer cancelInformer()

	cancels := map[types.UID]context.CancelFunc{}
	watchErrCh := make(chan error, 1)

	f := informers.NewSharedInformerFactoryWithOptions(s.client, 0,
		informers.WithNamespace(s.config.Namespace),
		informers.WithTweakListOptions(func(o *metav1.ListOptions) {
			// We set the LabelSelector on the ListOptions to filter pods at the
			// API level, so we only get events for pods that match our
			// selector. This is more efficient than getting all pod events and
			// filtering them in our event handlers.
			o.LabelSelector = s.config.Selector
		}),
	)
	inf := f.Core().V1().Pods().Informer()
	if err := inf.SetWatchErrorHandler(func(_ *cache.Reflector, watchErr error) {
		fields := log.Fields{
			"namespace": s.config.Namespace,
			"selector":  s.config.Selector,
			"error":     watchErr,
		}
		if apierrors.IsUnauthorized(watchErr) {
			s.logger.WithFields(fields).Error("kubernetes informer received Unauthorized, forcing datasource restart")
			select {
			case watchErrCh <- fmt.Errorf("kubernetes informer unauthorized for namespace=%q selector=%q unique_id=%q: %w", s.config.Namespace, s.config.Selector, s.config.UniqueId, watchErr):
			default:
			}
			cancelInformer()
			return
		}
		s.logger.WithFields(fields).Warn("kubernetes informer watch error")
	}); err != nil {
		return fmt.Errorf("while setting watch error handler for namespace=%q selector=%q: %w", s.config.Namespace, s.config.Selector, err)
	}

	// We ignore the ResourceEventHandlerRegistration returned by
	// AddEventHandler since we don't need to remove the handlers until shutdown,
	// and we will stop the entire informer at that time.
	s.logger.WithFields(log.Fields{
		"namespace": s.config.Namespace,
		"selector":  s.config.Selector,
	}).Info("adding kubernetes event handler")
	_, err = inf.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			p := obj.(*corev1.Pod)
			s.logger.Debugf("ADD %s labels=%v", podRef(p), p.Labels)
			s.tailPod(informerCtx, p, out, &wg, cancels)
		},
		UpdateFunc: func(oldObj, newObj any) {
			oldP := oldObj.(*corev1.Pod)
			newP := newObj.(*corev1.Pod)

			if oldP.Status.Phase != newP.Status.Phase {
				s.logger.Debugf("UPDATE phase %s -> %s", podRef(oldP), podRef(newP))
			} else {
				s.logger.Tracef("UPDATE %s", podRef(newP))
			}

			s.tailPod(informerCtx, newP, out, &wg, cancels)
		},
		DeleteFunc: func(obj any) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				t, _ := obj.(cache.DeletedFinalStateUnknown)
				pod, _ = t.Obj.(*corev1.Pod)
				s.logger.Debugf("DELETE(tombstone) %s", podRef(pod))
			} else {
				s.logger.Debugf("DELETE %s", podRef(pod))
			}

			if pod != nil {
				s.stopPod(pod, cancels)
			}
		},
	})

	if err != nil {
		return fmt.Errorf("while adding event handler for namespace=%q selector=%q: %w", s.config.Namespace, s.config.Selector, err)
	}
	f.Start(informerCtx.Done())
	if !cache.WaitForCacheSync(informerCtx.Done(), inf.HasSynced) {
		select {
		case watchErr := <-watchErrCh:
			return watchErr
		default:
		}
		return fmt.Errorf("cache sync failed for namespace=%q selector=%q", s.config.Namespace, s.config.Selector)
	}

	select {
	case <-ctx.Done():
	case watchErr := <-watchErrCh:
		s.mu.Lock()
		for _, c := range cancels {
			c()
		}
		s.mu.Unlock()
		wg.Wait()
		return watchErr
	}
	s.mu.Lock()
	for _, c := range cancels {
		c()
	}
	s.mu.Unlock()
	wg.Wait()

	return nil
}

func (s *Source) Dump() any {
	return s
}

func (s *Source) followPodLogs(ctx context.Context, ns string, pod string, container string, out chan pipeline.Event,
	onLineFunc func(string, string, chan pipeline.Event) error) error {
	client := s.client
	if client == nil {
		return errors.New("kubernetes client is not initialized")
	}

	req := client.CoreV1().Pods(ns).GetLogs(pod, &corev1.PodLogOptions{Container: container, Follow: true, Timestamps: false})
	fn := func() error {
		if err := ctx.Err(); err != nil {
			return nil
		}
		stream, err := req.Stream(ctx)
		if err != nil {
			return err
		}
		defer stream.Close()

		sc := bufio.NewScanner(stream)
		for sc.Scan() {
			if err := ctx.Err(); err != nil {
				return nil
			}
			if err := onLineFunc(sc.Text(), ns+"/"+pod+"/"+container, out); err != nil {
				return err
			}
		}
		if ctx.Err() != nil {
			return nil
		}
		return sc.Err()
	}
	for {
		err := fn()
		if err != nil {
			return err
		}
		// Clean EOF: check if the pod has terminated so we don't re-stream old logs.
		// If the Get fails or the pod is still Running, fall through and retry
		// (handles transient API server disconnects).
		if p, getErr := client.CoreV1().Pods(ns).Get(ctx, pod, metav1.GetOptions{}); getErr == nil && p.Status.Phase != corev1.PodRunning {
			s.logger.Debugf("stopped following logs for %s/%s/%s: pod is in phase %s", ns, pod, container, p.Status.Phase)
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(time.Second):
		}
	}
}

func (s *Source) processLine(line string, source string, out chan pipeline.Event) error {
	l := pipeline.Line{
		Raw:     line,
		Labels:  s.config.Labels,
		Time:    time.Now().UTC(),
		Src:     source,
		Process: true,
		Module:  s.GetName(),
	}
	if s.metricsLevel != metrics.AcquisitionMetricsLevelNone {
		metrics.KubernetesDataSourceLinesRead.With(prometheus.Labels{"source": source, "acquis_type": l.Labels["type"], "datasource_type": ModuleName}).Inc()
	}
	evt := pipeline.MakeEvent(s.config.UseTimeMachine, pipeline.LOG, true)
	evt.Line = l
	out <- evt
	s.logger.Tracef("got one line from %s: %s", source, line)
	return nil
}

func (s *Source) podWorker(parentCtx context.Context,
	pod *corev1.Pod,
	out chan pipeline.Event,
	wg *sync.WaitGroup,
	cancels map[types.UID]context.CancelFunc) context.CancelFunc {
	podCtx, cancel := context.WithCancel(parentCtx)
	wg.Go(func() {
		defer func() {
			s.mu.Lock()
			delete(cancels, pod.UID)
			s.mu.Unlock()
		}()
		var cw sync.WaitGroup
		for _, cont := range pod.Spec.Containers {
			cw.Go(func() {
				err := s.followPodLogs(podCtx, pod.Namespace, pod.Name, cont.Name, out, s.processLine)
				if err != nil {
					s.logger.Errorf("error following logs for %s/%s/%s: %s", pod.Namespace, pod.Name, cont.Name, err)
				} else {
					s.logger.Debugf("stopped following logs for %s/%s/%s", pod.Namespace, pod.Name, cont.Name)
				}
			})
		}
		cw.Wait()
	})
	return cancel
}

func (s *Source) tailPod(ctx context.Context, p *corev1.Pod, out chan pipeline.Event, wg *sync.WaitGroup, cancels map[types.UID]context.CancelFunc) {
	if p.Status.Phase != corev1.PodRunning {
		s.logger.Debugf("SKIP tailPod(non-running) %s", podRef(p))
		return
	}

	key := p.UID
	s.mu.Lock()
	if _, ok := cancels[key]; ok {
		s.logger.Tracef("tail already running %s", podRef(p))
		s.mu.Unlock()
		return
	}

	s.logger.Debugf("START tail %s", podRef(p))
	cancels[key] = s.podWorker(ctx, p, out, wg, cancels)
	s.mu.Unlock()
}

func (s *Source) stopPod(p *corev1.Pod, cancels map[types.UID]context.CancelFunc) {
	key := p.UID
	s.mu.Lock()
	cancel, ok := cancels[key]
	if ok {
		delete(cancels, key)
	}
	s.mu.Unlock()
	if ok {
		cancel()
	}
}
