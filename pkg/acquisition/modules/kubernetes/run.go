package kubernetes

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

func (s *Source) Stream(ctx context.Context, out chan pipeline.Event) error {
	var wg sync.WaitGroup
	var mu sync.Mutex

	s.logger.Info("Starting Kubernetes acquisition")

	cfg, err := s.config.buildClientConfig()
	if err != nil {
		return err
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("can't create a kubernetes client: %s", err)
	}

	cancels := map[types.UID]context.CancelFunc{}

	f := informers.NewSharedInformerFactoryWithOptions(cs, 0,
		informers.WithNamespace(s.config.Namespace),
		informers.WithTweakListOptions(func(o *metav1.ListOptions) { o.LabelSelector = s.config.Selector }),
	)
	inf := f.Core().V1().Pods().Informer()

	// We ignore the ResourceEventHandlerRegistration returned by
	// AddEventHandler since we don't need to remove the handlers until shutdown,
	// and we will stop the entire informer at that time.
	s.logger.Info("Adding kubernetes event handler")
	_, err = inf.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) { s.startPod(ctx, cs, obj.(*corev1.Pod), out, &wg, &mu, cancels) },
		UpdateFunc: func(_, newObj any) {
			s.startPod(ctx, cs, newObj.(*corev1.Pod), out, &wg, &mu, cancels)
		},
		DeleteFunc: func(obj any) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				t, _ := obj.(cache.DeletedFinalStateUnknown)
				pod, _ = t.Obj.(*corev1.Pod)
			}
			if pod != nil {
				s.stopPod(pod, &mu, cancels)
			}
		},
	})

	if err != nil {
		return fmt.Errorf("while adding event handler: %w", err)
	}
	f.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), inf.HasSynced) {
		return errors.New("cache sync failed")
	}

	<-ctx.Done()
	mu.Lock()
	for _, c := range cancels {
		c()
	}
	mu.Unlock()
	wg.Wait()

	return nil
}

func (s *Source) Dump() any {
	return s
}

func (*Source) followPodLogs(ctx context.Context, cs *kubernetes.Clientset, ns, pod, container string, onLine func(string) error) error {
	req := cs.CoreV1().Pods(ns).GetLogs(pod, &corev1.PodLogOptions{Container: container, Follow: true, Timestamps: false})
	stream, err := req.Stream(ctx)
	if err != nil {
		return err
	}
	defer stream.Close()

	sc := bufio.NewScanner(stream)
	for sc.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := onLine(sc.Text()); err != nil {
			return err
		}
	}
	return sc.Err()

}

func (s *Source) podWorker(parentCtx context.Context, cs *kubernetes.Clientset, pod *corev1.Pod, out chan pipeline.Event, wg *sync.WaitGroup) context.CancelFunc {
	podCtx, cancel := context.WithCancel(parentCtx)
	wg.Go(func() {
		var cw sync.WaitGroup
		for _, c := range pod.Spec.Containers {
			cw.Go(func() {
				_ = s.followPodLogs(podCtx, cs, pod.Namespace, pod.Name, c.Name, func(line string) error {
					source := fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)
					l := pipeline.Line{
						Raw: line,
						Labels: s.config.Labels,
						Time: time.Now().UTC(),
						Src: source,
						Process: true,
						Module: s.GetName(),
					}
					if s.metricsLevel != metrics.AcquisitionMetricsLevelNone {
						metrics.KubernetesDataSourceLinesRead.With(prometheus.Labels{"source": source, "acquis_type": l.Labels["type"], "datasource_type": ModuleName}).Inc()
					}
					evt := pipeline.MakeEvent(true, pipeline.LOG, true)
					evt.Line = l
					evt.Process = true
					evt.Type = pipeline.LOG
					out <- evt
					s.logger.Tracef("got one line from %s: %s", source, line)
					return nil
				})
			})
		}
		cw.Wait()
	})
	return cancel
}

func shouldTail(p *corev1.Pod) bool { return p.Status.Phase == corev1.PodRunning }

func (s *Source) startPod(meta context.Context, cs *kubernetes.Clientset, p *corev1.Pod, out chan pipeline.Event, wg *sync.WaitGroup, mu *sync.Mutex, cancels map[types.UID]context.CancelFunc) {
	if !shouldTail(p) {
		return
	}
	key := p.UID
	mu.Lock()
	if _, ok := cancels[key]; ok {
		mu.Unlock()
		return
	}
	cancels[key] = s.podWorker(meta, cs, p, out, wg)
	mu.Unlock()
}

func (*Source) stopPod(p *corev1.Pod, mu *sync.Mutex, cancels map[types.UID]context.CancelFunc) {
	key := p.UID
	mu.Lock()
	cancel, ok := cancels[key]
	if ok {
		delete(cancels, key)
	}
	mu.Unlock()
	if ok {
		cancel()
	}
}
