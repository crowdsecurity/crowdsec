package kubernetespodlogs

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/tomb.v2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

func (d *Source) OneShotAcquisition(ctx context.Context, out chan pipeline.Event, t *tomb.Tomb) error {
	d.logger.Debug("In oneshot")
	return nil
}

func (d *Source) StreamingAcquisition(ctx context.Context, out chan pipeline.Event, t *tomb.Tomb) error {
	var wg sync.WaitGroup
	var mu sync.Mutex

	d.logger.Info("Starting Kubernetes Pod Logs acquisition")

	cfg, err := d.buildConfig()
	if err != nil {
		log.Fatal(err)
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		log.Fatal(err)
	}

	cancels := map[string]context.CancelFunc{}

	f := informers.NewSharedInformerFactoryWithOptions(cs, 0,
		informers.WithNamespace(d.Config.Namespace),
		informers.WithTweakListOptions(func(o *metav1.ListOptions) { o.LabelSelector = d.Config.Selector }),
	)
	inf := f.Core().V1().Pods().Informer()

	// We ignore the ResourceEventHandlerRegistration returned by
	// AddEventHandler since we don't need to remove the handlers until shutdown,
	// and we will stop the entire informer at that time.
	_, err = inf.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) { d.startPod(ctx, cs, obj.(*corev1.Pod), out, &wg, &mu, cancels) },
		UpdateFunc: func(_, newObj interface{}) {
			d.startPod(ctx, cs, newObj.(*corev1.Pod), out, &wg, &mu, cancels)
		},
		DeleteFunc: func(obj interface{}) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				t, _ := obj.(cache.DeletedFinalStateUnknown)
				pod, _ = t.Obj.(*corev1.Pod)
			}
			if pod != nil {
				d.stopPod(pod, &mu, cancels)
			}
		},
	})

	if err != nil {
		return fmt.Errorf("while adding event handler: %w", err)
	}
	f.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), inf.HasSynced) {
		return fmt.Errorf("cache sync failed")
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

func (d *Source) Dump() any {
	return d
}

func (d *Source) followPodLogs(ctx context.Context, cs *kubernetes.Clientset, ns, pod, container string, onLine func(string) error) error {
	req := cs.CoreV1().Pods(ns).GetLogs(pod, &corev1.PodLogOptions{Container: container, Follow: true, Timestamps: true})
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

func (d *Source) podWorker(meta context.Context, cs *kubernetes.Clientset, pod *corev1.Pod, out chan pipeline.Event, wg *sync.WaitGroup) context.CancelFunc {
	podCtx, cancel := context.WithCancel(meta)
	wg.Add(1)
	go func() {
		defer wg.Done()
		var cw sync.WaitGroup
		for _, c := range pod.Spec.Containers {
			c := c.Name
			cw.Add(1)
			go func() {
				defer cw.Done()
				_ = d.followPodLogs(podCtx, cs, pod.Namespace, pod.Name, c, func(line string) error {
					source := fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)
					l := pipeline.Line{}
					l.Raw = line
					l.Labels = d.Config.Labels
					l.Time = time.Now().UTC()
					l.Src = source
					l.Process = true
					l.Module = d.GetName()
					if d.metricsLevel != metrics.AcquisitionMetricsLevelNone {
						metrics.DockerDatasourceLinesRead.With(prometheus.Labels{"source": source, "acquis_type": l.Labels["type"], "datasource_type": ModuleName}).Inc()
					}
					evt := pipeline.MakeEvent(true, pipeline.LOG, true)
					evt.Line = l
					evt.Process = true
					evt.Type = pipeline.LOG
					out <- evt
					return nil
				})
			}()
		}
		cw.Wait()
	}()
	return cancel
}

func shouldTail(p *corev1.Pod) bool { return p.Status.Phase == corev1.PodRunning }

func (d *Source) startPod(meta context.Context, cs *kubernetes.Clientset, p *corev1.Pod, out chan pipeline.Event, wg *sync.WaitGroup, mu *sync.Mutex, cancels map[string]context.CancelFunc) {
	if !shouldTail(p) {
		return
	}
	key := string(p.UID)
	mu.Lock()
	if _, ok := cancels[key]; ok {
		mu.Unlock()
		return
	}
	cancels[key] = d.podWorker(meta, cs, p, out, wg)
	mu.Unlock()
}

func (*Source) stopPod(p *corev1.Pod, mu *sync.Mutex, cancels map[string]context.CancelFunc) {
	key := string(p.UID)
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
