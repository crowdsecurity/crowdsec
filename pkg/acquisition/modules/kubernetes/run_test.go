package kubernetes

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	k8stesting "k8s.io/client-go/testing"

	fakekube "k8s.io/client-go/kubernetes/fake"

	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

// retryBackoffMidpoint sits halfway between an immediate return (expected to
// take microseconds) and the 1s retry backoff in followPodLogs (run.go), so
// tests can tell the two apart with margin on both sides instead of
// asserting against the exact backoff duration.
const retryBackoffMidpoint = 500 * time.Millisecond

func testLogger() *log.Entry {
	return log.WithField("type", ModuleName)
}

// reactToLogs makes the fake clientset answer Pods().GetLogs() requests with
// the given body/error, without interfering with plain pod Get/List calls.
func reactToLogs(client *fakekube.Clientset, body string, err error) {
	client.PrependReactor("get", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		if action.GetSubresource() != "log" {
			return false, nil, nil
		}
		if err != nil {
			return true, nil, err
		}
		return true, &runtime.Unknown{Raw: []byte(body)}, nil
	})
}

func newTestPod(name, ns string, phase corev1.PodPhase) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
			UID:       types.UID("uid-" + name),
		},
		Status: corev1.PodStatus{Phase: phase},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "container"}},
		},
	}
}

func TestFollowPodLogs_NoClient(t *testing.T) {
	s := &Source{logger: testLogger()}
	// followPodLogs returns before ever writing to out, but keep it buffered
	// for consistency with the other followPodLogs tests below.
	out := make(chan pipeline.Event, 1)

	err := s.followPodLogs(t.Context(), "ns", "pod", "container", out, s.processLine)
	require.ErrorContains(t, err, "kubernetes client is not initialized")
}

func TestFollowPodLogs_ReadsLinesAndStopsWhenPodNotRunning(t *testing.T) {
	pod := newTestPod("pod", "ns", corev1.PodSucceeded)
	client := fakekube.NewSimpleClientset(pod)
	reactToLogs(client, "line1\nline2\n", nil)

	s := &Source{logger: testLogger(), client: client}
	// followPodLogs is called synchronously below with no concurrent reader
	// on out, so it must be buffered or processLine's blocking send would
	// deadlock the test.
	out := make(chan pipeline.Event, 10)

	err := s.followPodLogs(t.Context(), "ns", "pod", "container", out, s.processLine)
	require.NoError(t, err)

	close(out)

	var lines []string
	for evt := range out {
		lines = append(lines, evt.Line.Raw)
	}

	assert.Equal(t, []string{"line1", "line2"}, lines)
}

func TestFollowPodLogs_FatalOnLineProcessingError(t *testing.T) {
	pod := newTestPod("pod", "ns", corev1.PodRunning)
	client := fakekube.NewSimpleClientset(pod)
	reactToLogs(client, "line1\n", nil)

	s := &Source{logger: testLogger(), client: client}
	// onLine below never actually writes to out, but keep it buffered for
	// consistency with the other followPodLogs tests, which call it
	// synchronously with no concurrent reader.
	out := make(chan pipeline.Event, 10)

	simpleErr := errors.New("fatal error in onLineFunc")
	onLine := func(_ string, _ string, _ chan pipeline.Event) error {
		return simpleErr
	}

	start := time.Now()
	err := s.followPodLogs(t.Context(), "ns", "pod", "container", out, onLine)
	elapsed := time.Since(start)

	require.Error(t, err)
	require.ErrorIs(t, err, simpleErr)
	assert.Less(t, elapsed, retryBackoffMidpoint, "a fatal onLineFunc error must not go through the retry backoff")
}

func TestFollowPodLogs_RetriesOnStreamError(t *testing.T) {
	pod := newTestPod("pod", "ns", corev1.PodRunning)
	client := fakekube.NewSimpleClientset(pod)
	reactToLogs(client, "", errors.New("connection refused"))

	s := &Source{logger: testLogger(), client: client}
	// the stream never succeeds here, so nothing is ever written to out, but
	// keep it buffered for consistency with the other followPodLogs tests.
	out := make(chan pipeline.Event, 10)

	ctx, cancel := context.WithTimeout(t.Context(), 1500*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := s.followPodLogs(ctx, "ns", "pod", "container", out, s.processLine)
	elapsed := time.Since(start)

	require.NoError(t, err, "a persistent stream error must be retried, not returned")
	assert.GreaterOrEqual(t, elapsed, retryBackoffMidpoint, "expected at least one retry backoff before the context timed out")
}

func TestFollowPodLogs_StopsOnContextCancel(t *testing.T) {
	pod := newTestPod("pod", "ns", corev1.PodRunning)
	client := fakekube.NewSimpleClientset(pod)

	s := &Source{logger: testLogger(), client: client}
	// Unbuffered on purpose: followPodLogs must never write to out once ctx
	// is already canceled. If it did, this blocking send would hang the
	// test instead of silently passing.
	out := make(chan pipeline.Event)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	err := s.followPodLogs(ctx, "ns", "pod", "container", out, s.processLine)
	require.NoError(t, err)
}

func TestTailPod_StartsWorkerAndStopPodCancelsIt(t *testing.T) {
	pod := newTestPod("pod", "ns", corev1.PodRunning)
	client := fakekube.NewSimpleClientset(pod)
	reactToLogs(client, "hello\n", nil)

	s := &Source{logger: testLogger(), client: client}
	s.initCancels()

	// unlike the followPodLogs tests above, tailPod runs the worker in its
	// own goroutine and the test reads out concurrently via select below, so
	// out can stay unbuffered: the worker's write and the test's read
	// rendezvous directly.
	out := make(chan pipeline.Event)
	var wg sync.WaitGroup

	s.tailPod(t.Context(), pod, out, &wg)

	// tailPod must treat this as a no-op since pod.UID is already tracked in
	// s.cancels. Not asserted directly, but if it weren't a no-op this would
	// spawn a second worker racing the first one over the same single-line
	// fake log stream, which the single <-out receive below can't account
	// for.
	s.tailPod(t.Context(), pod, out, &wg)

	select {
	case evt := <-out:
		assert.Equal(t, "hello", evt.Line.Raw)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for a log line from the tailed pod")
	}

	s.stopPod(pod)

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stopPod did not stop the worker goroutine in time")
	}

	s.mu.Lock()
	_, stillTracked := s.cancels[pod.UID]
	s.mu.Unlock()
	assert.False(t, stillTracked, "cancel func should be removed once the worker stops")
}

func TestTailPod_SkipsNonRunningPod(t *testing.T) {
	pod := newTestPod("pod", "ns", corev1.PodPending)
	client := fakekube.NewSimpleClientset(pod)

	s := &Source{logger: testLogger(), client: client}
	s.initCancels()

	// the pod is non-running so tailPod must skip it and never write to out;
	// unbuffered so a stray write would hang the test instead of passing
	// silently.
	out := make(chan pipeline.Event)
	var wg sync.WaitGroup

	s.tailPod(t.Context(), pod, out, &wg)

	s.mu.Lock()
	_, tracked := s.cancels[pod.UID]
	s.mu.Unlock()
	assert.False(t, tracked, "a non-running pod must not be tailed")
}
