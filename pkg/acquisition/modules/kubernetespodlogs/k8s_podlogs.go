//go:build !no_datasource_k8s_podlogs

package kubernetespodlogs

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	yaml "github.com/goccy/go-yaml"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"

	"github.com/crowdsecurity/go-cs-lib/trace"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

const (
	defaultAPIServer      = "https://kubernetes.default.svc"
	defaultTokenPath      = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	defaultCACertPath     = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	defaultResyncPeriod   = 30 * time.Second
	defaultRequestTimeout = 10 * time.Second
	defaultMaxLineBytes   = 1 << 20
	maxErrorBodyBytes     = 4096
	userAgent             = "crowdsec-k8s-podlogs"
	nodeNameEnvKey        = "NODE_NAME"
)

type KubernetesPodLogsConfig struct {
	configuration.DataSourceCommonCfg `yaml:",inline"`

	APIServer         string        `yaml:"api_server"`
	TokenPath         string        `yaml:"token_file"`
	BearerToken       string        `yaml:"bearer_token"`
	CACertPath        string        `yaml:"ca_cert"`
	InsecureSkipTLS   bool          `yaml:"insecure_skip_verify"`
	NodeName          string        `yaml:"node_name"`
	Namespaces        []string      `yaml:"namespaces"`
	LabelSelector     string        `yaml:"label_selector"`
	Containers        []string      `yaml:"containers"`
	SinceSeconds      *int64        `yaml:"since_seconds"`
	TailLines         *int64        `yaml:"tail_lines"`
	LimitBytes        int64         `yaml:"limit_bytes"`
	IncludeTimestamps bool          `yaml:"timestamps"`
	Follow            bool          `yaml:"follow"`
	ResyncPeriod      time.Duration `yaml:"resync_period"`
	RequestTimeout    time.Duration `yaml:"request_timeout"`
	MaxLineBytes      int           `yaml:"max_line_bytes"`
}

type podLogTarget struct {
	Namespace string
	Pod       string
	Container string
}

func (t podLogTarget) String() string {
	return fmt.Sprintf("%s/%s/%s", t.Namespace, t.Pod, t.Container)
}

type podLogKey struct {
	Namespace string
	Pod       string
	Container string
}

type KubernetesPodLogsSource struct {
	config          KubernetesPodLogsConfig
	logger          *log.Entry
	metricsLevel    metrics.AcquisitionMetricsLevel
	apiClient       *http.Client
	streamClient    *http.Client
	authToken       string
	apiServer       string
	namespaceFilter map[string]struct{}
	containerFilter map[string]struct{}
	out             chan types.Event
	activeStreams   map[podLogKey]context.CancelFunc
	activeMu        sync.Mutex
}

func defaultKubePodLogsConfig() KubernetesPodLogsConfig {
	return KubernetesPodLogsConfig{
		APIServer:      defaultAPIServer,
		TokenPath:      defaultTokenPath,
		CACertPath:     defaultCACertPath,
		Follow:         true,
		ResyncPeriod:   defaultResyncPeriod,
		RequestTimeout: defaultRequestTimeout,
		MaxLineBytes:   defaultMaxLineBytes,
	}
}

func (k *KubernetesPodLogsSource) normalizeConfig(cfg *KubernetesPodLogsConfig) {
	cfg.APIServer = strings.TrimSpace(cfg.APIServer)
	cfg.TokenPath = strings.TrimSpace(cfg.TokenPath)
	cfg.CACertPath = strings.TrimSpace(cfg.CACertPath)
	cfg.BearerToken = strings.TrimSpace(cfg.BearerToken)
	cfg.LabelSelector = strings.TrimSpace(cfg.LabelSelector)
	cfg.NodeName = strings.TrimSpace(cfg.NodeName)

	if cfg.NodeName == "" {
		cfg.NodeName = strings.TrimSpace(os.Getenv(nodeNameEnvKey))
	}

	if cfg.APIServer == "" {
		cfg.APIServer = defaultAPIServer
	}

	if cfg.Mode == "" {
		cfg.Mode = configuration.TAIL_MODE
	}

	if cfg.ResyncPeriod == 0 {
		cfg.ResyncPeriod = defaultResyncPeriod
	}

	if cfg.RequestTimeout == 0 {
		cfg.RequestTimeout = defaultRequestTimeout
	}

	if cfg.MaxLineBytes == 0 {
		cfg.MaxLineBytes = defaultMaxLineBytes
	}
}

func (k *KubernetesPodLogsSource) validateConfig(cfg KubernetesPodLogsConfig) error {
	if cfg.NodeName == "" {
		return errors.New("node_name must be set or NODE_NAME environment variable must be provided")
	}

	if cfg.Mode != configuration.TAIL_MODE {
		return fmt.Errorf("unsupported mode %s for k8s-podlogs datasource", cfg.Mode)
	}

	if cfg.LimitBytes < 0 {
		return errors.New("limit_bytes cannot be negative")
	}

	if cfg.SinceSeconds != nil && *cfg.SinceSeconds < 0 {
		return errors.New("since_seconds cannot be negative")
	}

	if cfg.TailLines != nil && *cfg.TailLines < 0 {
		return errors.New("tail_lines cannot be negative")
	}

	if cfg.ResyncPeriod < 0 {
		return errors.New("resync_period cannot be negative")
	}

	if cfg.RequestTimeout < 0 {
		return errors.New("request_timeout cannot be negative")
	}

	if cfg.MaxLineBytes < 0 {
		return errors.New("max_line_bytes cannot be negative")
	}

	if cfg.TokenPath == "" && cfg.BearerToken == "" {
		return errors.New("either token_file or bearer_token must be set")
	}

	if cfg.APIServer == "" {
		return errors.New("api_server cannot be empty")
	}

	return nil
}

func (k *KubernetesPodLogsSource) GetUuid() string {
	return k.config.UniqueId
}

func (k *KubernetesPodLogsSource) GetMetrics() []prometheus.Collector {
	return []prometheus.Collector{metrics.K8SPodLogsLines}
}

func (k *KubernetesPodLogsSource) GetAggregMetrics() []prometheus.Collector {
	return []prometheus.Collector{metrics.K8SPodLogsLines}
}

func (k *KubernetesPodLogsSource) GetMode() string {
	return k.config.Mode
}

func (k *KubernetesPodLogsSource) GetName() string {
	return "k8s-podlogs"
}

func (k *KubernetesPodLogsSource) Dump() any {
	return k
}

func (*KubernetesPodLogsSource) CanRun() error {
	return nil
}

func (k *KubernetesPodLogsSource) UnmarshalConfig(yamlConfig []byte) error {
	cfg := defaultKubePodLogsConfig()

	if err := yaml.UnmarshalWithOptions(yamlConfig, &cfg, yaml.Strict()); err != nil {
		return fmt.Errorf("cannot parse k8s-podlogs configuration: %s", yaml.FormatError(err, false, false))
	}

	k.normalizeConfig(&cfg)

	if err := k.validateConfig(cfg); err != nil {
		return err
	}

	k.namespaceFilter = buildSet(cfg.Namespaces)
	k.containerFilter = buildSet(cfg.Containers)

	k.config = cfg

	return nil
}

func (k *KubernetesPodLogsSource) Configure(config []byte, logger *log.Entry, metricsLevel metrics.AcquisitionMetricsLevel) error {
	k.logger = logger
	k.metricsLevel = metricsLevel

	if err := k.UnmarshalConfig(config); err != nil {
		return err
	}

	k.apiServer = strings.TrimRight(k.config.APIServer, "/")
	if k.apiServer == "" {
		k.apiServer = defaultAPIServer
	}

	if err := k.loadToken(); err != nil {
		return err
	}

	if err := k.buildHTTPClients(); err != nil {
		return err
	}

	k.activeStreams = make(map[podLogKey]context.CancelFunc)

	if k.logger != nil && k.logger.Logger.IsLevelEnabled(log.TraceLevel) {
		safeCfg := k.config
		if safeCfg.BearerToken != "" {
			safeCfg.BearerToken = "***"
		}
		k.logger.Tracef("k8s-podlogs configuration: %+v", safeCfg)
	}

	return nil
}

func (k *KubernetesPodLogsSource) StreamingAcquisition(ctx context.Context, out chan types.Event, t *tomb.Tomb) error {
	k.out = out

	runCtx, cancel := context.WithCancel(ctx)

	t.Go(func() error {
		<-t.Dying()
		cancel()
		return nil
	})

	t.Go(func() error {
		defer trace.CatchPanic("crowdsec/acquis/k8s-podlogs/live")
		return k.run(runCtx, t)
	})

	return nil
}

func (k *KubernetesPodLogsSource) run(ctx context.Context, t *tomb.Tomb) error {
	if err := k.syncStreams(ctx, t); err != nil {
		return err
	}

	ticker := time.NewTicker(k.config.ResyncPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			k.stopAll()
			return nil
		case <-ticker.C:
			if err := k.syncStreams(ctx, t); err != nil {
				k.logger.Errorf("k8s-podlogs sync error: %v", err)
			}
		}
	}
}

func (k *KubernetesPodLogsSource) syncStreams(ctx context.Context, t *tomb.Tomb) error {
	targets, err := k.listTargets(ctx)
	if err != nil {
		return err
	}

	desired := make(map[podLogKey]struct{}, len(targets))

	for _, target := range targets {
		key := target.key()
		desired[key] = struct{}{}
		k.startStreamIfNeeded(ctx, t, target)
	}

	k.stopMissing(desired)

	return nil
}

func (k *KubernetesPodLogsSource) listTargets(ctx context.Context) ([]podLogTarget, error) {
	pods, err := k.fetchPods(ctx)
	if err != nil {
		return nil, err
	}

	targets := make([]podLogTarget, 0)

	for _, pod := range pods {
		if pod.Status.Phase != corev1.PodRunning {
			continue
		}

		if !k.allowedNamespace(pod.Namespace) {
			continue
		}

		for _, container := range pod.Spec.Containers {
			if !k.allowedContainer(container.Name) {
				continue
			}

			if !isContainerRunning(pod.Status.ContainerStatuses, container.Name) {
				continue
			}

			targets = append(targets, podLogTarget{Namespace: pod.Namespace, Pod: pod.Name, Container: container.Name})
		}
	}

	return targets, nil
}

func (k *KubernetesPodLogsSource) fetchPods(ctx context.Context) ([]corev1.Pod, error) {
	endpoint := fmt.Sprintf("%s/api/v1/pods", k.apiServer)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("building pods request: %w", err)
	}

	query := req.URL.Query()
	query.Set("fieldSelector", fields.OneTermEqualSelector("spec.nodeName", k.config.NodeName).String())
	if k.config.LabelSelector != "" {
		query.Set("labelSelector", k.config.LabelSelector)
	}
	req.URL.RawQuery = query.Encode()
	k.decorateRequest(req)
	req.Header.Set("Accept", "application/json")

	resp, err := k.apiClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("listing pods: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("listing pods failed: %s: %s", resp.Status, readBodySnippet(resp.Body))
	}

	var list corev1.PodList
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return nil, fmt.Errorf("decoding pods response: %w", err)
	}

	return list.Items, nil
}

func (k *KubernetesPodLogsSource) startStreamIfNeeded(ctx context.Context, t *tomb.Tomb, target podLogTarget) {
	key := target.key()

	k.activeMu.Lock()
	if _, exists := k.activeStreams[key]; exists {
		k.activeMu.Unlock()
		return
	}

	streamCtx, cancel := context.WithCancel(ctx)
	k.activeStreams[key] = cancel
	k.activeMu.Unlock()

	t.Go(func() error {
		defer func() {
			cancel()
			k.removeStream(key)
		}()

		if err := k.consumeLogs(streamCtx, target); err != nil && !errors.Is(err, context.Canceled) {
			k.logger.Errorf("log stream %s failed: %v", key.String(), err)
		}

		return nil
	})
}

func (k *KubernetesPodLogsSource) consumeLogs(ctx context.Context, target podLogTarget) error {
	req, err := k.newLogRequest(ctx, target)
	if err != nil {
		return err
	}

	resp, err := k.streamClient.Do(req)
	if err != nil {
		return fmt.Errorf("opening log stream for %s: %w", target.String(), err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("log stream for %s failed: %s: %s", target.String(), resp.Status, readBodySnippet(resp.Body))
	}

	return k.scanStream(ctx, resp.Body, target)
}

func (k *KubernetesPodLogsSource) scanStream(ctx context.Context, body io.ReadCloser, target podLogTarget) error {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = body.Close()
		case <-done:
		}
	}()

	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 0, 64*1024), k.config.MaxLineBytes)

	for scanner.Scan() {
		k.emitLine(target, scanner.Text())
	}

	close(done)

	if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("reading log stream for %s: %w", target.String(), err)
	}

	return nil
}

func (k *KubernetesPodLogsSource) emitLine(target podLogTarget, raw string) {
	line := strings.TrimRight(raw, "\r\n")
	if line == "" {
		return
	}

	labels := k.buildLabels(target)

	evt := types.MakeEvent(k.config.UseTimeMachine, types.LOG, true)
	evt.Line = types.Line{
		Raw:     line,
		Labels:  labels,
		Time:    time.Now().UTC(),
		Src:     target.String(),
		Process: true,
		Module:  k.GetName(),
	}

	if k.metricsLevel != metrics.AcquisitionMetricsLevelNone {
		metrics.K8SPodLogsLines.WithLabelValues(k.metricSource(), k.GetName(), labels["type"]).Inc()
	}

	k.out <- evt
}

func (k *KubernetesPodLogsSource) buildLabels(target podLogTarget) map[string]string {
	labels := make(map[string]string, len(k.config.Labels)+4)
	for key, value := range k.config.Labels {
		labels[key] = value
	}

	labels["k8s_namespace"] = target.Namespace
	labels["k8s_pod"] = target.Pod
	labels["k8s_container"] = target.Container
	labels["k8s_node"] = k.config.NodeName

	return labels
}

func (k *KubernetesPodLogsSource) metricSource() string {
	if k.config.Name != "" {
		return k.config.Name
	}

	return k.config.NodeName
}

func (k *KubernetesPodLogsSource) newLogRequest(ctx context.Context, target podLogTarget) (*http.Request, error) {
	endpoint := fmt.Sprintf("%s/api/v1/namespaces/%s/pods/%s/log", k.apiServer, target.Namespace, target.Pod)

	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid log endpoint: %w", err)
	}

	query := u.Query()
	query.Set("container", target.Container)
	query.Set("follow", fmt.Sprintf("%t", k.config.Follow))
	if k.config.IncludeTimestamps {
		query.Set("timestamps", "true")
	}
	if k.config.SinceSeconds != nil {
		query.Set("sinceSeconds", fmt.Sprintf("%d", *k.config.SinceSeconds))
	}
	if k.config.TailLines != nil {
		query.Set("tailLines", fmt.Sprintf("%d", *k.config.TailLines))
	}
	if k.config.LimitBytes > 0 {
		query.Set("limitBytes", fmt.Sprintf("%d", k.config.LimitBytes))
	}
	u.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("building log request: %w", err)
	}

	k.decorateRequest(req)
	req.Header.Set("Accept", "text/plain")
	return req, nil
}

func (k *KubernetesPodLogsSource) decorateRequest(req *http.Request) {
	req.Header.Set("User-Agent", userAgent)
	if k.authToken != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", k.authToken))
	}
}

func (k *KubernetesPodLogsSource) startTLSConfig() (*tls.Config, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}

	if k.config.InsecureSkipTLS {
		tlsConfig.InsecureSkipVerify = true
		return tlsConfig, nil
	}

	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}

	if k.config.CACertPath != "" {
		pemBytes, err := os.ReadFile(k.config.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("reading CA certificate: %w", err)
		}
		if ok := pool.AppendCertsFromPEM(pemBytes); !ok {
			return nil, errors.New("unable to append CA certificate")
		}
	}

	tlsConfig.RootCAs = pool

	return tlsConfig, nil
}

func (k *KubernetesPodLogsSource) buildHTTPClients() error {
	tlsConfig, err := k.startTLSConfig()
	if err != nil {
		return err
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	k.apiClient = &http.Client{
		Timeout:   k.config.RequestTimeout,
		Transport: transport,
	}

	k.streamClient = &http.Client{
		Transport: transport,
	}

	return nil
}

func (k *KubernetesPodLogsSource) loadToken() error {
	if k.config.BearerToken != "" {
		k.authToken = k.config.BearerToken
		return nil
	}

	bytes, err := os.ReadFile(k.config.TokenPath)
	if err != nil {
		return fmt.Errorf("reading token file %s: %w", k.config.TokenPath, err)
	}

	token := strings.TrimSpace(string(bytes))
	if token == "" {
		return errors.New("token file is empty")
	}

	k.authToken = token

	return nil
}

func (k *KubernetesPodLogsSource) stopMissing(desired map[podLogKey]struct{}) {
	k.activeMu.Lock()
	defer k.activeMu.Unlock()

	for key, cancel := range k.activeStreams {
		if _, ok := desired[key]; ok {
			continue
		}
		cancel()
		delete(k.activeStreams, key)
	}
}

func (k *KubernetesPodLogsSource) stopAll() {
	k.activeMu.Lock()
	defer k.activeMu.Unlock()

	for key, cancel := range k.activeStreams {
		k.logger.Debugf("stopping log stream %s", key.String())
		cancel()
	}

	k.activeStreams = make(map[podLogKey]context.CancelFunc)
}

func (k *KubernetesPodLogsSource) removeStream(key podLogKey) {
	k.activeMu.Lock()
	delete(k.activeStreams, key)
	k.activeMu.Unlock()
}

func (k *KubernetesPodLogsSource) allowedNamespace(ns string) bool {
	if len(k.namespaceFilter) == 0 {
		return true
	}

	_, ok := k.namespaceFilter[ns]
	return ok
}

func (k *KubernetesPodLogsSource) allowedContainer(container string) bool {
	if len(k.containerFilter) == 0 {
		return true
	}

	_, ok := k.containerFilter[container]
	return ok
}

func buildSet(items []string) map[string]struct{} {
	set := make(map[string]struct{})
	for _, item := range items {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		set[trimmed] = struct{}{}
	}
	return set
}

func isContainerRunning(statuses []corev1.ContainerStatus, name string) bool {
	for _, status := range statuses {
		if status.Name == name && status.State.Running != nil {
			return true
		}
	}

	return false
}

func (t podLogTarget) key() podLogKey {
	return podLogKey{
		Namespace: t.Namespace,
		Pod:       t.Pod,
		Container: t.Container,
	}
}

func (k podLogKey) String() string {
	return fmt.Sprintf("%s/%s/%s", k.Namespace, k.Pod, k.Container)
}

func readBodySnippet(body io.ReadCloser) string {
	defer body.Close()
	data, err := io.ReadAll(io.LimitReader(body, maxErrorBodyBytes))
	if err != nil {
		return "<unavailable>"
	}

	return strings.TrimSpace(string(data))
}
