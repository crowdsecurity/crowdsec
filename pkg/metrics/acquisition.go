package metrics

var AcquisitionMetricsNames = []string{}

func RegisterAcquisitionMetric(metricName string) {
	AcquisitionMetricsNames = append(AcquisitionMetricsNames, metricName)
}
