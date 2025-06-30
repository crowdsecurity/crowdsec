package acquisition

var AcquisitionMetricsNames = []string{}

func RegisterAcquisitionMetric(metricName string) {
	AcquisitionMetricsNames = append(AcquisitionMetricsNames, metricName)
}
