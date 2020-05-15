package main

import (
	"fmt"
	"github.com/crowdsecurity/crowdsec/pkg/acquisition"
)

func loadAcquisition() (*acquisition.FileAcquisCtx, error) {
	var acquisitionCTX *acquisition.FileAcquisCtx
	var err error
	/*Init the acqusition : from cli or from acquis.yaml file*/
	if cConfig.SingleFile != "" {
		var input acquisition.FileCtx
		input.Filename = cConfig.SingleFile
		input.Mode = acquisition.CATMODE
		input.Labels = make(map[string]string)
		input.Labels["type"] = cConfig.SingleFileLabel
		acquisitionCTX, err = acquisition.InitReaderFromFileCtx([]acquisition.FileCtx{input})
	} else { /* Init file reader if we tail */
		acquisitionCTX, err = acquisition.InitReader(cConfig.AcquisitionFile)
	}
	if err != nil {
		return nil, fmt.Errorf("unable to start file acquisition, bailout %v", err)
	}
	if acquisitionCTX == nil {
		return nil, fmt.Errorf("no inputs to process")
	}
	if cConfig.Profiling == true {
		acquisitionCTX.Profiling = true
	}

	return acquisitionCTX, nil
}
