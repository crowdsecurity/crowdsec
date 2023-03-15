package types

import "os"

var SignalChan chan os.Signal = make(chan os.Signal, 1)
