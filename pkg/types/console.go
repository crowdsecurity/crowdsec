package types

const (
	SEND_CUSTOM_SCENARIOS  = "custom"
	SEND_TAINTED_SCENARIOS = "tainted"
	SEND_MANUAL_SCENARIOS  = "manual"
	SEND_LIVE_DECISIONS    = "live_decisions"
)

var CONSOLE_CONFIGS = []string{SEND_CUSTOM_SCENARIOS, SEND_LIVE_DECISIONS, SEND_MANUAL_SCENARIOS, SEND_TAINTED_SCENARIOS}

type ConsoleConfig struct {
	ActivatedSharing []string
}
