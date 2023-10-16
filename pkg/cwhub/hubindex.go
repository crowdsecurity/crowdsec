package cwhub


const (
	HubIndexFile = ".index.json"

	// managed item types
	COLLECTIONS   = "collections"
	PARSERS       = "parsers"
	POSTOVERFLOWS = "postoverflows"
	SCENARIOS     = "scenarios"
)

var (
	// XXX: The order is important, as it is used to construct the
	//      index tree in memory --> collections must be last
	ItemTypes = []string{PARSERS, POSTOVERFLOWS, SCENARIOS, COLLECTIONS}
	hubIdx    = HubIndex{nil}
)


type HubIndex struct {
	Items map[string]map[string]Item
}
