package csconfig

/*Configurations needed for crowdsec to load parser/scenarios/... + acquisition*/
type CrowdsecServiceCfg struct {
	AcquisitionFilePath  string            `yaml:"acquisition_path,omitempty"`
	ParserRoutinesCount  int               `yaml:"parser_routines"`
	BucketsRoutinesCount int               `yaml:"buckets_routines"`
	OutputRoutinesCount  int               `yaml:"output_routines"`
	SimulationConfig     *SimulationConfig `yaml:"-"`
	LintOnly             bool              `yaml:"-"`                          //if set to true, exit after loading configs
	BucketStateFile      string            `yaml:"state_input_file,omitempty"` //if we need to unserialize buckets at start
	BucketStateDumpDir   string            `yaml:"state_output_dir,omitempty"` //if we need to unserialize buckets on shutdown
	BucketsGCEnabled     bool              `yaml:"-"`                          //we need to garbage collect buckets when in forensic mode

	HubDir             string `yaml:"-"`
	DataDir            string `yaml:"-"`
	ConfigDir          string `yaml:"-"`
	HubIndexFile       string `yaml:"-"`
	SimulationFilePath string `yaml:"-"`
}
