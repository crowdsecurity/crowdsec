#this is is straight up conversion of test_env.sh, not pretty but does the job

param (
    [string]$base = ".\tests",
    [switch]$help = $false
)

function show_help() {
    Write-Output ".\test_env.ps1 -d tests #creates test env in .\tests"
}

function create_tree() {
	$null = New-Item -ItemType Directory $data_dir
	$null = New-Item -ItemType Directory $log_dir
	$null = New-Item -ItemType Directory $config_dir
	$null = New-Item -ItemType Directory $parser_dir
	$null = New-Item -ItemType Directory $parser_s00
	$null = New-Item -ItemType Directory $parser_s01
	$null = New-Item -ItemType Directory $parser_s02
	$null = New-Item -ItemType Directory $scenarios_dir
	$null = New-Item -ItemType Directory $postoverflows_dir
	$null = New-Item -ItemType Directory $cscli_dir
	$null = New-Item -ItemType Directory $hub_dir
    $null = New-Item -ItemType Directory $config_dir\$notif_dir
	$null = New-Item -ItemType Directory $base\$plugins_dir
}

function copy_file() {
    $null = Copy-Item ".\config\profiles.yaml" $config_dir
	$null = Copy-Item  ".\config\simulation.yaml" $config_dir
	$null = Copy-Item ".\cmd\crowdsec\crowdsec.exe" $base
	$null = Copy-Item ".\cmd\crowdsec-cli\cscli.exe" $base
	$null = Copy-Item -Recurse ".\config\patterns" $config_dir
	$null = Copy-Item ".\config\acquis.yaml" $config_dir
	$null = New-Item -ItemType File $config_dir\local_api_credentials.yaml
	$null = New-Item -ItemType File $config_dir\online_api_credentials.yaml
	#envsubst < "./config/dev.yaml" > $BASE/dev.yaml
    Copy-Item .\config\dev.yaml $base\dev.yaml
    $plugins | ForEach-Object {
        Copy-Item .\cmd\notification-$_\notification-$_.exe $base\$plugins_dir\notification-$_.exe
		Copy-Item .\cmd\notification-$_\$_.yaml $config_dir\$notif_dir\$_.yaml
    }
}

function setup() {
	& $base\cscli.exe -c "$config_file" hub update
	& $base\cscli.exe -c "$config_file" collections install crowdsecurity/linux crowdsecurity/windows
}

function setup_api() {
	& $base\cscli.exe -c "$config_file" machines add test -p testpassword -f $config_dir\local_api_credentials.yaml --force
}

if ($help) {
    show_help
    exit 0;
}

$null = New-Item -ItemType Directory $base

$base=(Resolve-Path $base).Path
$data_dir="$base\data"
$log_dir="$base\logs\"
$config_dir="$base\config"
$config_file="$base\dev.yaml"
$cscli_dir="$config_dir\crowdsec-cli"
$parser_dir="$config_dir\parsers"
$parser_s00="$parser_dir\s00-raw"
$parser_s01="$parser_dir\s01-parse"
$parser_s02="$parser_dir\s02-enrich"
$scenarios_dir="$config_dir\scenarios"
$postoverflows_dir="$config_dir\postoverflows"
$hub_dir="$config_dir\hub"
$plugins=@("http", "slack", "splunk", "email", "sentinel")
$plugins_dir="plugins"
$notif_dir="notifications"


Write-Output "Creating test tree in $base"
create_tree
Write-Output "Tree created"
Write-Output "Copying files"
copy_file
Write-Output "Files copied"
Write-Output "Setting up configuration"
$cur_path=$pwd
Set-Location $base
setup_api
setup
Set-Location $cur_path