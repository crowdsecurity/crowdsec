##This must be called with  $(MINIMUM_SUPPORTED_GO_MAJOR_VERSION) $(MINIMUM_SUPPORTED_GO_MINOR_VERSION) in this order
$min_major=$args[0]
$min_minor=$args[1]
$goversion = (go env GOVERSION).replace("go","").split(".")
$goversion_major=$goversion[0]
$goversion_minor=$goversion[1]
$err_msg="Golang version $goversion_major.$goversion_minor is not supported, please use least $min_major.$min_minor"

if ( $goversion_major -gt $min_major ) {
    exit 0;
}
elseif ($goversion_major -lt $min_major) {
    Write-Output $err_msg;
    exit 1;
}
elseif ($goversion_minor -lt $min_minor) {
    Write-Output $(GO_VERSION_VALIDATION_ERR_MSG);
    exit 1; 
}