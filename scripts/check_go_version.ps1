##This must be called with  $(MINIMUM_SUPPORTED_GO_MAJOR_VERSION) $(MINIMUM_SUPPORTED_GO_MINOR_VERSION) $(GO_MAJOR_VERSION) $(GO_MINOR_VERSION) in this order
$min_major=$args[0]
$min_minor=$args[1]
$cur_major=$args[2]
$cur_minor=$args[3]
$err_msg="Golang version $cur_major.$cur_minor is not supported, please use least $min_major.$min_minor"
if ( $cur_major -gt $min_major ) {
    exit 0;
}
elseif ($cur_major -lt $min_major) {
    Write-Output $err_msg;
    exit 1;
}
elseif ($cur_minor -lt $min_minor) {
    Write-Output $(GO_VERSION_VALIDATION_ERR_MSG);
    exit 1; 
}