#!/bin/bash

sudo systemctl stop crowdsec
go build -o notification-splunk
sudo chown root notification-splunk
sudo chgrp root notification-splunk
sudo cp ./notification-splunk /etc/crowdsec/plugins/
sudo systemctl restart crowdsec