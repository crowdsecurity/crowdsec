#!/bin/bash

go build -o notification-splunk
sudo chown root notification-splunk
sudo chgrp root notification-splunk
sudo mkdir -p  /etc/crowdsec/plugins/
sudo mkdir -p  /etc/crowdsec/notifications/
sudo systemctl stop crowdsec
sudo cp ./notification-splunk  /etc/crowdsec/plugins/
sudo cp ./splunk.yaml /etc/crowdsec/notifications
echo "Please update the configuration at '/etc/crowdsec/notifications/splunk.yaml' and restart crowdsec via 'sudo systemctl restart crowdsec'"