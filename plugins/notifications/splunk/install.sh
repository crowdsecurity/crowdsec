#!/bin/bash

go build -o notification-splunk
sudo chown root notification-splunk
sudo chgrp root notification-splunk
sudo mkdir -p  /etc/crowdsec/plugins/
sudo mkdir -p  /etc/crowdsec/notifications/
sudo cp ./notification-splunk  /etc/crowdsec/plugins/
sudo cp ./splunk.yaml /etc/crowdsec/notifications
sudo systemctl restart crowdsec
