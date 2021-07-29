#!/bin/bash

go build -o notification-http
sudo chown root notification-http
sudo chgrp root notification-http
sudo mkdir -p  /etc/crowdsec/plugins/
sudo mkdir -p  /etc/crowdsec/notifications/
sudo systemctl stop crowdsec
sudo cp ./notification-http  /etc/crowdsec/plugins/
sudo cp ./http.yaml /etc/crowdsec/notifications
echo "Please update the configuration at '/etc/crowdsec/notifications/http.yaml' and restart crowdsec via 'sudo systemctl restart crowdsec'"
