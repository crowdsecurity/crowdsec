#!/bin/bash

go build -o notification-http
sudo chown root notification-http
sudo chgrp root notification-http
sudo mkdir -p  /etc/crowdsec/plugins/
sudo mkdir -p  /etc/crowdsec/notifications/
sudo cp ./notification-http  /etc/crowdsec/plugins/
sudo cp ./http.yaml /etc/crowdsec/notifications
sudo systemctl restart crowdsec
