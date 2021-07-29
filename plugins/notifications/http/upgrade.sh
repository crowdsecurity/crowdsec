#!/bin/bash

sudo systemctl stop crowdsec
go build -o notification-http
sudo chown root notification-http
sudo chgrp root notification-http
sudo cp ./notification-http /etc/crowdsec/plugins/
sudo systemctl restart crowdsec