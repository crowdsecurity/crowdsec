#!/bin/bash

sudo systemctl stop crowdsec
go build -o notification-slack
sudo chown root notification-slack
sudo chgrp root notification-slack
sudo cp ./notification-slack /etc/crowdsec/plugins/
sudo systemctl restart crowdsec