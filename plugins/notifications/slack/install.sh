#!/bin/bash

go build -o notification-slack
sudo chown root notification-slack
sudo chgrp root notification-slack
sudo mkdir -p  /etc/crowdsec/plugins/
sudo mkdir -p  /etc/crowdsec/notifications/
sudo systemctl stop crowdsec
sudo cp ./notification-slack /etc/crowdsec/plugins/
sudo cp ./slack.yaml /etc/crowdsec/notifications/
echo "Please update the configuration at '/etc/crowdsec/notifications/slack.yaml' and restart crowdsec via 'sudo systemctl restart crowdsec'"