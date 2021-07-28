sudo systemctl stop crowdsec
go build . -o notification-slack
sudo chown root notification-slack
sudo chgrp root notification-slack
sudo mkdir -p  /etc/crowdsec/plugins/
sudo mkdir -p  /etc/crowdsec/notifications/
sudo cp ./notification-slack /etc/crowdsec/plugins/
