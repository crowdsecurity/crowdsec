systemctl daemon-reload
cscli update
cscli install collection crowdsecurity/linux
cscli install scenario crowdsecurity/ssh-bf
systemctl start crowdsec