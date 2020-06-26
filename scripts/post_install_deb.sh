systemctl daemon-reload
cscli update
/usr/local/bin/cswizard -i
cscli install collection crowdsecurity/linux
cscli install scenario crowdsecurity/ssh-bf
systemctl start crowdsec