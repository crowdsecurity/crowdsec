CSCLI_BIN_INSTALLED="/usr/local/bin/cscli"

systemctl daemon-reload
${CSCLI_BIN_INSTALLED} update
${CSCLI_BIN_INSTALLED} install collection crowdsecurity/linux
${CSCLI_BIN_INSTALLED} install scenario crowdsecurity/ssh-bf
${CSCLI_BIN_INSTALLED} api register >> /etc/crowdsec/config/api.yaml || ${CSCLI_BIN_INSTALLED} api reset >> /etc/crowdsec/config/api.yaml || log_err "unable to register, skipping crowdsec api registration"
