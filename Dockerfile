############################
# STEP 1 build executable binary
############################

FROM golang:alpine AS builder

RUN apk update && apk add make gettext gcc g++


WORKDIR $GOPATH/src/JohnDoeCrowdSec/granola

# COPY the source
COPY ./ .

RUN make build

RUN make install

RUN cp ./docker/docker.yaml /etc/crowdsec/docker.yaml
RUN cp ./docker/acquis.yaml /etc/crowdsec/crowdsec/

############################
# STEP 2
############################

FROM alpine:latest

COPY --from=builder /usr/local/bin/crowdsec /usr/local/bin/crowdsec
COPY --from=builder /usr/local/bin/cscli /usr/local/bin/cscli


COPY --from=builder /etc/crowdsec /etc/crowdsec
COPY --from=builder /var/run/crowdsec /var/run/crowdsec

RUN apk add --update bash rsyslog && rm -rf /var/cache/apk/*

###########################
##### Prepare rsyslog #####
###########################

RUN mkdir -p /etc/rsyslog.d/
RUN mkdir -p /var/spool/rsyslog/
RUN mkdir -p /var/log/rsyslog
RUN touch /var/log/syslog

EXPOSE 514 514

COPY ./docker/rsyslog.conf /etc/rsyslog.conf

###########################################
###### Configure crowdsec ###########
###########################################

RUN cscli config token "6ba94afde0fbf41310f7191934bc1d920245c9f1" 
RUN cscli config installdir "/etc/crowdsec/crowdsec/"
RUN cscli config dbpath "/var/run/crowdsec/crowdsec.db"

RUN cscli update

RUN cscli install collection crowdsec/base-http-scenarios
RUN cscli install collection crowdsec/linux
RUN cscli install collection crowdsec/nginx
RUN cscli install collection crowdsec/sshd

######################################
## Wrapper to launch multi services ##
######################################

COPY ./docker/wrapper.sh .
RUN chmod +x ./wrapper.sh

ENTRYPOINT ["./wrapper.sh"]

