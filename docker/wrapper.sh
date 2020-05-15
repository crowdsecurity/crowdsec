#!/bin/sh

CROWDSEC="crowdsec"
SYSLOG_NG="rsyslogd"


# Start the second process
rsyslogd -n -f /etc/rsyslog.conf &
status=$?
if [ $status -ne 0 ]; then
  echo "Failed to start ${SYSLOG_NG}: $status"
  exit $status
fi


# Start the first process
/usr/local/bin/crowdsec -c /etc/crowdsec/docker.yaml &
status=$?
if [ $status -ne 0 ]; then
  echo "Failed to start ${CROWDSEC}: $status"
  exit $status
fi


# Naive check runs checks once a minute to see if either of the processes exited.
# This illustrates part of the heavy lifting you need to do if you want to run
# more than one service in a container. The container exits with an error
# if it detects that either of the processes has exited.
# Otherwise it loops forever, waking up every 60 seconds

while sleep 60; do
  ps aux |grep ${CROWDSEC} |grep -q -v grep
  PROCESS_1_STATUS=$?
  ps aux |grep ${SYSLOG_NG} |grep -q -v grep
  PROCESS_2_STATUS=0
  # If the greps above find anything, they exit with 0 status
  # If they are not both 0, then something is wrong
  if [ $PROCESS_1_STATUS -ne 0 -o $PROCESS_2_STATUS -ne 0 ]; then
    echo "One of the processes has already exited."
    exit 1
  fi
done