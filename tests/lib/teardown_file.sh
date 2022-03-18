
# any stdout, stderr from now on will go to &3
eval "$(debug)"

# ensure we don't leave crowdsec running if tests are broken or interrupted
./instance-crowdsec stop

