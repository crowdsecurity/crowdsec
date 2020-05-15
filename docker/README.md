# Crowdwatch with docker


## Getting Started

Go in the main folder of crowdsec (if you are in the folder `docker/` please `cd ..`)


- Build the docker image

```
docker build -t crowdsec .
```


- Run the docker


```
docker run -d -p 514:514 --name crowdsec -v /var/run/crowdsec/crowdsec.db:/var/run/crowdsec/crowdsec.db crowdsec
```

:warning: Be sure that your ban plugin will get decision from the db located in `/var/run/crowdsec/crowdsec.db` on your host.




## TODO:

 - Be sure that bans are applied on the host
    - Check that the sqlite db is created by crowdsec in the docker and read by the ban plugin on the host
 - Forward traffic to the docker syslog (127.0.0.1:514) and check that logs are correctly parsed
