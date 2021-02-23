# Docker Compose

This example explains how to integrate Crowdsec in environment deployed with docker-compose. It set up multiple containers :

![Schema](schema.png)

This example contains multiple containers :
* app : apache server serving index.html containing an `hello world`
* reverse-proxy : nginx that serving this app from the host
* crowdsec : it will read reverse-proxy logs from the shared volume
* dashboard : we use [metabase](https://hub.docker.com/r/metabase/metabase) to display crowdsec database data.

We have chosen the simplest way to collect logs (by sharing volumes between containers), if you are in production, you are probably using logging-driver to centralize logs with rsyslog or another driver, so don't forget to adapt the crowdsec docker-compose configuration to read the logs properly.

**Prerequisites:** [Docker](https://docs.docker.com/engine/install/) / [Docker Compose](https://docs.docker.com/compose/install/)

## Step 1: Run all services in docker-compose.yml

[docker compose file](docker-compose.yml) contains the yaml configuration to deploy all the containers together by on command.

Deploy the stack using : `docker-compose up -d`

Then to see the status : `docker-compose ps`

## Step 2: Install & Configure bouncer on host


## Step 3: Configure dashboard

The dashboard is deployed using static metabase.db ([explained here](https://docs.crowdsec.net/faq/#how-to-have-a-dashboard-without-docker)), so you have to use the defaults credentials to connect to the database, then update immediatly those credentials.

Then you need to update the crowdsec database path :
* Go to `http://localhost:3003/` and connect with defaults credentials
* Go to `http://localhost:3003/admin/databases/2` and modify the file path `/var/lib/crowdsec/data/crowdsec.db`
* Save changes and go back to the home, you'll see the active decisions pulled from the online API.

## Step 4: Simulate an attack and check detection + prevention
