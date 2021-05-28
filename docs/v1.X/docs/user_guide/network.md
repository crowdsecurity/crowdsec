
# Ports inventory

 - `tcp/8080` exposes a [REST API](https://crowdsecurity.github.io/api_doc/index.html?urls.primaryName=LAPI) for bouncers, `cscli` and comunication between crowdsec agent and local api
 - `tcp/6060` (endpoint `/metrics`) exposes [prometheus metrics](https://doc.crowdsec.net/Crowdsec/v1/observability/prometheus/)
 - `tcp/6060` (endpoint `/debug`) exposes pprof debugging metrics

# Outgoing connections

 - Local API connects to `tcp/443` on `api.crowdsec.net` (signal push and blocklists pull)
 - `cscli` connects to `tcp/443` on `raw.githubusercontent.com` to fetch scenarios, parsers etc.
 - `cscli dashboard` fetches metabase configuration from a s3 bucket (`https://crowdsec-statics-assets.s3-eu-west-1.amazonaws.com/`)



# Comunication between components

## Bouncers -> Local API

 - Bouncers are using Local API on `tcp/8080` by default

## Agents -> Local API

 - Agents connect to local API on port `tcp/8080` (only relevant )

!!! warning
    If there is an error in the agent configuration, it will also cause the Local API to fail if both of them are running in the same machine !
    Both components need proper configuration to run (we decide to keep this behavior to detect agent or local API errors on start).

## Local API -> Central API

 - Central API is reached on port `tcp/443` by Local API. The FQDN is `api.crowdsec.net`

## Local API -> Database

 - When using a networked database (PostgreSQL or MySQL), only the local API needs to access the database, agents don't have to be able to comunicate with it.

## Prometheus -> Agents

 - If you're scrapping prometheus metrics from your agents or your local API, you need to allow inbound connections to `tcp/6060`



