# APIL


## Run APIL

```
cd cmd/api
go run main.go
```

## generate sample data

```
cd cmd/sample
go run main.go
```

requests will be sent to apil and data will be generated in sqlite db `ent.db` containing data in `sample.json` file.

## Curl cheat sheet
```
curl -XGET "http://localhost:8080/signals?scenario=crowdsecurity%2Fscenario1" -H "accept: application/json"

curl -XGET "http://localhost:8080/decisions/ip/1.1.1.1" -H "accept: application/json"
```

