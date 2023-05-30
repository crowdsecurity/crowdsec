# Hacking

## Install deps, dev-deps and run test

```sh
$ git clone git@github.com:goombaio/namegenerator.git
$ cd skeleton
export GO111MODULE=on  # ref: https://dave.cheney.net/2018/07/16/using-go-modules-with-travis-ci
make deps
make dev-deps
make test
```
