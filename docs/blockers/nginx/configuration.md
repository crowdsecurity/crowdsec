The blocker configuration is in `/usr/local/lua/crowdsec/crowdsec.conf` :

```
DB_PATH=/var/lib/crowdsec/data/crowdsec.db       # The path of the crowdsec SQlite3 database.
LOG_FILE=/tmp/lua_mod.log                        # Path to file to log
CACHE_EXPIRATION=1                               # Cache expiration in seconds
CACHE_SIZE=1000                                  # Max cache size
```

The nginx configuration file used by nginx to run the module is `/etc/nginx/conf.d/crowdsec_nginx.conf`.