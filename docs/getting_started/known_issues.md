# Known bugs and limitations

## Some users experience crash on 32bits architecture

For now, on 32bit architecture there's a alignment bug in
https://github.com/jamiealquiza/tachymeter library that prevents
crowdsec from running properly with prometheus gathering metrics.
All versions since v0.3.1 are affected.

The workaround is to disable prometheus until the bug is fixed.  For
doing this you'll have to set `prometheus` to `false` in the file
`/etc/crowdsec/config/default.yaml`.

We are working on solving this issue by getting rid of the culprit
library.
