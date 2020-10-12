# Known bugs and limitations

## Some users experience crash on 32bits architecture

For now, on 32bit architecture there's a alignment bug in
https://github.com/jamiealquiza/tachymeter library that prevents
crowdsec from running properly with prometheus gathering metrics.
The workaround is to disable prometheus until the bug is fixed.
(We'll get rid of this library in the near future)
