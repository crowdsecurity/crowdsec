
<center>[nginx {{plugins.name}} github](https://github.com/crowdsecurity/cs-nginx-plugin/)</center>

First, please [download the latest version](https://github.com/crowdsecurity/cs-nginx-plugin/releases/latest) of our nginx blocker.

And run the following commands:

```bash
tar xzvf cs-nginx-plugin-release.tgz
```
```bash
cd cs-nginx-plugin-vX.Y.Z/
```
```bash
sudo ./install.sh
```
```bash
sudo systemctl restart nginx
```

When an IP is referenced in the database, any request from this IP will lead to a `403` reply.

