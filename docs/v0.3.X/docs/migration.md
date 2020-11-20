# Migration from v0.X to v1.X

To upgrade {{v0X.crowdsec.name}} from v0.X to v1, we'll follow those steps

#### Backup up configuration

```
sudo cscli backup save /tmp/crowdsec_backup
sudo cp -R  /etc/crowdsec/config/patterns /tmp/crowdsec_backup
```

#### Uninstall old version & install new 

Download latest V1 {{v0X.crowdsec.name}} version [here]({{v0X.crowdsec.download_url}})

```
tar xvzf crowdsec-release.tgz
cd crowdsec-v1.X/
sudo ./wizard.sh --uninstall
sudo ./wizard.sh --bininstall
```

!!! warning
        Don't forget to remove {{v0X.metabase.name}} dashboard if you installed it manually (without {{v0X.cli.name}}).

#### Restore configuration

Copy `machine_id` and `password` from `/tmp/crowdsec_backup/api_creds.json` and edit `/etc/crowdsec/online_api_credentials.yaml`

```
url: https://api.crowdsec.net/
login: <machine_id>
password: <password>
```

!!! warning
        Before restoring old backup, if you have `local` or `tainted` postoverflows, be aware that they are no longer compatible. You should update the syntax (the community and us are available to help you doing this part).
```
sudo cscli hub update
sudo cscli config restore --old-backup /tmp/crowdsec_backup/
sudo cp -R /tmp/crowdsec_backup/patterns /etc/crowdsec/
```

#### Upgrade {{v0X.bouncers.name}}

If you were using **{{v0X.bouncers.name}}** (formerly called **blocker(s)**), you need to replace them by the new compatibles {{v0X.bouncers.name}}, available on the [hub](https://hub.crowdsec.net/browse/#bouncers) (selecting `agent version` to `v1`).

Following your bouncer type (netfilter, nginx, wordpress etc...), you need to replace them by the new available {{v0X.bouncers.name}} on the hub, please follow the {{v0X.bouncers.name}} documentation that will help you to install easily.

We're also available to help (on [discourse](https://discourse.crowdsec.net/) or [gitter](https://gitter.im/crowdsec-project/community)) upgrading your {{v0X.bouncers.name}}.