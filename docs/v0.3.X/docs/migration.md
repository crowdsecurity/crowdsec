# Migration from v0.X to v1.X

!!! warning
        Migrating to V1.X will impact (any change you made will be lost and must be adapted to the new configuration) :
        
        - Database model : your existing database will be lost, a new one will be created in the V1.

        - {{v1X.crowdsec.Name}} configuration :
            - `/etc/crowdsec/config/default.yaml` : check [new format](/Crowdsec/v1/references/crowdsec-config/#configuration-format)
            - `/etc/crowdsec/config/profiles.yaml` : check [new format](/Crowdsec/v1/references/profiles/#profiles-configurations)

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
cd crowdsec-v1*/
sudo ./wizard.sh --uninstall
sudo ./wizard.sh --bininstall
```

!!! warning
        Don't forget to remove {{v0X.metabase.name}} dashboard if you installed it manually (without {{v0X.cli.name}}).

#### Restore configuration

!!! warning
        Before restoring old backup, if you have `local` or `tainted` postoverflows, be aware that they are no longer compatible. You should update the syntax (the community and us are available to help you doing this part).
```
sudo cscli hub update
sudo cscli config restore --old-backup /tmp/crowdsec_backup/
sudo cp -R /tmp/crowdsec_backup/patterns /etc/crowdsec/
```

#### Start & health check

Finally, you will be able to start {{v0X.crowdsec.name}} service. Before that, just check if {{v1X.lapi.name}} and {{v0X.api.name}} are correctly configured.

```
ubuntu@ip-:~$ sudo cscli lapi status 
INFO[0000] Loaded credentials from /etc/crowdsec/local_api_credentials.yaml 
INFO[0000] Trying to authenticate with username 941c3fxxxxxxxxxxxxxxxxxxxxxx on http://localhost:8080/ 
INFO[0000] You can successfully interact with Local API (LAPI)

ubuntu@ip-:~$ sudo cscli capi status 
INFO[0000] Loaded credentials from /etc/crowdsec/online_api_credentials.yaml 
INFO[0000] Trying to authenticate with username 941c3fxxxxxxxxxxxxxxxxxxxxxxx on https://api.crowdsec.net/ 
INFO[0000] You can successfully interact with Central API (CAPI)

ubuntu@ip-:~$ sudo systemctl start crowdsec.service
ubuntu@ip-:~$ sudo systemctl status crowdsec.service
```

You can even check logs (located by default here: `/var/log/crowdsec.log` & `/var/log/crowdsec_api.log`).

You can now navigate documentation to learn new {{v0X.cli.name}} commands to interact with crowdsec.

#### Upgrade {{v0X.bouncers.name}}

If you were using **{{v0X.bouncers.name}}** (formerly called **blocker(s)**), you need to replace them by the new compatibles {{v0X.bouncers.name}}, available on the [hub](https://hub.crowdsec.net/browse/#bouncers) (selecting `agent version` to `v1`).

Following your bouncer type (netfilter, nginx, wordpress etc...), you need to replace them by the new available {{v0X.bouncers.name}} on the hub, please follow the {{v0X.bouncers.name}} documentation that will help you to install easily.

We're also available to help (on [discourse](https://discourse.crowdsec.net/) or [gitter](https://gitter.im/crowdsec-project/community)) upgrading your {{v0X.bouncers.name}}.