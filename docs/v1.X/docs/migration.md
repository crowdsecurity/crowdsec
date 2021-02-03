# Migration from v0.X to v1.X

!!! warning
        Migrating to V1.X will impact (any change you made will be lost and must be adapted to the new configuration) :
        
        - Database model : your existing database will be lost, a new one will be created in the V1.

        - {{v1X.crowdsec.Name}} configuration :
            - `/etc/crowdsec/config/default.yaml` : check [new format](/Crowdsec/v1/references/crowdsec-config/#configuration-format)
            - `/etc/crowdsec/config/profiles.yaml` : check [new format](/Crowdsec/v1/references/profiles/#profiles-configurations)


To upgrade {{v1X.crowdsec.name}} from v0.X to v1, we'll follow those steps

#### Backup up configuration

```bash
sudo cscli backup save /tmp/crowdsec_backup
sudo cp -R  /etc/crowdsec/config/patterns /tmp/crowdsec_backup
```

#### Uninstall old version & install new 

Download latest V1 {{v1X.crowdsec.name}} version [here]({{v1X.crowdsec.download_url}})

```bash
tar xvzf crowdsec-release.tgz
cd crowdsec-v1*/
sudo ./wizard.sh --uninstall
sudo rm /etc/cron.d/crowdsec_pull
sudo ./wizard.sh --bininstall
```

!!! warning
        Don't forget to remove {{v1X.metabase.name}} dashboard if you installed it manually (without {{v1X.cli.name}}).

#### Restore configuration

!!! warning
        Before restoring old backup, if you have `local` or `tainted` postoverflows, be aware that they are no longer compatible. You should update the syntax (the community and us are available to help you doing this part).
```bash
sudo cscli hub update
sudo cscli config restore --old-backup /tmp/crowdsec_backup/
sudo cp -R /tmp/crowdsec_backup/patterns /etc/crowdsec/
```

### Register crowdsec to local & central API

```bash
$ sudo cscli machines add -a
INFO[0000] Machine '...' created successfully 
INFO[0000] API credentials dumped to '/etc/crowdsec/local_api_credentials.yaml' 
```

Before starting the services, let's check that we're properly registered :

```bash
$ sudo cscli capi status
INFO[0000] Loaded credentials from /etc/crowdsec/online_api_credentials.yaml 
INFO[0000] Trying to authenticate with username ... on https://api.crowdsec.net/ 
INFO[0000] You can successfully interact with Central API (CAPI) 
```

#### Start & health check

Finally, you will be able to start {{v1X.crowdsec.name}} service. Before that, just check if {{v1X.lapi.name}} and {{v1X.api.name}} are correctly configured.

```bash
$ sudo systemctl enable crowdsec
$ sudo systemctl start crowdsec
$ sudo cscli lapi status
INFO[0000] Loaded credentials from /etc/crowdsec/local_api_credentials.yaml 
INFO[0000] Trying to authenticate with username ... on http://127.0.0.1:8080/ 
INFO[0000] You can successfully interact with Local API (LAPI) 
$ sudo cscli capi status
INFO[0000] Loaded credentials from /etc/crowdsec/online_api_credentials.yaml 
INFO[0000] Trying to authenticate with username ... on https://api.crowdsec.net/ 
INFO[0000] You can successfully interact with Central API (CAPI) 
```

!!! warning
        If you're facing issues with `cscli lapi status`, just re-run `cscli machines add -a`.
        If you're facing issues with `cscli capi status`, just re-run `cscli capi register`


You can check logs (located by default here: `/var/log/crowdsec.log` & `/var/log/crowdsec_api.log`).

You can now navigate documentation to learn new {{v1X.cli.name}} commands to interact with crowdsec.

#### Upgrade {{v1X.bouncers.name}}

If you were using **{{v1X.bouncers.name}}** (formerly called **blocker(s)**), you need to replace them by the new compatibles {{v1X.bouncers.name}}, available on the [hub](https://hub.crowdsec.net/browse/#bouncers) (selecting `agent version` to `v1`).

Following your bouncer type (netfilter, nginx, wordpress etc...), you need to replace them by the new available {{v1X.bouncers.name}} on the hub, please follow the {{v1X.bouncers.name}} documentation that will help you to install easily.

We're also available to help (on [discourse](https://discourse.crowdsec.net/) or [gitter](https://gitter.im/crowdsec-project/community)) upgrading your {{v1X.bouncers.name}}.