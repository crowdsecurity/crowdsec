# Upgrade notes

Crowdsec does it best not to break existing setups, and the following rules generally applies :

 - patches (`X.X.Y` to `X.X.Z`) can be applied blindly and are for bugfixes and backward compatible changes
 - minor (`X.Y.X` to `X.Z.X`) can be applied blindly but might introduce some features that are not backward compatible
 - major (`Y.X.X` to `Z.X.X`) must be applied with caution as they might break existing installation


!!! warning

    We **strongly** advise you against running crowdsec and LAPI in different versions.
    When upgrading existing setup, we suggest you to upgrade both crowdsec, cscli and LAPI.

# Upgrades from debian packages (official or pragmatic)

```bash
apt-get update 
apt-get install crowdsec
```

# Upgrades from release tarball

## Patch upgrade

`wizard.sh --binupgrade`

When doing a minor/patch upgrade (ie. `1.0.0` to `1.0.1`), the `--binupgrade` feature should be the more appropriate : It will simply upgrade the existing binaries, letting all configurations untouched.

## Minor upgrade

`wizard.sh --upgrade`

When doing a minor upgrade (ie. `1.0.4` to `1.1.0`), the `--upgrade` feature should be used : It will attempt to migrate and upgrade any existing configurations, include tainted/custom ones. The ambition is to be able to upgrade scenarios, parsers etc to the latest version when relevant, while keeping custom/tainted ones untouched.

It's using `cscli config backup`, creating a directory (usually `/tmp/tmp.<random>`) in which it's going to dump all relevant configurations before performing an upgrade :

 - configuration files : `acquis.yaml` `*_credentials.yaml` `profiles.yaml` `simulation.yaml` `config.yaml`
 - one directory for **parsers**, **scenarios**, **postoverflows** and **collections**, where it's going to store both reference to upstream configurations, and your custom/tainted ones

It is then going to cleanup crowdsec configuration, `/etc/crowdsec/` content (except bouncers configuration), before deploying the new binaries. Once this is done, configuration will be restored from our temp directory using `cscli config restore`.


## Major upgrade

For major upgrades (ie. `0.3.X` to `1.0.X`), `wizard` won't do the trick, and you'll have to rely on documentation to do so :

 - Migrating from `0.3.X` to `1.0.X` :  [documentation](Crowdsec/v1/migration/)


# Manual operations

[`cscli config`](/Crowdsec/v1/cscli/cscli_config/) is your friend here, with [`backup`](/Crowdsec/v1/cscli/cscli_config_backup/) and [`restore`](/Crowdsec/v1/cscli/cscli_config_backup/) subcommands allowing you to backup and restore all of the configuration files.


# Upgrading collections/parsers/scenarios

[`cscli hub`](/Crowdsec/v1/cscli/cscli_hub/) allows you to view, update and upgrade configurations :

 - [`cscli hub update`](/Crowdsec/v1/cscli/cscli_hub_update/) downloads the latest list of available scenarios/parsers/etc
 - [`cscli hub list`](/Crowdsec/v1/cscli/cscli_hub_list/) lists all the installed configurations, their versions and status
 - [`cscli hub upgrade`](/Crowdsec/v1/cscli/cscli_hub_upgrade/) upgrades existing configurations to the latest available version in said list
