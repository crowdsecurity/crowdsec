# Upgrades

The wizard is here to help the user in the process of upgrading an existing installation.
Various items need to be kept during the upgrade process:

 - scenarios/parsers/postoverflows : upstream scenarios need to be updated, while local/tainted ones need to be kept as-is
 - most configurations must be kept as-is (`acquis.yaml` `*_credentials.yaml` `profiles.yaml` `simulation.yaml` `config.yaml`)
 - database (especially if it's a SQLite file)


## Patch upgrade

`wizard.sh --binupgrade`

When doing a minor/patch upgrade (ie. `1.0.0` to `1.0.1`), the `--binupgrade` feature should be the more appropriate : It will simply upgrade the existing binaries, letting all configurations untouched.

As any breaking change should lead to a version bump and appropriate warning, this is the safest option.


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

