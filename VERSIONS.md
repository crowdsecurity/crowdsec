# Versions matrix

## Maintenance policy

The last two major releases are supported. Hence as of now 1.4.4 and
1.3.4 are supported.

## Matrix Versions

| OS | Platform | Distribution | Distribution Version | CrowdSec Version | CrowdSec Location |
|----|----------|--------------|------------------|----------------------|-------------------|
| Linux | amd64/arm64/armhf | Debian | bookworm/bullseye/buster/stretch | 1.4.4 and 1.3.4 | [packagecloud](https://packagecloud.io/crowdsec/crowdsec) |
| Linux | amd64/arm64 | RedHat/CentOS | 6/7/8/9 | 1.4.4 and 1.3.4 | [packagecloud](https://packagecloud.io/crowdsec/crowdsec) |
| Linux | amd64/arm64/armel/armhf/i386/mips64el/mipsel/ppc64el/s390x | Debian | 1.0.9 | [official debian repository](https://packages.debian.org/search?keywords=crowdsec&searchon=names&suite=stable&section=all) |
| Linux | amd64/arm64 | Fedora | 34/35/36/37 | 1.4.4 and 1.3.4 | [packagecloud](https://packagecloud.io/crowdsec/crowdsec) |
| Linux | amd64/arm64 | Amazon linux | 2 | 1.4.4 and 1.3.4 |  [packagecloud](https://packagecloud.io/crowdsec/crowdsec) |
| Linux | amd64/arm64 | Ubuntu Linux| 16.04/18.04/20.04/22.04/22.10 | 1.4.4 and 1.3.4 | [packagecloud](https://packagecloud.io/crowdsec/crowdsec) |
| FreeBSD | amd64/i386 | N/A | 12 | 1.4.3 | [freshports](https://www.freshports.org/security/crowdsec/) |
| FreeBSD | amd64/i386/arm64/armv7 | N/A | 13 | 1.4.3 | [freshports](https://www.freshports.org/security/crowdsec/) |
| FreeBSD | amd64/i386 | N/A | 14 | 1.4.3 | [freshports](https://www.freshports.org/security/crowdsec/) |
| FreeBSD | arm64/armv7 | N/A | 14 | 1.4.3 | [freshports](https://www.freshports.org/security/crowdsec/) |
| OPNsense | amd64 | N/A | 22.7 | 1.4.3 | [freshports](https://www.freshports.org/security/crowdsec/) |
| Windows | amd64 | to be defined | 1.4.4 | [github releases](https://github.com/crowdsecurity/crowdsec/releases/tag/v1.4.4)|
| Windows | amd64 | to be defined | 1.4.2 | [chocolatey](https://community.chocolatey.org/packages?q=crowdsec) |
| Linux | almost all OpenWRT supported platform | OpenWRT | 21.02/22.03 | 1.3.0 | [OpenWrt repository](https://openwrt.org/packages/pkgdata/crowdsec) |
| Linux/Windows | amd64/arm64 | docker | N/A | 1.4.4 | [dockerhub](https://hub.docker.com/r/crowdsecurity/crowdsec) |
| helm chart | amd64/arm64 | helm | N/A | 1.4.4 | [helm chart](https://github.com/crowdsecurity/helm-charts) |
| home assitant | amd64/arm64 | docker | N/A | 1.4.4 | [crowdsecurity home assistant addon repo](https://github.com/crowdsecurity/home-assistant-addons/)|

Note: There is a subtile difference between armel, armhf and armv7:
armel and armhf are the ports name defined by debian, armel is
available on armv6 capable processer and higher, and armhf is
available on armv7 capable and higher.

Linux
=====

Linux packages are maintained by CrowdSec and shipped through
packagecloud.io repositories. Issues for packages have to be created
directly against the [crowdsec source
repository](https://github.com/crowdsecurity/crowdsec). Packages are
published automatically few hours after each new releases.

There are two public repositories:
* [pkgcloud.io stable repository](https://packagecloud.io/crowdsec/) for published release
* [pkgcloud.io beta repository](https://packagecloud.io/crowdsec-testing/) for published release

Note: There is a version on official debian repository as well.


FreeBSD
=======

FreeBSD ports are updated via requests to https://bugs.freebsd.org/bugzilla/

Anybody can open issues or even updates but most packages have an official maintainer (@mmetc for crowdsec).
Issues are reviewed by maintainers, then by committers or by the ports management team.
A proper review process is in place therefore updates can take a few days.

To see pending issues related to crowdsec or the bouncers, search "crowdsec".
To see closed issues as well, search for "ALL crowdsec"

The state of the packages for the several FreeBSD versions and architectures can be seen at https://www.freshports.org/

Usually packages apprear in the repository updates (quarterly or latest), but
if required they can be installed directly, for example:

$ pkg add https://pkg.freebsd.org/FreeBSD:12:amd64/latest/All/crowdsec-1.4.3.pkg

The repository for work-in-progress ports is
https://github.com/crowdsecurity/packaging-freebsd, once tested they are
submitted in bugzilla.

The following packages have been ported so far:

 - CrowdSec - https://github.com/freebsd/freebsd-ports/tree/main/security/crowdsec [1]
   packages: https://www.freshports.org/security/crowdsec/

 - Firewall Bouncer - https://github.com/freebsd/freebsd-ports/tree/main/security/crowdsec-firewall-bouncer
   packages: https://www.freshports.org/security/crowdsec-firewall-bouncer/

 - Blocklist Mirror - https://github.com/freebsd/freebsd-ports/tree/main/security/crowdsec-blocklist-mirror
   packages: https://www.freshports.org/security/crowdsec-blocklist-mirror


[1] read-only mirror of https://cgit.freebsd.org/ports/
also on https://gitlab.com/FreeBSD/freebsd-ports


OPNsense 
========

OPNsense has its own port tree, which tracks the main branch from
freebsd: https://github.com/opnsense/ports Updates are frequent (often
daily) but can be delayed for code freeze or holidays.  The source of
the crowdsec plugin is in
https://github.com/opnsense/plugins/tree/master/security/crowdsec and
it depends on the crowdsec and firewall bouncer packages.  New
versions are pushed via pull requests on the github repository.

Windows
=======

CrowdSec Windows releases are available for download few minutes after
releasing directly on the [release page of
github](https://github.com/crowdsecurity/crowdsec/releases). 

We do our best to keep an up to date version in [chocolatey
repository](https://community.chocolatey.org/packages?q=crowdsec) as
well. It has go through a moderation process, so we don't have any
grasp on the publication timeline.

Issues have to be filed directly against the [crowdsec source
repository](https://github.com/crowdsecurity/crowdsec)
