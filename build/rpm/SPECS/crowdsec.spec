
Name:           crowdsec
Version:        %(echo $VERSION)
Release:        %(echo $PACKAGE_NUMBER)%{?dist}
Summary:        Crowdsec - An open-source, lightweight agent to detect and respond to bad behaviors. It also automatically benefits from our global community-wide IP reputation database

License:        MIT
URL:            https://crowdsec.net
Source0:        https://github.com/crowdsecurity/%{name}/archive/v%(echo $VERSION).tar.gz
Source1:        80-%{name}.preset
Patch0:         user.patch
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  systemd
%{?fc33:BuildRequires: systemd-rpm-macros}
%{?fc34:BuildRequires: systemd-rpm-macros}
%{?fc35:BuildRequires: systemd-rpm-macros}
%{?fc36:BuildRequires: systemd-rpm-macros}

%define debug_package %{nil}

%description

%define version_number  %(echo $VERSION)
%define releasever  %(echo $RELEASEVER)
%global name crowdsec
%global __mangle_shebangs_exclude_from /usr/bin/env

%prep
%setup -q -T -b 0

%patch0

%build
sed -i "s#/usr/local/lib/crowdsec/plugins/#%{_libdir}/%{name}/plugins/#g" config/config.yaml

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/etc/crowdsec/acquis.d
mkdir -p %{buildroot}/etc/crowdsec/hub
mkdir -p %{buildroot}/etc/crowdsec/patterns
mkdir -p %{buildroot}/etc/crowdsec/console/
mkdir -p %{buildroot}%{_sharedstatedir}/%{name}/data
mkdir -p %{buildroot}%{_presetdir}

mkdir -p %{buildroot}%{_sharedstatedir}/%{name}/plugins
mkdir -p %{buildroot}%{_sysconfdir}/crowdsec/notifications/
mkdir -p %{buildroot}%{_libdir}/%{name}/plugins/


install -m 755 -D cmd/crowdsec/crowdsec %{buildroot}%{_bindir}/%{name}
install -m 755 -D cmd/crowdsec-cli/cscli %{buildroot}%{_bindir}/cscli
install -m 755 -D debian/hubupdate.sh %{buildroot}%{_libexecdir}/%{name}/hubupdate.sh
install -m 644 -D debian/crowdsec.service %{buildroot}%{_unitdir}/%{name}.service
install -m 644 -D debian/crowdsec-hubupdate.service %{buildroot}%{_unitdir}/%{name}-hubupdate.service
install -m 644 -D debian/crowdsec-hubupdate.timer %{buildroot}%{_unitdir}/%{name}-hubupdate.timer
install -m 644 -D config/patterns/* -t %{buildroot}%{_sysconfdir}/crowdsec/patterns
install -m 600 -D config/config.yaml %{buildroot}%{_sysconfdir}/crowdsec
install -m 600 -D config/detect.yaml %{buildroot}/var/lib/%{name}/data/
install -m 644 -D config/simulation.yaml %{buildroot}%{_sysconfdir}/crowdsec
install -m 644 -D config/profiles.yaml %{buildroot}%{_sysconfdir}/crowdsec
install -m 644 -D config/console.yaml %{buildroot}%{_sysconfdir}/crowdsec
install -m 644 -D config/context.yaml %{buildroot}%{_sysconfdir}/crowdsec/console/
install -m 644 -D %{SOURCE1} %{buildroot}%{_presetdir}

# plugins could go to _libexecdir but we'll leave them in _libdir because it's referenced in config.yaml

install -m 551 cmd/notification-slack/notification-slack %{buildroot}%{_libdir}/%{name}/plugins/
install -m 551 cmd/notification-http/notification-http %{buildroot}%{_libdir}/%{name}/plugins/
install -m 551 cmd/notification-splunk/notification-splunk %{buildroot}%{_libdir}/%{name}/plugins/
install -m 551 cmd/notification-email/notification-email %{buildroot}%{_libdir}/%{name}/plugins/
install -m 551 cmd/notification-sentinel/notification-sentinel %{buildroot}%{_libdir}/%{name}/plugins/
install -m 551 cmd/notification-file/notification-file %{buildroot}%{_libdir}/%{name}/plugins/

install -m 600 cmd/notification-slack/slack.yaml %{buildroot}%{_sysconfdir}/crowdsec/notifications/
install -m 600 cmd/notification-http/http.yaml %{buildroot}%{_sysconfdir}/crowdsec/notifications/
install -m 600 cmd/notification-splunk/splunk.yaml %{buildroot}%{_sysconfdir}/crowdsec/notifications/
install -m 600 cmd/notification-email/email.yaml %{buildroot}%{_sysconfdir}/crowdsec/notifications/
install -m 600 cmd/notification-sentinel/sentinel.yaml %{buildroot}%{_sysconfdir}/crowdsec/notifications/
install -m 600 cmd/notification-file/file.yaml %{buildroot}%{_sysconfdir}/crowdsec/notifications/

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%{_bindir}/%{name}
%{_bindir}/cscli
%{_libexecdir}/%{name}/hubupdate.sh
%{_libdir}/%{name}/plugins/notification-slack
%{_libdir}/%{name}/plugins/notification-http
%{_libdir}/%{name}/plugins/notification-splunk
%{_libdir}/%{name}/plugins/notification-email
%{_libdir}/%{name}/plugins/notification-sentinel
%{_libdir}/%{name}/plugins/notification-file
%{_sysconfdir}/%{name}/patterns/linux-syslog
%{_sysconfdir}/%{name}/patterns/ruby
%{_sysconfdir}/%{name}/patterns/nginx
%{_sysconfdir}/%{name}/patterns/junos
%{_sysconfdir}/%{name}/patterns/cowrie_honeypot
%{_sysconfdir}/%{name}/patterns/redis
%{_sysconfdir}/%{name}/patterns/firewalls
%{_sysconfdir}/%{name}/patterns/paths
%{_sysconfdir}/%{name}/patterns/java
%{_sysconfdir}/%{name}/patterns/postgresql
%{_sysconfdir}/%{name}/patterns/bacula
%{_sysconfdir}/%{name}/patterns/mcollective
%{_sysconfdir}/%{name}/patterns/rails
%{_sysconfdir}/%{name}/patterns/haproxy
%{_sysconfdir}/%{name}/patterns/nagios
%{_sysconfdir}/%{name}/patterns/mysql
%{_sysconfdir}/%{name}/patterns/ssh
%{_sysconfdir}/%{name}/patterns/tcpdump
%{_sysconfdir}/%{name}/patterns/exim
%{_sysconfdir}/%{name}/patterns/bro
%{_sysconfdir}/%{name}/patterns/modsecurity
%{_sysconfdir}/%{name}/patterns/aws
%{_sysconfdir}/%{name}/patterns/smb
%{_sysconfdir}/%{name}/patterns/mongodb
%attr(0640, root, root) /var/lib/%{name}/data/detect.yaml
%config(noreplace) %{_sysconfdir}/%{name}/config.yaml
%config(noreplace) %{_sysconfdir}/%{name}/simulation.yaml
%config(noreplace) %{_sysconfdir}/%{name}/profiles.yaml
%config(noreplace) %{_sysconfdir}/%{name}/console.yaml
%config(noreplace) %{_sysconfdir}/%{name}/console/context.yaml
%config(noreplace) %{_presetdir}/80-%{name}.preset
%config(noreplace) %{_sysconfdir}/%{name}/notifications/http.yaml
%config(noreplace) %{_sysconfdir}/%{name}/notifications/slack.yaml
%config(noreplace) %{_sysconfdir}/%{name}/notifications/splunk.yaml
%config(noreplace) %{_sysconfdir}/%{name}/notifications/email.yaml
%config(noreplace) %{_sysconfdir}/%{name}/notifications/sentinel.yaml
%config(noreplace) %{_sysconfdir}/%{name}/notifications/file.yaml

%{_unitdir}/%{name}.service
%{_unitdir}/%{name}-hubupdate.service
%{_unitdir}/%{name}-hubupdate.timer

%ghost %attr(0600,root,root) %{_sysconfdir}/%{name}/hub/.index.json
%ghost %attr(0600,root,root) %{_localstatedir}/log/%{name}.log
%dir /var/lib/%{name}/data/
%dir %{_sysconfdir}/%{name}/hub

%ghost %attr(0600,root,root) %{_sysconfdir}/crowdsec/local_api_credentials.yaml
%ghost %attr(0600,root,root) %{_sysconfdir}/crowdsec/online_api_credentials.yaml
%ghost %{_sysconfdir}/crowdsec/acquis.yaml

%pre

#systemctl stop crowdsec || true

#if [ $1 == 2 ]; then
#    upgrade pre-install here
#fi


%post -p /bin/sh

#install
if [ "$1" = 1 ]; then
    if [ ! -f "/var/lib/crowdsec/data/crowdsec.db" ] ; then
        touch /var/lib/crowdsec/data/crowdsec.db
    fi

    if [ ! -f "%{_sysconfdir}/crowdsec/online_api_credentials.yaml" ] ; then
        install -m 600 /dev/null  /etc/crowdsec/online_api_credentials.yaml
        cscli capi register --error
    fi
    if [ ! -f "%{_sysconfdir}/crowdsec/local_api_credentials.yaml" ] ; then
        install -m 600 /dev/null  /etc/crowdsec/local_api_credentials.yaml
        cscli machines add -a --force --error
    fi

    cscli hub update
    cscli hub upgrade

    echo "Creating acquisition configuration"
    cscli setup unattended

    GREEN=$(printf '\033[0;32m')
    BOLD=$(printf '\033[1m')
    RESET=$(printf '\033[0m')

    echo "${BOLD}Get started with CrowdSec:${RESET}"
    echo " * Go further by following our ${BOLD}post installation steps${RESET} : ${GREEN}${BOLD}https://docs.crowdsec.net/u/getting_started/next_steps${RESET}"
    echo "===================================================================================================================="
    echo " * Install a ${BOLD}remediation component${RESET} to block attackers: ${GREEN}${BOLD}https://docs.crowdsec.net/u/bouncers/intro${RESET}"
    echo "===================================================================================================================="
    echo " * Find more ${BOLD}collections${RESET}, ${BOLD}parsers${RESET} and ${BOLD}scenarios${RESET} created by the community with the Hub: ${GREEN}${BOLD}https://hub.crowdsec.net${RESET}"
    echo "===================================================================================================================="
    echo " * Subscribe to ${BOLD}additional blocklists${RESET}, ${BOLD}visualize${RESET} your alerts and more with the console: ${GREEN}${BOLD}https://app.crowdsec.net${RESET}"
fi

echo "You can always run the configuration again interactively by using 'cscli setup'"

%systemd_post %{name}.service

if [ $1 == 1 ]; then
    LAPI=true
    API=$(cscli config show --key "Config.API.Server")
    if [ "$API" = "nil" ] ; then
        LAPI=false
    else
       ENABLED=$(cscli config show --key "Config.API.Server.Enable" 2>/dev/null || true)
       if [ "$ENABLED" = "false" ]; then
           LAPI=false
       fi
        URI=$(cscli config show --key "Config.API.Server.ListenURI" 2>/dev/null || true)
        PORT=${URI##*:}
    fi
    if [ "$LAPI" = false ] || [ -z "$PORT" ] || [ -z "$(ss -nlt "sport = ${PORT}" 2>/dev/null | grep -v ^State || true)" ]  ; then
        %if 0%{?fc35} || 0%{?fc36}
        systemctl enable crowdsec 
        %endif
        systemctl start crowdsec || echo "crowdsec is not started"
    else
        echo "Not attempting to start crowdsec, port ${PORT} is already used or lapi was disabled"
        echo "This port is configured through /etc/crowdsec/config.yaml and /etc/crowdsec/local_api_credentials.yaml"
    fi
fi

%systemd_post %{name}-hubupdate.timer
systemctl enable --now %{name}-hubupdate.timer

%preun

#systemctl stop crowdsec || echo "crowdsec was not started"

%systemd_preun %{name}.service
%systemd_preun %{name}-hubupdate.timer

%postun

%systemd_postun_with_restart %{name}.service
%systemd_postun %{name}-hubupdate.timer

if [ $1 == 0 ]; then
    rm -rf /etc/crowdsec/hub
fi

#systemctl stop crowdsec || echo "crowdsec was not started"

%changelog
* Tue Feb 16 2021 Manuel Sabban <manuel@crowdsec.net>
- First initial packaging
