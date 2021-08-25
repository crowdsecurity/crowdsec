
Name:           crowdsec
Version:        %(echo $VERSION)
Release:        %(echo $PACKAGE_NUMBER)%{?dist}
Summary:        Crowdsec - An open-source, lightweight agent to detect and respond to bad behaviours. It also automatically benefits from our global community-wide IP reputation database

License:        MIT
URL:            https://crowdsec.net
Source0:        https://github.com/crowdsecurity/%{name}/archive/v%(echo $VERSION).tar.gz
Source1:        80-%{name}.preset
Patch0:         crowdsec.unit.patch
Patch1:         fix-wizard.patch
Patch2:         config.patch
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  git
BuildRequires:  make
BuildRequires:  jq
BuildRequires:  systemd
%{?fc33:BuildRequires: systemd-rpm-macros}
%{?fc34:BuildRequires: systemd-rpm-macros}

%define debug_package %{nil}

%description

%define version_number  %(echo $VERSION)
%define releasever  %(echo $RELEASEVER)
%global local_version v%{version_number}-%{releasever}-rpm
%global name crowdsec
%global __mangle_shebangs_exclude_from /usr/bin/env

%prep
%setup -q -T -b 0

%patch0
%patch1
%patch2

%build
BUILD_VERSION=%{local_version} make

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/etc/crowdsec/hub
mkdir -p %{buildroot}/etc/crowdsec/patterns
mkdir -p %{buildroot}%{_sharedstatedir}/%{name}/data
mkdir -p %{buildroot}%{_presetdir}

mkdir -p %{buildroot}%{_sharedstatedir}/%{name}/plugins
mkdir -p %{buildroot}%{_sysconfdir}/crowdsec/notifications/



install -m 755 -D cmd/crowdsec/crowdsec %{buildroot}%{_bindir}/%{name}
install -m 755 -D cmd/crowdsec-cli/cscli %{buildroot}%{_bindir}/cscli
install -m 755 -D wizard.sh %{buildroot}/usr/share/crowdsec/wizard.sh
install -m 644 -D config/crowdsec.service %{buildroot}%{_unitdir}/%{name}.service
install -m 644 -D config/patterns/* -t %{buildroot}%{_sysconfdir}/crowdsec/patterns
install -m 644 -D config/config.yaml %{buildroot}%{_sysconfdir}/crowdsec
install -m 644 -D config/simulation.yaml %{buildroot}%{_sysconfdir}/crowdsec
install -m 644 -D config/profiles.yaml %{buildroot}%{_sysconfdir}/crowdsec
install -m 644 -D %{SOURCE1} %{buildroot}%{_presetdir}

install -m 551 plugins/notifications/slack/notification-slack %{buildroot}%{_sharedstatedir}/%{name}/plugins/
install -m 551 plugins/notifications/http/notification-http %{buildroot}%{_sharedstatedir}/%{name}/plugins/
install -m 551 plugins/notifications/splunk/notification-splunk %{buildroot}%{_sharedstatedir}/%{name}/plugins/

install -m 644 plugins/notifications/slack/slack.yaml %{buildroot}%{_sysconfdir}/crowdsec/notifications/
install -m 644 plugins/notifications/http/http.yaml %{buildroot}%{_sysconfdir}/crowdsec/notifications/
install -m 644 plugins/notifications/splunk/splunk.yaml %{buildroot}%{_sysconfdir}/crowdsec/notifications/



%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
/usr/bin/%{name}
/usr/bin/cscli
/usr/share/%{name}/wizard.sh
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
%config(noreplace) %{_sysconfdir}/%{name}/config.yaml
%config(noreplace) %{_sysconfdir}/%{name}/simulation.yaml
%config(noreplace) %{_sysconfdir}/%{name}/profiles.yaml
%config(noreplace) %{_presetdir}/80-%{name}.preset

%{_unitdir}/%{name}.service

%ghost %{_sysconfdir}/%{name}/hub/.index.json
%ghost %{_localstatedir}/log/%{name}.log
%dir /var/lib/%{name}/data/

%ghost %{_sysconfdir}/crowdsec/local_api_credentials.yaml
%ghost %{_sysconfdir}/crowdsec/online_api_credentials.yaml
%ghost %{_sysconfdir}/crowdsec/acquis.yaml

%pre

#systemctl stop crowdsec || true

if [ $1 == 2 ];then  
    if [[ ! -d /var/lib/crowdsec/backup ]]; then
        cscli config backup /var/lib/crowdsec/backup
    fi
fi


%post -p /bin/bash

if [ $1 == 1 ]; then

    if [ ! -f "/var/lib/crowdsec/data/crowdsec.db" ] ; then
        touch /var/lib/crowdsec/data/crowdsec.db
    fi

    echo $SHELL
    . /usr/share/crowdsec/wizard.sh -n

    echo Creating acquisition configuration
    if [ ! -f "/etc/crowsec/acquis.yaml" ] ; then
        set +e
        SILENT=true detect_services
        SILENT=true genacquisition
        set +e
    fi
    if [ ! -f "%{_sysconfdir}/crowdsec/online_api_credentials.yaml" ] && [ ! -f "%{_sysconfdir}/crowdsec/local_api_credentials.yaml" ] ; then
        touch %{_sysconfdir}/crowdsec/online_api_credentials.yaml
        touch %{_sysconfdir}/crowdsec/local_api_credentials.yaml
        cscli capi register
        cscli machines add -a
    fi
    if [ ! -f "%{_sysconfdir}/crowdsec/online_api_credentials.yaml" ] ; then
        touch %{_sysconfdir}/crowdsec/online_api_credentials.yaml
        cscli capi register
    fi
    if [ ! -f "%{_sysconfdir}/crowdsec/local_api_credentials.yaml" ] ; then
        touch %{_sysconfdir}/crowdsec/local_api_credentials.yaml
        cscli machines add -a
    fi

    cscli hub update
    CSCLI_BIN_INSTALLED="/usr/bin/cscli" SILENT=true install_collection

    systemctl start crowdsec || echo "crowdsec is not started"
    
elif [ $1 == 2 ] && [ -d /var/lib/crowdsec/backup ]; then
    cscli config restore /var/lib/crowdsec/backup
    if [ $? == 0 ]; then
       rm -rf /var/lib/crowdsec/backup
    fi

fi

%systemd_post %{name}.service

%preun

#systemctl stop crowdsec || echo "crowdsec was not started"

%systemd_preun %{name}.service

%postun

%systemd_postun_with_restart %{name}.service

#systemctl stop crowdsec || echo "crowdsec was not started"

%changelog
* Tue Feb 16 2021 Manuel Sabban <manuel@crowdsec.net>
- First initial packaging
