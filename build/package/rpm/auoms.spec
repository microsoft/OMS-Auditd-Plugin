Summary:        Microsoft Operations Management Suite Audit Data Collector
Name:           auoms
Version:        %_version
Release:        %_release%{?_dist}
License:        MIT
Vendor:         Microsoft Corporation
Distribution:   Azure Linux
Group:          Applications/System
URL:            http://www.microsoft.com
Requires:       re2

%description
A service that collects and forwards events to the Microsoft Operations Management Suite agent.

%preinstall

if [ -e /opt/microsoft/auoms/bin/auoms ]; then
    rm /opt/microsoft/auoms/bin/auoms
fi
if [ -e /opt/microsoft/auoms/bin/auomscollect ]; then
    rm /opt/microsoft/auoms/bin/auomscollect
fi

if [ $1 -gt 1 ] ; then
    if [ -e /etc/audisp/plugins.d/auoms.conf ]; then
        if [ -e /etc/audisp/plugins.d/auoms.conf.auomssave ]; then
            rm /etc/audisp/plugins.d/auoms.conf.auomssave
        fi
        cp -p /etc/audisp/plugins.d/auoms.conf /etc/audisp/plugins.d/auoms.conf.auomssave
    fi
    if [ -e /etc/audit/plugins.d/auoms.conf ]; then
        if [ -e /etc/audit/plugins.d/auoms.conf.auomssave ]; then
            rm /etc/audit/plugins.d/auoms.conf.auomssave
        fi
        cp -p /etc/audit/plugins.d/auoms.conf /etc/audit/plugins.d/auoms.conf.auomssave
    fi
fi

%post -p /sbin/ldconfig

rm -rf /var/opt/microsoft/auoms/data
if [ -e /bin/systemctl ]; then
    rm /etc/init.d/auoms
fi
if [ -e /usr/sbin/semodule ]; then
    echo "System appears to have SELinux installed, attempting to install selinux policy module for auoms"

    DO_INSTALL=0
    DO_REMOVE=0
    MODULE_VERSION=$(grep policy_module /usr/share/selinux/packages/auoms/auoms.te | sed 's/^policy_module(auoms,\([0-9][^)]*\));$/\1/')
    INSTALLED_VERSION=$(/usr/sbin/semodule -l | grep auoms | cut -f2)
    if [ -z "$INSTALLED_VERSION" ]; then
        DO_INSTALL=1
    elif [ "$INSTALLED_VERSION" != "$MODULE_VERSION" ]; then
        DO_REMOVE=1
        DO_INSTALL=1
    else
        echo "Latest selinux policy module for auoms is already installed"
        MODULE_INSTALLED=1
    fi

    if [ $DO_REMOVE -ne 0 ]; then
        echo "Removing older auoms selinux policy version $INSTALLED_VERSION"
        /usr/sbin/semodule -r auoms >/dev/null 2>&1
    fi

    if [ $DO_INSTALL -ne 0 ]; then
        echo "Installing auoms selinux policy version $MODULE_VERSION"
        /usr/sbin/semodule -i /usr/share/selinux/packages/auoms/auoms.pp >/dev/null 2>&1
        if [ $? -ne 0 ]; then
            echo "ERROR: Failed to install auoms selinux policy module"
            exit 0
        fi
    fi
    echo "Labeling auoms files"
    /sbin/restorecon -R -v /opt/microsoft/auoms/bin/auoms
    /sbin/restorecon -R -v /opt/microsoft/auoms/bin/auomscollect
fi
if [ $1 -gt 1 ] ; then
    if [ -e /etc/audisp/plugins.d/auoms.conf.auomssave ]; then
        if [ -e /etc/audisp/plugins.d/auoms.conf ]; then
            rm /etc/audisp/plugins.d/auoms.conf
        fi
        cp -p /etc/audisp/plugins.d/auoms.conf.auomssave /etc/audisp/plugins.d/auoms.conf
    fi
    if [ -e /etc/audit/plugins.d/auoms.conf.auomssave ]; then
        if [ -e /etc/audit/plugins.d/auoms.conf ]; then
            rm /etc/audit/plugins.d/auoms.conf
        fi
        cp -p /etc/audit/plugins.d/auoms.conf.auomssave /etc/audit/plugins.d/auoms.conf
    fi
    /opt/microsoft/auoms/bin/auomsctl upgrade
fi
rm -f /etc/audisp/plugins.d/auoms.conf.*
rm -f /etc/audit/plugins.d/auoms.conf.*

%preun

if [ $1 -eq 0 ]; then
    /opt/microsoft/auoms/bin/auomsctl disable
fi

%postun -p /sbin/ldconfig

if [ $1 -eq 0 ]; then
    rm -f /etc/audisp/plugins.d/auoms.conf*
    rm -f /etc/audit/plugins.d/auoms.conf*

    if [ -e /usr/sbin/semodule ]; then
        if [ ! -z "$(semodule -l | grep '^auoms\s*[0-9]')" ]; then
            echo "Removing selinux policy module for auoms"
            /usr/sbin/semodule -r auoms
            if [ -e /sbin/auditd ]; then
                echo "Restarting auditd"
                service auditd restart
                sleep 1
                # On CentOS/RHEL 7 the restart may fail to start auditd
                # So, double check and start the service if restart failed
                pgrep -x auditd >/dev/null 2>&1
                if [ $? -ne 0 ]; then
                    service auditd start
                fi
            fi
        fi
    fi

    rm -rf /etc/opt/microsoft/auoms
    rm -rf /var/opt/microsoft/auoms
fi

%files
%defattr(-,root,root)
%{_prefix}/LICENSE
%{_prefix}/THIRD_PARTY_IP_NOTICE
%{_prefix}/auoms.init
%{_prefix}/auoms.service
%{_bindir}/auoms
%{_bindir}/auomscollect
%{_bindir}/auomsctl
%exclude %{_bindir}/fakeaudispd
%exclude %{_bindir}/file2sock
%exclude %{_bindir}/testreceiver
%{_sysconfdir}/opt/microsoft/auoms/auoms.conf
%{_sysconfdir}/opt/microsoft/auoms/auomscollect.conf
%{_sysconfdir}/opt/microsoft/auoms/example_output.conf
%{_sysconfdir}/opt/microsoft/auoms/example_redact.conf
%{_datadir}/selinux/packages/auoms/auoms.fc
%{_datadir}/selinux/packages/auoms/auoms.te
