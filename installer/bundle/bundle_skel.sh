#! /bin/sh

####
# microsoft-oms-auditd-plugin
#
# Copyright (c) Microsoft Corporation
#
# All rights reserved. 
#
# MIT License
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
####


#
# Shell Bundle installer package for the OMS project
#

# This script is a skeleton bundle file for ULINUX only for project OMS.

PATH=/usr/bin:/usr/sbin:/bin:/sbin
umask 022

# Can't use something like 'readlink -e $0' because that doesn't work everywhere
# And HP doesn't define $PWD in a sudo environment, so we define our own
case $0 in
    /*|~*)
        SCRIPT_INDIRECT="`dirname $0`"
        ;;
    *)
        PWD="`pwd`"
        SCRIPT_INDIRECT="`dirname $PWD/$0`"
        ;;
esac

SCRIPT_DIR="`(cd \"$SCRIPT_INDIRECT\"; pwd -P)`"
SCRIPT="$SCRIPT_DIR/`basename $0`"
EXTRACT_DIR="`pwd -P`/auomsbundle.$$"
DPKG_CONF_QUALS="--force-confold --force-confdef"

# These symbols will get replaced during the bundle creation process.

TAR_FILE=<TAR_FILE>
AUOMS_PKG=<AUOMS_PKG>
INSTALL_TYPE=<INSTALL_TYPE>
SCRIPT_LEN=<SCRIPT_LEN>
SCRIPT_LEN_PLUS_ONE=<SCRIPT_LEN+1>

usage()
{
    echo "usage: $1 [OPTIONS]"
    echo "Options:"
    echo "  --extract                  Extract contents and exit."
    echo "  --force                    Force upgrade (override version checks)."
    echo "  --install                  Install the package from the system."
    echo "  --purge                    Uninstall the package and remove all related data."
    echo "  --remove                   Uninstall the package from the system."
    echo "  --restart-deps             Reconfigure and restart dependent service(s)."
    echo "  --source-references        Show source code reference hashes."
    echo "  --upgrade                  Upgrade the package in the system."
    echo "  --version                  Version of this shell bundle."
    echo "  --version-check            Check versions already installed to see if upgradable."
    echo "  --debug                    use shell debug mode."
    echo
    echo "  -? | -h | --help           shows this usage text."
}

source_references()
{
    cat <<EOF
-- Source code references --
EOF
}

cleanup_and_exit()
{
    # $1: Exit status
    # $2: Non-blank (if we're not to delete bundles), otherwise empty

    if [ -z "$2" -a -d "$EXTRACT_DIR" ]; then
        cd $EXTRACT_DIR/..
        rm -rf $EXTRACT_DIR
    fi

    if [ -n "$1" ]; then
        exit $1
    else
        exit 0
    fi
}

check_version_installable() {
    # POSIX Semantic Version <= Test
    # Exit code 0 is true (i.e. installable).
    # Exit code non-zero means existing version is >= version to install.
    #
    # Parameter:
    #   Installed: "x.y.z.b" (like "4.2.2.135"), for major.minor.patch.build versions
    #   Available: "x.y.z.b" (like "4.2.2.135"), for major.minor.patch.build versions

    if [ $# -ne 2 ]; then
        echo "INTERNAL ERROR: Incorrect number of parameters passed to check_version_installable" >&2
        cleanup_and_exit 1
    fi

    # Current version installed
    local INS_MAJOR=`echo $1 | cut -d. -f1`
    local INS_MINOR=`echo $1 | cut -d. -f2`
    local INS_PATCH=`echo $1 | cut -d. -f3`
    local INS_BUILD=`echo $1 | cut -d. -f4`

    # Available version number
    local AVA_MAJOR=`echo $2 | cut -d. -f1`
    local AVA_MINOR=`echo $2 | cut -d. -f2`
    local AVA_PATCH=`echo $2 | cut -d. -f3`
    local AVA_BUILD=`echo $2 | cut -d. -f4`

    # Check bounds on MAJOR
    if [ $INS_MAJOR -lt $AVA_MAJOR ]; then
        return 0
    elif [ $INS_MAJOR -gt $AVA_MAJOR ]; then
        return 1
    fi

    # MAJOR matched, so check bounds on MINOR
    if [ $INS_MINOR -lt $AVA_MINOR ]; then
        return 0
    elif [ $INS_MINOR -gt $AVA_MINOR ]; then
        return 1
    fi

    # MINOR matched, so check bounds on PATCH
    if [ $INS_PATCH -lt $AVA_PATCH ]; then
        return 0
    elif [ $INS_PATCH -gt $AVA_PATCH ]; then
        return 1
    fi

    # PATCH matched, so check bounds on BUILD
    if [ $INS_BUILD -lt $AVA_BUILD ]; then
        return 0
    elif [ $INS_BUILD -gt $AVA_BUILD ]; then
        return 1
    fi

    # Version available is identical to installed version, so don't install
    return 1
}

getVersionNumber()
{
    # Parse a version number from a string.
    #
    # Parameter 1: string to parse version number string from
    #     (should contain something like mumble-4.2.2.135.universal.x86.tar)
    # Parameter 2: prefix to remove ("mumble-" in above example)

    if [ $# -ne 2 ]; then
        echo "INTERNAL ERROR: Incorrect number of parameters passed to getVersionNumber" >&2
        cleanup_and_exit 1
    fi

    echo $1 | sed -e "s/$2//" -e 's/\.universal\..*//' -e 's/\.x64.*//' -e 's/\.x86.*//' -e 's/-/./'
}

verifyNoInstallationOption()
{
    if [ -n "${installMode}" ]; then
        echo "$0: Conflicting qualifiers, exiting" >&2
        cleanup_and_exit 1
    fi

    return;
}

verifyPrivileges() {
    # Parameter: desired operation (for meaningful output)
    if [ -z "$1" ]; then
        echo "verifyPrivileges missing required parameter (operation)" 1>& 2
        exit 1
    fi

    if [ `id -u` -ne 0 ]; then
        echo "Must have root privileges to be able to perform $1 operation" 1>& 2
        exit 1
    fi
}

ulinux_detect_installer()
{
    INSTALLER=

    # If DPKG lives here, assume we use that. Otherwise we use RPM.
    which dpkg > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        INSTALLER=DPKG
    else
        INSTALLER=RPM
    fi
}

# $1 - The name of the package to check as to whether it's installed
check_if_pkg_is_installed() {
    if [ "$INSTALLER" = "DPKG" ]; then
        dpkg -s $1 2> /dev/null | grep Status | grep " installed" 1> /dev/null
    else
        rpm -q $1 2> /dev/null 1> /dev/null
    fi

    return $?
}

# $1 - The filename of the package to be installed
# $2 - The package name of the package to be installed
pkg_add() {
    pkg_filename=$1
    pkg_name=$2

    echo "----- Installing package: $2 ($1) -----"

    if [ -z "${forceFlag}" -a -n "$3" ]; then
        if [ $3 -ne 0 ]; then
            echo "Skipping package since existing version >= version available"
            return 0
        fi
    fi

    if [ "$INSTALLER" = "DPKG" ]; then
        dpkg --install --refuse-downgrade ${pkg_filename}.deb
    else
        [ -n "${forceFlag}" ] && FORCE="--replacefiles --replacepkgs"
        rpm --upgrade $FORCE ${pkg_filename}.rpm
    fi
}

# $1 - The package name of the package to be uninstalled
pkg_rm() {
    echo "----- Removing package: $1 -----"
    if [ "$INSTALLER" = "DPKG" ]; then
        dpkg --purge ${1}
    else
        rpm --erase ${1}
    fi
}

# $1 - The filename of the package to be installed
# $2 - The package name of the package to be installed
# $3 - Okay to upgrade the package? (Optional)
pkg_upd() {
    pkg_filename=$1
    pkg_name=$2
    pkg_allowed=$3

    echo "----- Updating package: $pkg_name ($pkg_filename) -----"

    if [ -z "${forceFlag}" -a -n "$pkg_allowed" ]; then
        if [ $pkg_allowed -ne 0 ]; then
            echo "Skipping package since existing version >= version available"
            return 0
        fi
    fi

    if [ "$INSTALLER" = "DPKG" ]; then
        [ -z "${forceFlag}" ] && FORCE="--refuse-downgrade"
        dpkg --install --force-confnew $FORCE ${pkg_filename}.deb

        export PATH=/usr/local/sbin:/usr/sbin:/sbin:$PATH
    else
        [ -n "${forceFlag}" ] && FORCE="--force"
        rpm --upgrade --replacefiles --replacepkgs $FORCE ${pkg_filename}.rpm
    fi
}

get_arch()
{
    if [ $(uname -m) = 'x86_64' ]; then
        echo "x64"
    else
        echo "x86"
    fi
}

compare_arch()
{
    #check if the user is trying to install the correct bundle (x64 vs. x86)
    echo "Checking host architecture ..."
    AR=$(get_arch)

    case $AUOMS_PKG in
        *"$AR")
            ;;
        *)
            echo "Cannot install $AUOMS_PKG on ${AR} platform"
            cleanup_and_exit 1
            ;;
    esac
}

compare_install_type()
{
    # If the bundle has an INSTALL_TYPE, check if the bundle being installed
    # matches the installer on the machine (rpm vs.dpkg)
    if [ ! -z "$INSTALL_TYPE" ]; then
        if [ $INSTALLER != $INSTALL_TYPE ]; then
           echo "This kit is intended for ${INSTALL_TYPE} systems and cannot install on ${INSTALLER} systems"
           cleanup_and_exit 1
        fi
    fi
}

getInstalledVersion()
{
    # Parameter: Package to check if installed
    # Returns: Printable string (version installed or "None")
    if check_if_pkg_is_installed $1; then
        if [ "$INSTALLER" = "DPKG" ]; then
            local version="`dpkg -s $1 2> /dev/null | grep 'Version: '`"
            getVersionNumber "$version" "Version: "
        else
            local version=`rpm -q $1 2> /dev/null | tail -n 1`
            getVersionNumber $version ${1}-
        fi
    else
        echo "None"
    fi
}

shouldInstall_auoms()
{
    local versionInstalled=`getInstalledVersion auoms`
    [ "$versionInstalled" = "None" ] && return 0
    local versionAvailable=`getVersionNumber $AUOMS_PKG auoms-`

    check_version_installable $versionInstalled $versionAvailable
}

#
# Main script follows
#

ulinux_detect_installer
set -e

while [ $# -ne 0 ]
do
    case "$1" in
        --extract-script)
            # hidden option, not part of usage
            # echo "  --extract-script FILE  extract the script to FILE."
            head -${SCRIPT_LEN} "${SCRIPT}" > "$2"
            shouldexit=true
            shift 2
            ;;

        --extract-binary)
            # hidden option, not part of usage
            # echo "  --extract-binary FILE  extract the binary to FILE."
            tail -n +${SCRIPT_LEN_PLUS_ONE} "${SCRIPT}" > "$2"
            shouldexit=true
            shift 2
            ;;

        --extract)
            verifyNoInstallationOption
            installMode=E
            shift 1
            ;;

        --force)
            forceFlag=true
            shift 1
            ;;

        --install)
            verifyNoInstallationOption
            verifyPrivileges "install"
            installMode=I
            shift 1
            ;;

        -p|--proxy)
            proxy=$2
            shift 2
            ;;

        --purge)
            verifyNoInstallationOption
            verifyPrivileges "purge"
            installMode=P
            shouldexit=true
            shift 1
            ;;

        --remove)
            verifyNoInstallationOption
            verifyPrivileges "remove"
            installMode=R
            shouldexit=true
            shift 1
            ;;

        --restart-deps)
            restartDependencies=--restart-deps
            shift 1
            ;;

        -s|--shared)
            onboardKey=$2
            shift 2
            ;;

        --source-references)
            source_references
            cleanup_and_exit 0
            ;;

        --version)
            echo "Version: `getVersionNumber $AUOMS_PKG omsagent-`"
            exit 0
            ;;

        --version-check)
            printf '%-15s%-15s%-15s%-15s\n\n' Package Installed Available Install?

            # OMS agent itself
            versionInstalled=`getInstalledVersion auoms`
            versionAvailable=`getVersionNumber $AUOMS_PKG omsagent-`
            if shouldInstall_auoms; then shouldInstall="Yes"; else shouldInstall="No"; fi
            printf '%-15s%-15s%-15s%-15s\n' auom $versionInstalled $versionAvailable $shouldInstall

            exit 0
            ;;

        --upgrade)
            verifyNoInstallationOption
            verifyPrivileges "upgrade"
            installMode=U
            shift 1
            ;;

        --debug)
            echo "Starting shell debug mode." >&2
            echo "" >&2
            echo "SCRIPT_INDIRECT: $SCRIPT_INDIRECT" >&2
            echo "SCRIPT_DIR:      $SCRIPT_DIR" >&2
            echo "EXTRACT DIR:     $EXTRACT_DIR" >&2
            echo "SCRIPT:          $SCRIPT" >&2
            echo >&2
            set -x
            shift 1
            ;;

        -\? | -h | --help)
            usage `basename $0` >&2
            cleanup_and_exit 0
            ;;

         *)
            echo "Unknown argument: '$1'" >&2
            echo "Use -h or --help for usage" >&2
            cleanup_and_exit 1
            ;;
    esac
done

if [ -n "${forceFlag}" ]; then
    if [ "$installMode" != "I" -a "$installMode" != "U" ]; then
        echo "Option --force is only valid with --install or --upgrade" >&2
        cleanup_and_exit 1
    fi
fi

if [ -z "${installMode}" ]; then
    echo "$0: No options specified, specify --help for help" >&2
    cleanup_and_exit 3
fi

# Do we need to remove the package?
set +e
if [ "$installMode" = "R" -o "$installMode" = "P" ]; then
    pkg_rm auoms

    if [ "$installMode" = "P" ]; then
        echo "Purging all files in auoms ..."
        rm -rf /etc/opt/microsoft/auoms /opt/microsoft/auoms /var/opt/microsoft/auoms
    fi
fi

if [ -n "${shouldexit}" ]; then
    # when extracting script/tarball don't also install
    cleanup_and_exit 0
fi

#
# Extract the binary here.
#

echo "Extracting..."

# $PLATFORM is validated, so we know we're on Linux of some flavor
tail -n +${SCRIPT_LEN_PLUS_ONE} "${SCRIPT}" | tar xzf -
STATUS=$?
if [ ${STATUS} -ne 0 ]; then
    echo "Failed: could not extract the install bundle."
    cleanup_and_exit ${STATUS}
fi

#
# Do stuff after extracting the binary here, such as actually installing the package.
#

EXIT_STATUS=0

case "$installMode" in
    E)
        # Files are extracted, so just exit
        cleanup_and_exit ${STATUS}
        ;;

    I)
        echo "Installing auoms ..."

        pkg_add $AUOMS_PKG auoms
        EXIT_STATUS=$?
        ;;

    U)
        echo "Updating auoms ..."

        shouldInstall_auoms
        pkg_upd $AUOMS_PKG auoms $?
        EXIT_STATUS=$?
        ;;

    *)
        echo "$0: Invalid setting of variable \$installMode ($installMode), exiting" >&2
        cleanup_and_exit 2
esac

# Remove the package that was extracted as part of the bundle

[ -f $AUOMS_PKG.rpm ] && rm $AUOMS_PKG.rpm
[ -f $AUOMS_PKG.deb ] && rm $AUOMS_PKG.deb

if [ $? -ne 0 -o "$EXIT_STATUS" -ne "0" ]; then
    cleanup_and_exit 1
fi

cleanup_and_exit 0

#####>>- This must be the last line of this script, followed by a single empty line. -<<#####
