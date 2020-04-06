# auoms
Originally the OMS Auditd Plugin, that forwards kaudit/auditd events to OMS
Agent for Linux as part of Azure Security Centre, this MSTIC-Research branch
contains a version of auoms that can stand alone and can forward events to
syslog, for collection by Azure Sentinel.

# Build Instructions
## OMS Connector for Sentinel
To send events to Azure Sentinel, you will need to install the OMS Agent.

In your workspace in Azure Sentinel, navigate to Settingsm, then Advanced
Settings.
In 'Connected Sources', select 'Linux Servers'.  Copy the command line from
'Download And Onboard Agent For Linux' and paste into a terminal window on
your server you wish to monitor.  This will install the OMS Agent.
Select 'Data', then 'Syslog'.  Enter 'user' and hit the plus button.
Select the 'info' level plus all other levels of alert you require.
(All agent events are currently transmitted with a level of 'info'.)

## Required Packages
* rapidjson-dev
* libmsgpack-dev

## Build
git clone https://github.com/microsoft/OMS-Auditd-Plugin
cd OMS-Auditd-Plugin
git checkout MSTIC-Research
cmake .
make

## Install
sudo mkdir -p /opt/microsoft/auoms/bin
sudo cp auoms auomscollect auomsctl /opt/microsoft/auoms/bin

# Run
If you are using OMS Agent then you can simply start the auoms service with

sudo service auoms start


