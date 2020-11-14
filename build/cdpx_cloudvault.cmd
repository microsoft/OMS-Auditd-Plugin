set DIR=%~dp0

cd /d %DIR%
cd ..

if EXIST cloudvault rmdir /s cloudvault
mkdir cloudvault

set DIR=%~dp0

dir artifacts
dir "artifacts\drop Sign"
dir "artifacts\drop Sign\build"
dir "artifacts\drop BuildBundle"
dir "artifacts\drop BuildBundle\build"

if NOT EXIST "artifacts\drop Sign\build" exit /b 1
if NOT EXIST "artifacts\drop BuildBundle\build" exit /b 1

Xcopy /Y "artifacts\drop Sign\build\*.deb" cloudvault
Xcopy /Y "artifacts\drop Sign\build\*.rpm" cloudvault
Xcopy /Y "artifacts\drop BuildBundle\build\*.sh" cloudvault

dir cloudvault\*.deb

if %ERRORLEVEL% NEQ 0 exit /b %ERRORLEVEL%

dir cloudvault\*.rpm

if %ERRORLEVEL% NEQ 0 exit /b %ERRORLEVEL%

dir cloudvault\*.sh

if %ERRORLEVEL% NEQ 0 exit /b %ERRORLEVEL%

exit /b 0