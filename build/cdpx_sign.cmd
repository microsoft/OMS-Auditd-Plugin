set DIR=%~dp0

cd /d %DIR%
cd ..

if EXIST signed rmdir /s signed
mkdir signed

dir artifacts
dir "artifacts\drop BuildPackages"
dir "artifacts\drop BuildPackages\build"

if NOT EXIST "artifacts\drop BuildPackages\build" exit /b 1

Xcopy /Y "artifacts\drop BuildPackages\build\*.deb" signed
Xcopy /Y "artifacts\drop BuildPackages\build\*.rpm" signed

dir signed\*.deb

if %ERRORLEVEL% NEQ 0 exit /b %ERRORLEVEL%

dir signed\*.rpm

if %ERRORLEVEL% NEQ 0 exit /b %ERRORLEVEL%

exit /b 0
