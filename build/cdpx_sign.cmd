set DIR=%~dp0

cd /d %DIR%
cd ..

if EXIST signed rmdir /s signed
mkdir signed

dir signed
dir %CDP_TEMP_PRIOR_DROP_FOLDER_CONTAINER_PATH%\current
dir %CDP_TEMP_PRIOR_DROP_FOLDER_CONTAINER_PATH%\current\drop
dir %CDP_TEMP_PRIOR_DROP_FOLDER_CONTAINER_PATH%\current\drop\BuildPackages
dir %CDP_TEMP_PRIOR_DROP_FOLDER_CONTAINER_PATH%\current\drop\BuildPackages\outputs
dir %CDP_TEMP_PRIOR_DROP_FOLDER_CONTAINER_PATH%\current\drop\BuildPackages\outputs\build

if NOT EXIST %CDP_TEMP_PRIOR_DROP_FOLDER_CONTAINER_PATH%\current\drop\BuildPackages\outputs\build exit /b 0

Xcopy /Y %CDP_TEMP_PRIOR_DROP_FOLDER_CONTAINER_PATH%\current\drop\BuildPackages\outputs\build\*.deb signed
Xcopy /Y %CDP_TEMP_PRIOR_DROP_FOLDER_CONTAINER_PATH%\current\drop\BuildPackages\outputs\build\*.rpm signed

dir signed\*.deb

if %ERRORLEVEL% NEQ 0 exit /b %ERRORLEVEL%

dir signed\*.rpm

if %ERRORLEVEL% NEQ 0 exit /b %ERRORLEVEL%

exit /b 0