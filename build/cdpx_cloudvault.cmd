set DIR=%~dp0

cd /d %DIR%
cd ..

if EXIST cloudvault rmdir /s cloudvault
mkdir cloudvault

dir %CDP_TEMP_PRIOR_DROP_FOLDER_CONTAINER_PATH%\current
dir %CDP_TEMP_PRIOR_DROP_FOLDER_CONTAINER_PATH%\current\drop
dir %CDP_TEMP_PRIOR_DROP_FOLDER_CONTAINER_PATH%\current\drop\Sign
dir %CDP_TEMP_PRIOR_DROP_FOLDER_CONTAINER_PATH%\current\drop\Sign\outputs
dir %CDP_TEMP_PRIOR_DROP_FOLDER_CONTAINER_PATH%\current\drop\Sign\outputs\build

dir %CDP_TEMP_PRIOR_DROP_FOLDER_CONTAINER_PATH%\current\drop\BuildBundle
dir %CDP_TEMP_PRIOR_DROP_FOLDER_CONTAINER_PATH%\current\drop\BuildBundle\outputs
dir %CDP_TEMP_PRIOR_DROP_FOLDER_CONTAINER_PATH%\current\drop\BuildBundle\outputs\build

if NOT EXIST %CDP_TEMP_PRIOR_DROP_FOLDER_CONTAINER_PATH%\current\drop\Sign\outputs\build exit /b 0
if NOT EXIST %CDP_TEMP_PRIOR_DROP_FOLDER_CONTAINER_PATH%\current\drop\BuildBundle\outputs\build exit /b 0

Xcopy /Y %CDP_TEMP_PRIOR_DROP_FOLDER_CONTAINER_PATH%\current\drop\Sign\outputs\build\*.deb cloudvault
Xcopy /Y %CDP_TEMP_PRIOR_DROP_FOLDER_CONTAINER_PATH%\current\drop\Sign\outputs\build\*.rpm cloudvault
Xcopy /Y %CDP_TEMP_PRIOR_DROP_FOLDER_CONTAINER_PATH%\current\drop\BuildBundle\outputs\build\*.sh cloudvault

dir cloudvault\*.deb

if %ERRORLEVEL% NEQ 0 exit /b %ERRORLEVEL%

dir cloudvault\*.rpm

if %ERRORLEVEL% NEQ 0 exit /b %ERRORLEVEL%

dir cloudvault\*.sh

if %ERRORLEVEL% NEQ 0 exit /b %ERRORLEVEL%

exit /b 0