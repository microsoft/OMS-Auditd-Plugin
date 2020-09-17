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

Xcopy \Y %CDP_TEMP_PRIOR_DROP_FOLDER_CONTAINER_PATH%\current\drop\BuildPackages\outputs\build\*.deb signed
Xcopy \Y %CDP_TEMP_PRIOR_DROP_FOLDER_CONTAINER_PATH%\current\drop\BuildPackages\outputs\build\*.rpm signed

dir signed
