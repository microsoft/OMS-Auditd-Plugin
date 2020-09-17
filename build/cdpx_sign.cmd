set DIR=%~dp0

cd /d %DIR%
cd ..

if EXIST signed rmdir /s signed
mkdir signed
copy %CDP_TEMP_PRIOR_DROP_FOLDER_CONTAINER_PATH%\current\drop\BuildPackages\outputs\build\*.deb signed
copy %CDP_TEMP_PRIOR_DROP_FOLDER_CONTAINER_PATH%\current\drop\BuildPackages\outputs\build\*.rpm signed
