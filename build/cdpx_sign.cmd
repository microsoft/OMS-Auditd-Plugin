set DIR=%~dp0

cd /d %DIR%
cd ..

if EXIST signed rmdir /s signed
mkdir signed
dir /s %CDP_TEMP_PRIOR_DROP_FOLDER_CONTAINER_PATH%
cp %CDP_TEMP_PRIOR_DROP_FOLDER_CONTAINER_PATH%/current/drop/BuildPackages/* signed
