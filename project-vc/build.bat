echo|set /p="Current directory = "
cd

ping -n 1 nas > nul
IF ERRORLEVEL 0 GOTO set_local

ping -n 1 10.255.255.1 > nul
IF ERRORLEVEL 0 GOTO set_remote

echo No test environment is available to deploy source files
pause

GOTO end

:copy_files
xcopy "..\..\cloudfsapi.c" %TD% /Y /D
xcopy  "..\..\cloudfuse.c" %TD% /Y /D 
xcopy  "..\..\commonfs.c" %TD% /Y /D 
xcopy  "..\..\cloudfsapi.h" %TD% /Y /D 
xcopy "..\..\commonfs.h" %TD% /Y /D 
xcopy "..\..\test\test.sh" %TD% /Y /D
xcopy "..\..\test\test_functions.sh" %TD% /Y /D
xcopy "..\..\test\test_multithread.sh" %TD% /Y /D
xcopy "..\..\test\debug.sh" %TD% /Y /D
xcopy "..\..\test\.hubicfuse.*" %TD% /Y /D
rem copy /b %TD%newsrc +,,
rem touch %TD%newsrc
GOTO end

:set_remote
echo Deploying remotely
SET TD=\\10.255.255.1\private\Development\fasthubicfuse-run\
goto copy_files

:set_local
echo Deploying locally
SET TD=\\nas\private\Development\fasthubicfuse-run\
goto copy_files

:end