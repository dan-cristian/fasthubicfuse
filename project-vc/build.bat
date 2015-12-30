echo Current directory is:
cd

echo Listing remote folder content
set TD=\\10.255.255.1\private\Development\fasthubicfuse-run\
dir %TD%

xcopy "..\..\cloudfsapi.c" %TD% /Y /D
xcopy  "..\..\cloudfuse.c" %TD% /Y /D
xcopy  "..\..\commonfs.c" %TD% /Y /D
xcopy  "..\..\cloudfsapi.h" %TD% /Y /D
xcopy "..\..\commonfs.h" %TD% /Y /D
xcopy "..\..\test\test.sh" %TD% /Y /D
