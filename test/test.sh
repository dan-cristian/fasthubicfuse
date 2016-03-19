#!/bin/bash

if [ $# -eq 0 ]; then
		TEST_FOLDER=t1
		echo "No arguments supplied, test folder=$1"
	else
		TEST_FOLDER=$1
		echo "Not cleaning fuse cache folder"
fi

. test_functions.sh
if [ $# -eq 0 ]; then
	delete_fuse_cache
fi
echo "Test folder = $HUB"
#echo Waiting for a new build...
setup_config_progressive
setup_test

while true; do

	#sleep 1
	#if [ -f $SRC_FILE ]; then
		#setup_config_standard
		#echo Detected new source file!
		#killall hubicfuse > /dev/null 2>&1
		#killall gdb > /dev/null 2>&1
		#sleep 2
	#fi
	
	

	#if [ -f $BUILD_FILE ]; then
		#echo New build detected!
		#sleep 5
		#setup_test
		
		if test_upload_small; then exit; fi
		if test_download_small; then exit; fi
		if test_upload_medium; then exit; fi
		if test_download_medium; then exit; fi
		
		if test_utimens; then exit; fi
		if test_create; then exit; fi
		if test_chmod; then exit; fi
		if test_chown; then exit; fi
		
		if test_upload_small; then exit; fi
		if test_downup_small; then exit; fi		
		if test_rename_small; then exit; fi
		
		if test_upload_small; then exit; fi
		if test_upload_medium; then exit; fi
		
		if test_delete_small; then exit; fi
		if test_upload_small; then exit; fi
		if test_upload_medium; then exit; fi
		
		if test_download_small; then exit; fi
		if test_download_small; then exit; fi
		
		
		echo "Check copy consistency, older segments should be removed..."
		
		#cache_reset
		
		echo ===============
		echo
		#rm $BUILD_FILE
		echo Repeating tests...
	#fi
done