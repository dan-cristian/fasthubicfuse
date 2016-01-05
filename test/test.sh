HUB_ROOT=/mnt/hubic2/test
HUB=/mnt/hubic2/test/t1
HUB_NOCACHE=/mnt/hubic2/test/ref
SRC=~/test/ref
HUBIC_TMP=/media/temp/hubicfuse
TMP=~/test/tmp
BUILD_FILE=newbuild
SRC_FILE=newsrc
SMALL=small.txt
LARGE=large.avi
TINY=tiny.txt
TINY_MD5=41ec28b253670dcc01601014317bece0
LARGE_MD5=701603c35a8b3af176dc687e17e7b44e
SMALL_MD5=70a4b9f4707d258f559f91615297a3ec

PASSED_MSG="\e[32m PASSED \e[0m"
FAILED_MSG="\e[31m FAILED \e[0m"

function check()
{
if [ "$?" == "0" ]; then
  echo -e $PASSED_MSG
  return 1
else
  echo -e $FAILED_MSG
  return 0
fi
}

function test(){
  echo -n "Testing: $1" $2 "..."
  eval $2
  check
}

function test_md5(){
	echo -n "Testing: md5sum check" $1 "..."
	md5=$(md5sum $1)
	if [[ "$md5" == *"$2"* ]]; then
		echo -e $PASSED_MSG
		return 1
	else
		echo -n " $md5!=$2 "
		echo -e $FAILED_MSG
		return 0
	fi
}

function main(){
	echo
	echo Cleaning folders...
	rm -Rf $HUBIC_TMP/*
	rm -Rf $TMP/*
	
	rm -Rf $HUB/*
	rmdir $HUB

	echo Preparing temp folders...
	mkdir -p $TMP
	mkdir -p $HUB_ROOT

	if test MKDIR "mkdir $HUB"; then return; fi
	if test RMDIR "rmdir $HUB"; then return; fi
	if test "create test folder" "mkdir $HUB"; then return; fi

	if test "upload non-segmented file" "cp $SRC/$SMALL $HUB/"; then return; fi
	if test "download uploaded file" "cp $HUB/$SMALL $TMP/"; then return; fi
	if test_md5 "$TMP/$SMALL" "$SMALL_MD5"; then return; fi
	
	if test "download file" "cp $HUB_NOCACHE/$TINY $TMP/"; then return; fi
	if test_md5 "$TMP/$TINY" "$TINY_MD5"; then return; fi
	
	if test "download file" "cp $HUB_NOCACHE/$SMALL $TMP/"; then return; fi
	if test_md5 "$TMP/$SMALL" "$SMALL_MD5"; then return; fi
	
	if test "download file" "cp $HUB_NOCACHE/$LARGE $TMP/"; then return; fi
	if test_md5 "$TMP/$LARGE" "$LARGE_MD5"; then return; fi
	
	
	
	
}

echo Waiting for a new build...
while true; do
	sleep 1
	if [ -f $SRC_FILE ]; then
		echo Detected new source file, killing hubicfuse
		killall hubicfuse > /dev/null 2>&1
		killall gdb > /dev/null 2>&1
		sleep 2
	fi
	
	if [ -f $BUILD_FILE ]; then
		echo New build detected!
		rm $BUILD_FILE
		read -t 5 -p "Press a key to run tests"
		main
		echo Test completed!
		echo ===============
		echo
		echo Waiting for a new build...
	fi
done