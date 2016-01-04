HUB_ROOT=/mnt/hubic2/test
HUB=/mnt/hubic2/test/t1
SRC=~/test/ref
HUBIC_TMP=/media/temp/hubicfuse
TMP=~/test/tmp
BUILD_FILE=newbuild
SRC_FILE=newsrc
SMALL=small.txt
LARGE=large.avi


function check()
{
if [ "$?" == "0" ]; then
  echo -e "\e[32m PASSED \e[0m"
  return 1
else
  echo -e "\e[31m FAILED \e[0m"
  return 0
fi
}

function test(){
  echo -n "Testing: $1" $2 "..."
  eval $2
  check
}


function main(){
	echo
	echo Cleaning folders...
	rm -Rf $HUBIC_TMP/*
	rm -Rf $HUB/*
	rm -Rf $TMP/*
	rmdir $HUB

	echo Preparing temp folders...
	mkdir -p $TMP
	mkdir -p $HUB_ROOT

	if test MKDIR "mkdir $HUB"; then return; fi
	if test RMDIR "rmdir $HUB"; then return; fi
	if test "create test folder" "mkdir $HUB"; then return; fi

	if test "upload non-segmented file" "cp $SRC/$SMALL $HUB/"; then return; fi
}

echo Waiting for a new build...
while true; do
	sleep 1
	if [ -f $SRC_FILE ]; then
		echo Detected new source file, killing hubicfuse
		killall hubicfuse > /dev/null 2>&1
		killall gdb > /dev/null 2>&1
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