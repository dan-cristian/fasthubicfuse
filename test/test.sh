HUB=/mnt/hubic2/test
SRC=~/test/ref
HUBIC_TMP=/media/temp/hubicfuse
TMP=~/test/tmp
SMALL=small.txt
LARGE=large.avi


function check()
{
if [ "$?" == "0" ]; then
  echo -e "\e[32m PASSED \e[0m"
else
  echo -e "\e[31m FAILED \e[0m"
  exit
fi
}

function test(){
  echo -n "Testing $1" $2 "..."
  eval $2
  check
}

echo Cleaning folders
rm -R $HUBIC_TMP/*
rm -R $HUB/*
rm -R $TMP/*
rmdir $HUB

echo Preparing temp folders
mkdir $TMP

test MKDIR "mkdir $HUB"
test RMDIR "rmdir $HUB"
test "create test folder" "mkdir $HUB"

test "upload non-segmented file" "cp $SRC/$SMALL $HUB/"
