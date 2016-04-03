
SRC_FILE=newsrc

function main(){
echo
killall hubicfuse > /dev/null 2>&1
make clean
make debug
sudo umount -l /mnt/hubic > /dev/null 2>&1
sudo make install
if [ "$?" == "0" ]; then
	rm -Rf /mnt/hubic/*
	touch newbuild
	gdb --eval-command=run handle SIGPIPE nostop noprint pass --args hubicfuse /mnt/hubic -o noatime,noauto_cache,sync_read,allow_other,big_writes,large_read,max_write=131072,max_read=131072 -f
else
	echo error make
fi
}

echo Waiting for source file changes...
#while true; do
sleep 1
#if [ -f $SRC_FILE ]; then
	echo New source detected, compiling!
	rm $SRC_FILE
	#clean screen log and http log
	truncate ~/screenlog.0 -s 0
	truncate /media/temp/log/fasthubicfuse-http.log -s 0
	main
	echo Run completed!
	echo ==============
	echo
	echo Waiting for source file changes...
#fi
#done