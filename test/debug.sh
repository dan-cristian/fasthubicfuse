killall hubicfuse
#git pull origin progressive_operations
#rm /media/disk0/temp/hubicfuse/.*
make clean
make debug
sudo umount -l /mnt/hubic2
sudo make install
if [ "$?" == "0" ]; then
#hubicfuse /mnt/hubic -o noauto_cache,sync_read,allow_other -f -o max_read=131072 -o max_write=131072
gdb --eval-command=run --args hubicfuse /mnt/hubic2 -o noauto_cache,sync_read,allow_other,big_writes,large_read -f
#gdbserver :12345 hubicfuse /mnt/hubic -o noauto_cache,sync_read,allow_other -f
#standard test
#valgrind  -v --suppressions=test/valgrind-suppressions-all.supp --tool=memcheck --leak-check=yes --track-origins=yes  hubicfuse /mnt/hubic -o noauto_cache,sync_read,allow_other -f

#generate suppresion info
#valgrind  -v --suppressions=test/valgrind-suppressions-all.supp --gen-suppressions=all --memcheck:leak-check=full --show-reachable=yes  hubicfuse /mnt/hubic -o noauto_cache,sync_read,allow_other -f

#valgrind --tool=memcheck --leak-check=yes --track-origins=yes --leak-check=full --show-leak-kinds=all  hubicfuse /mnt/hubic -o noauto_cache,sync_read,allow_other -d
#G_DEBUG=gc-friendly G_SLICE=always-malloc valgrind --tool=memcheck --leak-check=yes --track-origins=yes  hubicfuse /mnt/hubic2 -o noauto_cache,sync_read,allow_other,big_writes,large_read -f
#valgrind --tool=memcheck --track-origins=yes  hubicfuse /mnt/hubic2 -o noauto_cache,sync_read,allow_other,big_writes,large_read -f
else
	echo error make
fi
