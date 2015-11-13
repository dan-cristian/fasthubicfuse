killall hubicfuse
git pull origin utime
make
sudo umount -l /mnt/hubic
sudo make install
gdb --args hubicfuse /mnt/hubic -o noauto_cache,sync_read,allow_other -f
#gdbserver :12345 hubicfuse /mnt/hubic -o noauto_cache,sync_read,allow_other -f
#valgrind --tool=memcheck --leak-check=yes --track-origins=yes  hubicfuse /mnt/hubic -o noauto_cache,sync_read,allow_other -d
#valgrind --tool=memcheck --leak-check=yes --track-origins=yes --leak-check=full --show-leak-kinds=all  hubicfuse /mnt/hubic -o noauto_cache,sync_read,allow_other -d
#G_DEBUG=gc-friendly G_SLICE=always-malloc valgrind --tool=memcheck --leak-check=yes --track-origins=yes  hubicfuse /mnt/hubic -o noauto_cache,sync_read,allow_other -f
