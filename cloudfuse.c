#define FUSE_USE_VERSION 26
#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pthread.h>
#include <pwd.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stddef.h>
#include "commonfs.h"
#include "cloudfsapi.h"
#include "config.h"

extern char *temp_dir;

extern pthread_mutex_t dcachemut;
extern pthread_mutexattr_t mutex_attr;
extern int cache_timeout;
extern int option_cache_statfs_timeout;
extern long fuse_active_opp_count;

typedef struct
{
  int fd;
  int flags;
} openfile;

// updated to support utimens
static int cfs_getattr(const char *path, struct stat *stbuf)
{
	fuse_active_opp_count++;
  debugf(KBLU "cfs_getattr(%s):%d", path, fuse_active_opp_count);
  stbuf->st_uid = geteuid();
  stbuf->st_gid = getegid();
  if (!strcmp(path, "/"))
  {
    stbuf->st_mode = S_IFDIR | 0755;
    stbuf->st_nlink = 2;
		debug_list_cache_content();
		debugf(KBLU "exit 0: cfs_getattr(%s)", path);
		fuse_active_opp_count--;
		return 0;
  }
	//get file. if not in cache will be downloaded.
  dir_entry *de = path_info(path);
  if (!de) {
		debug_list_cache_content();
		debugf(KRED "exit 1: cfs_getattr(%s) not-in-cache", path);
		fuse_active_opp_count--;
		return -ENOENT;
  }
  else {
    //debugf("On getattr found cache for %s ctime=%li.%li mtime=%li.%li atime=%li.%li", path,
    //  de->ctime.tv_sec, de->ctime.tv_nsec, de->mtime.tv_sec, de->mtime.tv_nsec, de->atime.tv_sec, de->atime.tv_nsec);
  }
  // change needed due to utimens
  //stbuf->st_ctime = stbuf->st_mtime = de->last_modified;
  stbuf->st_atime = de->atime.tv_sec;
  stbuf->st_mtime = de->mtime.tv_sec;
  stbuf->st_ctime = de->ctime.tv_sec;

  //end change

  if (de->isdir)
  {
    stbuf->st_size = 0;
    stbuf->st_mode = S_IFDIR | 0755;
    stbuf->st_nlink = 2;
  }
  else if (de->islink)
  {
    stbuf->st_size = 1;
    stbuf->st_mode = S_IFLNK | 0755;
    stbuf->st_nlink = 1;
    stbuf->st_size = de->size;
    /* calc. blocks as if 4K blocksize filesystem; stat uses units of 512B */
    stbuf->st_blocks = ((4095 + de->size) / 4096) * 8;
  }
  else
  {
    stbuf->st_size = de->size;
    /* calc. blocks as if 4K blocksize filesystem; stat uses units of 512B */
    stbuf->st_blocks = ((4095 + de->size) / 4096) * 8;
    stbuf->st_mode = S_IFREG | 0666;
    stbuf->st_nlink = 1;
  }
	debug_list_cache_content();
	debugf(KBLU "exit 2: cfs_getattr(%s)", path);
	fuse_active_opp_count--;
	return 0;
}

static int cfs_fgetattr(const char *path, struct stat *stbuf, struct fuse_file_info *info)
{
	fuse_active_opp_count++;
  debugf(KBLU "cfs_fgetattr(%s)", path);
  openfile *of = (openfile *)(uintptr_t)info->fh;
  if (of)
  {
    stbuf->st_size = cloudfs_file_size(of->fd);
    stbuf->st_mode = S_IFREG | 0666;
    stbuf->st_nlink = 1;
		debugf(KBLU "exit 0: cfs_fgetattr(%s)", path);
		fuse_active_opp_count--;
    return 0;
  }
	debugf(KRED "exit 1: cfs_fgetattr(%s)", path);
	fuse_active_opp_count--;
  return -ENOENT;
}

static int cfs_readdir(const char *path, void *buf, fuse_fill_dir_t filldir, off_t offset, struct fuse_file_info *info)
{
	fuse_active_opp_count++;
  debugf(KBLU "cfs_readdir(%s)", path);
  dir_entry *de;
	//change to use path_info, avoid internal call
	//de = path_info(path);
	//if (!de) {
	if (!caching_list_directory(path, &de)) {
		debug_list_cache_content();
		debugf(KRED "exit 0: cfs_readdir(%s)", path);
		fuse_active_opp_count--;
		return -ENOLINK;
	}
  filldir(buf, ".", NULL, 0);
  filldir(buf, "..", NULL, 0);
  for (; de; de = de->next)
    filldir(buf, de->name, NULL, 0);
	debug_list_cache_content();
	debugf(KBLU "exit 1: cfs_readdir(%s)", path);
	fuse_active_opp_count--;
	return 0;
}

static int cfs_mkdir(const char *path, mode_t mode)
{
	fuse_active_opp_count++;
	debugf(KBLU "cfs_mkdir(%s)", path);
	int response = cloudfs_create_directory(path);
  if (response){
    update_dir_cache(path, 0, 1, 0);
		debug_list_cache_content();
		debugf(KBLU "exit 0: cfs_mkdir(%s)", path);
		fuse_active_opp_count--;
    return 0;
  }
	debugf(KRED "exit 1: cfs_mkdir(%s) response=%d", path, response);
	fuse_active_opp_count--;
	return -ENOENT;
}

static int cfs_create(const char *path, mode_t mode, struct fuse_file_info *info)
{
  debugf(KBLU "cfs_create(%s)", path);
  FILE *temp_file;
	int errsv;

  if (*temp_dir) {
    /*char tmp_path[PATH_MAX];
    strncpy(tmp_path, path, PATH_MAX);
    char *pch;
    while((pch = strchr(tmp_path, '/'))) {
      *pch = '.';
    }*/
    //char file_path[PATH_MAX] = "";
    //snprintf(file_path, PATH_MAX, TEMP_FILE_NAME_FORMAT, temp_dir, (long)getpid(), tmp_path);
    char file_path_safe[NAME_MAX] = "";
		get_safe_cache_file_path(path, file_path_safe, temp_dir);
    temp_file = fopen(file_path_safe, "w+b");
		errsv = errno;
    if (temp_file == NULL){
      debugf(KRED "Cannot open temp file %s.error %s\n", file_path_safe, strerror(errsv));
      //return -EIO;
    }
  }
  else {
    temp_file = tmpfile();
		errsv = errno;
    if (temp_file == NULL){
      debugf(KRED "Cannot open tmp file for path %s.error %s\n", path, strerror(errsv));
      //return -EIO;
    }
  }
  openfile *of = (openfile *)malloc(sizeof(openfile));
  of->fd = dup(fileno(temp_file));
  fclose(temp_file);
  of->flags = info->flags;
  info->fh = (uintptr_t)of;
  update_dir_cache(path, 0, 0, 0);
  info->direct_io = 1;
	debug_list_cache_content();
	debugf(KBLU "exit: cfs_create(%s) result=%d:%s", path, errsv, strerror(errsv));
  return 0;
}



// open(download) file from cloud
static int cfs_open(const char *path, struct fuse_file_info *info)
{
	fuse_active_opp_count++;
  debugf(KBLU "cfs_open(%s)", path);
  FILE *temp_file = NULL;
	int errsv;
  dir_entry *de = path_info(path);

	debug_print_descriptor(info);
	
  if (*temp_dir)
  {
    char file_path_safe[NAME_MAX];
		get_safe_cache_file_path(path, file_path_safe, temp_dir);

		debugf("cfs_open status: try open (%s)", file_path_safe);
    if (access(file_path_safe, F_OK) != -1){
      // file exists
      temp_file = fopen(file_path_safe, "r");
			errsv = errno;
      debugf("file exists");
    }
    //FIXME: commented out as condition will not be meet in some odd cases and program will crash
		else {
			errsv = errno;
			debugf("cfs_open status: file not in cache, err=%s", strerror(errsv));
			//debugf("")
			//if (!(info->flags & O_WRONLY)) {
				debugf("opening for write");

				// we need to lock on the filename another process could open the file
				// while we are writing to it and then only read part of the file

				// duplicate the directory caching datastructure to make the code easier
				// to understand.

				// each file in the cache needs:
				//  filename, is_writing, last_closed, is_removing
				// the first time a file is opened a new entry is created in the cache
				// setting the filename and is_writing to true.  This check needs to be
				// wrapped with a lock.
				//
				// each time a file is closed we set the last_closed for the file to now
				// and we check the cache for files whose last
				// closed is greater than cache_timeout, then start a new thread rming
				// that file.

				// TODO: just to prevent this craziness for now
				temp_file = fopen(file_path_safe, "w+b");
				errsv = errno;
				if (temp_file == NULL) {
					debugf("Cannot open temp_file=[%s] err=%d:%s", file_path_safe, errsv, strerror(errsv));
				}

				if (!cloudfs_object_write_fp(path, temp_file))
				{
					fclose(temp_file);
					debug_list_cache_content();
					debugf(KRED "exit 0: cfs_open(%s)", path);
					fuse_active_opp_count--;
					return -ENOENT;
				}
				/*}
			else {
				debugf(KRED "Unable to create a temp file=%s", file_path_safe);
				if (temp_file == NULL) {
					debugf(KRED "Temp file is null");
				}
			}*/
		}
  }
  else
  {
    temp_file = tmpfile();
    if (temp_file == NULL) {
      debugf("Cannot create temp_file err=%s", strerror(errno));
    }
    if (!(info->flags & O_TRUNC))
    {
      if (!cloudfs_object_write_fp(path, temp_file) && !(info->flags & O_CREAT))
      {
        fclose(temp_file);
				debug_list_cache_content();
				debugf(KRED"exit 1: cfs_open(%s)", path);
				fuse_active_opp_count--;
        return -ENOENT;
      }
    }
  }

  if (temp_file == NULL){
		debug_list_cache_content();
		debugf(KRED "exit 2: cfs_open(%s)", path);
		fuse_active_opp_count--;
    return -ENOENT;
  }
  else {
    update_dir_cache(path, (de ? de->size : 0), 0, 0);
    openfile *of = (openfile *)malloc(sizeof(openfile));
    of->fd = dup(fileno(temp_file));
    if (of->fd == -1){
      //FIXME: potential leak if free not used?
      free(of);
			debug_list_cache_content();
			debugf(KRED "exit 3: cfs_open(%s)", path);
			fuse_active_opp_count--;
      return -ENOENT;
    }
    fclose(temp_file);
    //TODO: why this allocation to of?
    of->flags = info->flags;
    info->fh = (uintptr_t)of;
    info->direct_io = 1;
    info->nonseekable = 1;
    //FIXME: potential leak if free(of) not used? although if free(of) is used will generate bad descriptor errors
		debug_list_cache_content();
		debugf(KBLU "exit 4: cfs_open(%s)", path);
		fuse_active_opp_count--;
    return 0;
  }
}

static int cfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *info)
{
	fuse_active_opp_count++;
  debugf(KBLU "cfs_read(%s)", path);
	debug_print_descriptor(info);
	int result = pread(((openfile *)(uintptr_t)info->fh)->fd, buf, size, offset);
	debugf(KBLU "exit: cfs_read(%s) result=%s", path, strerror(errno));
	fuse_active_opp_count--;
	return result;
}

static int cfs_flush(const char *path, struct fuse_file_info *info)
{
	fuse_active_opp_count++;
  debugf(KBLU "cfs_flush(%s)", path);
	debug_print_descriptor(info);
  openfile *of = (openfile *)(uintptr_t)info->fh;
	int errsv = 0;

  if (of) {
    update_dir_cache(path, cloudfs_file_size(of->fd), 0, 0);
    if (of->flags & O_RDWR || of->flags & O_WRONLY)
    {
      FILE *fp = fdopen(dup(of->fd), "r");
			errsv = errno;
			if (fp != NULL) {
				rewind(fp);
				if (!cloudfs_object_read_fp(path, fp))
				{
					fclose(fp);
					errsv = errno;
					debugf(KRED"exit 0: cfs_flush(%s) result=%d:%s", path, errsv, strerror(errno));
					fuse_active_opp_count--;
					return -ENOENT;
				}
				fclose(fp);
				errsv = errno;
			}
			else {
				debugf(KRED "status: cfs_flush, err=%d:%s", errsv, strerror(errno));
			}
    }
  }
	debugf(KBLU "exit 1: cfs_flush(%s) result=%d:%s", path, errsv, strerror(errno));
	fuse_active_opp_count--;
	return 0;
}

static int cfs_release(const char *path, struct fuse_file_info *info)
{
	fuse_active_opp_count++;
  debugf(KBLU "cfs_release(%s)", path);
	debug_print_descriptor(info);
  close(((openfile *)(uintptr_t)info->fh)->fd);
	debugf(KBLU "exit: cfs_release(%s)", path);
	fuse_active_opp_count--;
	return 0;
}

static int cfs_rmdir(const char *path)
{
  debugf(KBLU "cfs_rmdir(%s)", path);
  int success = cloudfs_delete_object(path);
	if (success == -1) {
		debugf(KBLU "exit 0: cfs_rmdir(%s)", path);
		return -ENOTEMPTY;
	}
  if (success){
    dir_decache(path);
		debugf(KBLU "exit 1: cfs_rmdir(%s)", path);
    return 0;
  }
	debugf(KBLU "exit 2: cfs_rmdir(%s)", path);
  return -ENOENT;
}

static int cfs_ftruncate(const char *path, off_t size, struct fuse_file_info *info)
{
  debugf(KBLU "cfs_ftruncate(%s)", path);
  openfile *of = (openfile *)(uintptr_t)info->fh;
  if (ftruncate(of->fd, size))
    return -errno;
  lseek(of->fd, 0, SEEK_SET);
  update_dir_cache(path, size, 0, 0);
	debugf(KBLU "exit: cfs_ftruncate(%s)", path);
  return 0;
}

static int cfs_write(const char *path, const char *buf, size_t length, off_t offset, struct fuse_file_info *info)
{
	fuse_active_opp_count++;
  debugf(KBLU "cfs_write(%s)", path);
	
	debug_print_descriptor(info);
  // FIXME: Potential inconsistent cache update if pwrite fails?
  update_dir_cache(path, offset + length, 0, 0);
	//int result = pwrite(info->fh, buf, length, offset);
	debug_print_flags(info->flags);
	int result = pwrite(((openfile *)(uintptr_t)info->fh)->fd, buf, length, offset);
	int errsv = errno;
	//debug_list_cache_content();
	debugf(KBLU "exit: cfs_write(%s) result=%d:%s", path, errsv, strerror(errsv));
	fuse_active_opp_count--;
	return result;
}

static int cfs_unlink(const char *path)
{
	debugf(KBLU "cfs_unlink(%s)", path);
  int success = cloudfs_delete_object(path);
	if (success == -1) {
		debugf(KBLU "exit 0: cfs_unlink(%s)", path);
		return -EACCES;
	}
  if (success)
  {
    dir_decache(path);
		debugf(KBLU "exit 1: cfs_unlink(%s)", path);
    return 0;
  }
	debugf(KBLU "exit 2: cfs_unlink(%s)", path);
  return -ENOENT;
}

static int cfs_fsync(const char *path, int idunno, struct fuse_file_info *info)
{
  debugf("Fsync path=[%s]", path);
  return 0;
}

static int cfs_truncate(const char *path, off_t size)
{
  debugf("Truncate path=[%s]", path);
  cloudfs_object_truncate(path, size);
  return 0;
}

//todo: called regularly on large copy (via mc), can be optimised (cached)?
static int cfs_statfs(const char *path, struct statvfs *stat)
{
	fuse_active_opp_count++;
  debugf(KBLU "cfs_statfs(%s)", path);
  if (cloudfs_statfs(path, stat)){
		debugf(KBLU "exit 0: cfs_statfs(%s)", path);
		fuse_active_opp_count--;
    return 0;
  }
	else {
		debugf(KRED"exit 1: cfs_statfs(%s)", path);
		fuse_active_opp_count--;
		return -EIO;
	}
}

static int cfs_chown(const char *path, uid_t uid, gid_t gid)
{
  debugf(KBLU "cfs_chown(%s)", path);
  return 0;
}

static int cfs_chmod(const char *path, mode_t mode)
{
  debugf("Chmod path=[%s]", path);
  return 0;
}

static int cfs_rename(const char *src, const char *dst)
{
  debugf("Rename src=[%s] dst=[%s]", src, dst);
  dir_entry *src_de = path_info(src);
  if (!src_de)
      return -ENOENT;
  if (src_de->isdir)
    return -EISDIR;
  if (cloudfs_copy_object(src, dst))
  {
    /* FIXME this isn't quite right as doesn't preserve last modified */
    update_dir_cache(dst, src_de->size, 0, 0);
    return cfs_unlink(src);
  }
  return -EIO;
}

static int cfs_symlink(const char *src, const char *dst)
{
  debugf("Symlink src=[%s] dst=[%s]", src, dst);
  if(cloudfs_create_symlink(src, dst))
  {
    update_dir_cache(dst, 1, 0, 1);
    return 0;
  }
  return -EIO;
}

static int cfs_readlink(const char* path, char* buf, size_t size)
{
  debugf("Readlink path=[%s]", path);
  FILE *temp_file = tmpfile();
  int ret = 0;

  if (!cloudfs_object_write_fp(path, temp_file))
  {
      ret = -ENOENT;
  }

  if (!pread(fileno(temp_file), buf, size, 0))
  {
      ret = -ENOENT;
  }

  fclose(temp_file);
  return ret;
}

static void *cfs_init(struct fuse_conn_info *conn)
{
  signal(SIGPIPE, SIG_IGN);
  return NULL;
}

/*
Order of operations when fuse is updating file time attrs with touch -t command:
Open, Write_Fp, [READ CLOUD], [u cache], Flush, [u cache], Read_fp, [Put on cloud]
;
utimes, [u cache], getattr, flush, [u cache], read_fp, [PUT on cloud], release
http://man7.org/linux/man-pages/man2/utimensat.2.html
times: times[0] specifies the new "last access time" (atime)
times: times[1] specifies the new "last modification time" (mtime)
*/
static int cfs_utimens(const char *path, const struct timespec times[2]){
	debugf(KBLU "cfs_utimens(%s)", path);
  //debugf("Calling utimes path=[%s] t0=[%li.%li] t1=[%li.%li]", path, times[0].tv_sec, times[0].tv_nsec, times[1].tv_sec, times[1].tv_nsec);
  // looking for file entry in cache
  dir_entry *path_de = path_info(path);
  if (!path_de) {
		debugf(KBLU "exit 0: cfs_utimens(%s)" KRED " file not in cache", path);
    return -ENOENT;
  }
  struct timespec now;
  clock_gettime(CLOCK_REALTIME, &now);

	if (path_de->atime.tv_sec != times[0].tv_sec || path_de->atime.tv_nsec != times[0].tv_nsec ||
			path_de->mtime.tv_sec != times[1].tv_sec || path_de->mtime.tv_nsec != times[1].tv_nsec) {
		debugf(KCYN "utime must change for %s, prev: atime=%li.%li mtime=%li.%li, to be set: atime=%li.%li mtime=%li.%li", path,
			path_de->atime.tv_sec, path_de->atime.tv_nsec, path_de->mtime.tv_sec, path_de->mtime.tv_nsec,
			times[0].tv_sec, times[0].tv_nsec, times[1].tv_sec, times[1].tv_nsec
			);
		path_de->atime = times[0];
		path_de->mtime = times[1];
		// not sure how to best obtain ctime yet. just record current date.
		path_de->ctime = now;
	}

	debugf(KBLU "exit 1: cfs_utimens(%s)", path);
  return 0;
}


int cfs_setxattr(const char *path, const char *name, const char *value, size_t size, int flags){
  return 0;
}

int cfs_getxattr(const char *path, const char *name, char *value, size_t size){
  return 0;
}


FuseOptions options = {
    .cache_timeout = "600",
    .verify_ssl = "true",
    .segment_size = "1073741824",
    .segment_above = "2147483647",
    .storage_url = "",
    .container = "",
    //.temp_dir = "/tmp/",
    .temp_dir = "",
    .client_id = "",
    .client_secret = "",
    .refresh_token = ""
};

ExtraFuseOptions extra_options = {
	.get_extended_metadata = "false",
	.curl_verbose = "false",
	.cache_statfs_timeout = 0
};

int parse_option(void *data, const char *arg, int key, struct fuse_args *outargs)
{
  if (sscanf(arg, " cache_timeout = %[^\r\n ]", options.cache_timeout) ||
		sscanf(arg, " verify_ssl = %[^\r\n ]", options.verify_ssl) ||
    sscanf(arg, " segment_above = %[^\r\n ]", options.segment_above) ||
    sscanf(arg, " segment_size = %[^\r\n ]", options.segment_size) ||
    sscanf(arg, " storage_url = %[^\r\n ]", options.storage_url) ||
    sscanf(arg, " container = %[^\r\n ]", options.container) ||
    sscanf(arg, " temp_dir = %[^\r\n ]", options.temp_dir) ||
    sscanf(arg, " client_id = %[^\r\n ]", options.client_id) ||
    sscanf(arg, " client_secret = %[^\r\n ]", options.client_secret) ||
    sscanf(arg, " refresh_token = %[^\r\n ]", options.refresh_token) ||

		sscanf(arg, " get_extended_metadata = %[^\r\n ]", extra_options.get_extended_metadata) ||
		sscanf(arg, " curl_verbose = %[^\r\n ]", extra_options.curl_verbose) ||
		sscanf(arg, " cache_statfs_timeout = %[^\r\n ]", extra_options.cache_statfs_timeout)
		)
    return 0;
  if (!strcmp(arg, "-f") || !strcmp(arg, "-d") || !strcmp(arg, "debug"))
    cloudfs_debug(1);
  return 1;
}

void interrupt_handler(int sig) {
  debugf("Got interrupt signal %d, cleaning memory", sig);
  //TODO: clean memory allocations
  //http://www.cprogramming.com/debugging/valgrind.html
  cloudfs_free();
  //TODO: clear dir cache

  pthread_mutex_destroy(&dcachemut);
  exit(0);
}

void initialise_options() {
	cloudfs_verify_ssl(!strcasecmp(options.verify_ssl, "true"));
	cloudfs_option_get_extended_metadata(!strcasecmp(extra_options.get_extended_metadata, "true"));
	cloudfs_option_curl_verbose(!strcasecmp(extra_options.curl_verbose, "true"));
	if (*extra_options.cache_statfs_timeout) {
		option_cache_statfs_timeout = atoi(extra_options.cache_statfs_timeout);
	}
}

int main(int argc, char **argv)
{
  fprintf(stderr, "Starting hubicfuse on homedir %s!", get_home_dir());
  signal(SIGINT, interrupt_handler);

  char settings_filename[MAX_PATH_SIZE] = "";
  FILE *settings;
  struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

  snprintf(settings_filename, sizeof(settings_filename), "%s/.hubicfuse", get_home_dir());
  if ((settings = fopen(settings_filename, "r")))
  {
    char line[OPTION_SIZE];
    while (fgets(line, sizeof(line), settings))
      parse_option(NULL, line, -1, &args);
    fclose(settings);
  }

  fuse_opt_parse(&args, &options, NULL, parse_option);

  cache_timeout = atoi(options.cache_timeout);
  segment_size = atoll(options.segment_size);
  segment_above = atoll(options.segment_above);
  // this is ok since main is on the stack during the entire execution
  override_storage_url = options.storage_url;
  public_container = options.container;
  temp_dir = options.temp_dir;

  if (!*options.client_id || !*options.client_secret || !*options.refresh_token)
  {
    fprintf(stderr, "Unable to determine client_id, client_secret or refresh_token.\n\n");
    fprintf(stderr, "These can be set either as mount options or in "
                    "a file named %s\n\n", settings_filename);
    fprintf(stderr, "  client_id=[App's id]\n");
    fprintf(stderr, "  client_secret=[App's secret]\n");
    fprintf(stderr, "  refresh_token=[Get it running hubic_token]\n");
    fprintf(stderr, "The following settings are optional:\n\n");
    fprintf(stderr, "  cache_timeout=[Seconds for directory caching, default 600]\n");
    fprintf(stderr, "  verify_ssl=[false to disable SSL cert verification]\n");
    fprintf(stderr, "  segment_size=[Size to use when creating DLOs, default 1073741824]\n");
    fprintf(stderr, "  segment_above=[File size at which to use segments, defult 2147483648]\n");
    fprintf(stderr, "  storage_url=[Storage URL for other tenant to view container]\n");
    fprintf(stderr, "  container=[Public container to view of tenant specified by storage_url]\n");
    fprintf(stderr, "  temp_dir=[Directory to store temp files]\n");

		fprintf(stderr, "  get_extended_metadata=[true to enable download of utime, chmod, chown file attributes (but slower)]\n");
		fprintf(stderr, "  curl_verbose=[true to debug info on curl requests (lots of output)]\n");
		fprintf(stderr, "  cache_statfs_timeout=[number of seconds to cache requests to statfs (cloud statistics), 0 for no cache]\n");
		
    return 1;
  }

  cloudfs_init();
	initialise_options();
  

  cloudfs_set_credentials(options.client_id, options.client_secret, options.refresh_token);

  if (!cloudfs_connect())
  {
    fprintf(stderr, "Failed to authenticate.\n");
    return 1;
  }

  #ifndef HAVE_OPENSSL
  #warning Compiling without libssl, will run single-threaded.
  fuse_opt_add_arg(&args, "-s");
  #endif

  struct fuse_operations cfs_oper = {
    .readdir = cfs_readdir,
    .mkdir = cfs_mkdir,
    .read = cfs_read,
    .create = cfs_create,
    .open = cfs_open,
    .fgetattr = cfs_fgetattr,
    .getattr = cfs_getattr,
    .flush = cfs_flush,
    .release = cfs_release,
    .rmdir = cfs_rmdir,
    .ftruncate = cfs_ftruncate,
    .truncate = cfs_truncate,
    .write = cfs_write,
    .unlink = cfs_unlink,
    .fsync = cfs_fsync,
    .statfs = cfs_statfs,
    .chmod = cfs_chmod,
    .chown = cfs_chown,
    .rename = cfs_rename,
    .symlink = cfs_symlink,
    .readlink = cfs_readlink,
    .init = cfs_init,
    // implementing utimens capabilities
    .utimens = cfs_utimens,
    .setxattr = cfs_setxattr,
    .getxattr = cfs_getxattr,
  };

	pthread_mutexattr_init(&mutex_attr);
	pthread_mutexattr_settype(&mutex_attr, PTHREAD_MUTEX_RECURSIVE);
  pthread_mutex_init(&dcachemut, &mutex_attr);
  return fuse_main(args.argc, args.argv, &cfs_oper, &options);
}
