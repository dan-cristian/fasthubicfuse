#define _GNU_SOURCE
#include <stdio.h>
#include <magic.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifdef __linux__
#include <alloca.h>
#endif
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <openssl/md5.h>
#include <pwd.h>
#include <fuse.h>
#include "commonfs.h"
#include "config.h"

pthread_mutex_t dmut;
pthread_mutexattr_t mutex_attr;
dir_cache *dcache;
int cache_timeout;
int debug = 0;

// needed to get correct GMT / local time, as it does not work
// http://zhu-qy.blogspot.ro/2012/11/ref-how-to-convert-from-utc-to-local.html
time_t my_timegm(struct tm *tm) {
  time_t epoch = 0;
  time_t offset = mktime(gmtime(&epoch));
  time_t utc = mktime(tm);
  return difftime(utc, offset);
}

// hubic stores time as GMT so we have to do conversions

/*void time_t set_now_time_to_gmt(){
  struct timespec now;
  clock_gettime(CLOCK_REALTIME, &now);
  http://stackoverflow.com/questions/1764710/converting-string-containing-localtime-into-utc-in-c
}
*/
//expect time_str as a friendly string format
time_t get_time_from_str_as_gmt(char *time_str){
  struct tm val_time_tm;
  time_t val_time_t;
  strptime(time_str, "%FT%T", &val_time_tm);
  val_time_tm.tm_isdst = -1;
  val_time_t = my_timegm(&val_time_tm);
  return val_time_t;
}

time_t get_time_as_local(time_t time_t_val, char time_str[], int char_buf_size){
  struct tm loc_time_tm;
  loc_time_tm = *localtime(&time_t_val);
  if (time_str != NULL) {
    //debugf("Local len=%d size=%d pass=%d", strlen(time_str), sizeof(time_str), char_buf_size);
    strftime(time_str, char_buf_size, "%c", &loc_time_tm);
    //debugf("Local timestr=[%s] size=%d", time_str, strlen(time_str));
  }
  //debugf("Local time_t %li", mktime(&loc_time_tm));
  return mktime(&loc_time_tm);
}

int get_time_as_string(time_t time_t_val, char *time_str){
  struct tm time_val_tm;
  time_val_tm = *gmtime(&time_t_val);
  return strftime(time_str, strlen(time_str), "%c", &time_val_tm);
}

time_t get_time_now() {
	struct timespec now;
	clock_gettime(CLOCK_REALTIME, &now);
	return now.tv_sec;
}

char *str2md5(const char *str, int length) {
  int n;
  MD5_CTX c;
  unsigned char digest[16];
  char *out = (char*)malloc(33);

  MD5_Init(&c);

  while (length > 0) {
    if (length > 512) {
      MD5_Update(&c, str, 512);
    }
    else {
      MD5_Update(&c, str, length);
    }
    length -= 512;
    str += 512;
  }

  MD5_Final(digest, &c);

  for (n = 0; n < 16; ++n) {
    snprintf(&(out[n * 2]), 16 * 2, "%02x", (unsigned int)digest[n]);
  }

  return out;
}

void get_file_path_from_fd(int fd, char *path, int size_path) {
	char proc_path[MAX_PATH_SIZE];
	/* Read out the link to our file descriptor. */
	sprintf(proc_path, "/proc/self/fd/%d", fd);
	memset(path, 0, size_path);
	readlink(proc_path, path, size_path - 1);
}

void debug_print_flags(int flags) {
	int accmode, val;
	accmode = flags & O_ACCMODE;
	if (accmode == O_RDONLY)				debugf(KRED "read only");
	else if (accmode == O_WRONLY)   debugf(KRED "write only");
	else if (accmode == O_RDWR)     debugf(KRED "read write");
	else debugf(KRED "unknown access mode");

	if (val & O_APPEND)         debugf(KRED ", append");
	if (val & O_NONBLOCK)       debugf(KRED ", nonblocking");
#if !defined(_POSIX_SOURCE) && defined(O_SYNC)
	if (val & O_SYNC)           debugf(KRED ", synchronous writes");
#endif

}

void debug_print_descriptor(struct fuse_file_info *info) {
	char file_path[MAX_PATH_SIZE];
	get_file_path_from_fd(info->fh, file_path, sizeof(file_path));
	debugf(KCYN "descriptor localfile=[%s] fd=%d", file_path, info->fh);
	debug_print_flags(info->flags);
}

void dir_for(const char *path, char *dir)
{
  strncpy(dir, path, MAX_PATH_SIZE);
  char *slash = strrchr(dir, '/');
  if (slash)
    *slash = '\0';
}

//prints cache content for debug purposes
void debug_list_cache_content() {
	
	return;

	dir_cache *cw;
	dir_entry *de;
	for (cw = dcache; cw; cw = cw->next) {
		debugf("LIST-CACHE: DIR[%s]", cw->path);
		for (de = cw->entries; de; de = de->next) {
			debugf("LIST-CACHE:   FOLDER[%s]", de->full_name);
		}
	}
}

//adding a directory in cache
dir_cache *new_cache(const char *path)
{
  debugf(KMAG "new_cache(%s)", path);
  dir_cache *cw = (dir_cache *)calloc(sizeof(dir_cache), 1);
  cw->path = strdup(path);
  cw->prev = NULL;
  cw->entries = NULL;
  cw->cached = time(NULL);
	//added cache by access
	cw->accessed_in_cache = time(NULL);
  if (dcache)
    dcache->prev = cw;
  cw->next = dcache;
	dir_cache *result;
	result = (dcache = cw);
	debugf("exit: new_cache(%s)", path);
  return result;
}



void cloudfs_free_dir_list(dir_entry *dir_list)
{
  while (dir_list)
  {
    dir_entry *de = dir_list;
    dir_list = dir_list->next;
    free(de->name);
    free(de->full_name);
    free(de->content_type);
    //TODO free all added fields
    free(de->md5sum);
    free(de);
  }
}


void dir_decache(const char *path)
{
  dir_cache *cw;
	debugf(KCYN "dir_decache(%s)", path);
  pthread_mutex_lock(&dmut);
  dir_entry *de, *tmpde;
  char dir[MAX_PATH_SIZE];
  dir_for(path, dir);
  for (cw = dcache; cw; cw = cw->next)
  {
    if (!strcmp(cw->path, path))
    {
      if (cw == dcache)
        dcache = cw->next;
      if (cw->prev)
        cw->prev->next = cw->next;
      if (cw->next)
        cw->next->prev = cw->prev;
      cloudfs_free_dir_list(cw->entries);
      free(cw->path);
      free(cw);
    }
    else if (cw->entries && !strcmp(dir, cw->path))
    {
      if (!strcmp(cw->entries->full_name, path))
      {
        de = cw->entries;
        cw->entries = de->next;
        de->next = NULL;
        cloudfs_free_dir_list(de);
      }
      else for (de = cw->entries; de->next; de = de->next)
      {
        if (!strcmp(de->next->full_name, path))
        {
          tmpde = de->next;
          de->next = de->next->next;
          tmpde->next = NULL;
          cloudfs_free_dir_list(tmpde);
          break;
        }
      }
    }
  }
  pthread_mutex_unlock(&dmut);
}

void init_dir_entry(dir_entry *de) {
	de->size = 0;
	de->next = NULL;
	de->md5sum = NULL;
	de->accessed_in_cache = time(NULL);
	de->last_modified = time(NULL);
	de->mtime.tv_sec = time(NULL);
	de->atime.tv_sec = time(NULL);
	de->ctime.tv_sec = time(NULL);
	de->mtime.tv_nsec = 0;
	de->atime.tv_nsec = 0;
	de->ctime.tv_nsec = 0;
}
//check for file in cache, if found size will be updated, if not found and this is a dir, a new dir cache entry is created
void update_dir_cache(const char *path, off_t size, int isdir, int islink)
{
  debugf(KCYN "update_dir_cache(%s)", path);
  pthread_mutex_lock(&dmut);
  dir_cache *cw;
  dir_entry *de;
  char dir[MAX_PATH_SIZE];
  dir_for(path, dir);
  for (cw = dcache; cw; cw = cw->next)
  {
    if (!strcmp(cw->path, dir))
    {
      for (de = cw->entries; de; de = de->next)
      {
        if (!strcmp(de->full_name, path))
        {
          de->size = size;
          pthread_mutex_unlock(&dmut);
					debugf("exit 0: update_dir_cache(%s)", path);
          return;
        }
      }
      de = (dir_entry *)malloc(sizeof(dir_entry));
			init_dir_entry(de);

      de->size = size;
      de->isdir = isdir;
      de->islink = islink;
      de->name = strdup(&path[strlen(cw->path) + 1]);
      de->full_name = strdup(path);
			/*
      de->md5sum = NULL;
			de->accessed_in_cache = time(NULL);
			de->last_modified = time(NULL);
			// utimens change
			de->mtime.tv_sec = time(NULL);
			de->atime.tv_sec = time(NULL);
			de->ctime.tv_sec = time(NULL);
			de->mtime.tv_nsec = 0;
			de->atime.tv_nsec = 0;
			de->ctime.tv_nsec = 0;
			// change end
			*/
      if (isdir)
      {
        de->content_type = strdup("application/link");
      }
      if (islink)
      {
        de->content_type = strdup("application/directory");
      }
      else
      {
        de->content_type = strdup("application/octet-stream");
      }
      de->next = cw->entries;
      cw->entries = de;
      if (isdir)
        new_cache(path);
      break;
    }
  }
	debugf("exit 1: update_dir_cache(%s)", path);
  pthread_mutex_unlock(&dmut);
}

//returns first file entry in linked list. if not in cache will be downloaded.
int caching_list_directory(const char *path, dir_entry **list)
{
	debugf("caching_list_directory(%s)", path);
	//int lock = pthread_mutex_trylock(&dmut);
	//debugf("Mutex lock on caching_list_directory=%d", lock);
  pthread_mutex_lock(&dmut);
	bool new_entry = false;
	if (!strcmp(path, "/"))
    path = "";
  
	dir_cache *cw;
  for (cw = dcache; cw; cw = cw->next)
  if (!strcmp(cw->path, path)){
    //debugf("Found in list directory %s", cw->path);
    break;
  }
  if (!cw)
  {
		//trying to download this entry from cloud, list will point to cached or downloaded entries
    if (!cloudfs_list_directory(path, list)){
			//download was not ok
      pthread_mutex_unlock(&dmut);
			debugf("exit 0: caching_list_directory(%s) "KRED"[CACHE-DIR-MISS]", path);
      return  0;
    }
		debugf("caching_list_directory: new_cache(%s) "KYEL"[CACHE-CREATE]", path);
    cw = new_cache(path);
		new_entry = true;
  }
  else if (cache_timeout > 0 && (time(NULL) - cw->cached > cache_timeout))
  {
    if (!cloudfs_list_directory(path, list)){
      //mutex unlock was forgotten?
      pthread_mutex_unlock(&dmut);
			debugf("exit 1: caching_list_directory(%s)", path);
      return  0;
    }
    cloudfs_free_dir_list(cw->entries);
    cw->cached = time(NULL);
		debugf("status: caching_list_directory(%s) "KYEL"[CACHE-EXPIRED]", path);
  }
	else {
		debugf("status: caching_list_directory(%s) "KGRN"[CACHE-DIR-HIT]", path);
		*list = cw->entries;
	}
	//adding new dir file list to global cache, now the dir becomes visible
  cw->entries = *list;
  pthread_mutex_unlock(&dmut);
	debugf("exit 2: caching_list_directory(%s)", path);
  return 1;
}

dir_entry *path_info(const char *path)
{
	debugf("path_info(%s)", path);
	char dir[MAX_PATH_SIZE];
	dir_for(path, dir);
	dir_entry *tmp;
	if (!caching_list_directory(dir, &tmp)) {
		debugf("exit 0: path_info(%s) "KRED"[CACHE-DIR-MISS]", path);
		return NULL;
	}
	//iterate in file list obtained from cache or downloaded
	for (; tmp; tmp = tmp->next)
	{
		if (!strcmp(tmp->full_name, path)) {
			//debugf("FOUND in cache %s", tmp->full_name);
			debugf("exit 1: path_info(%s) %s[CACHE-FILE-HIT]", path, KGRN);
			return tmp;
		}
	}
	debugf("exit 2: path_info(%s) %s[CACHE-MISS]", path, KRED);
	return NULL;
}


//retrieve folder from local cache if exists, return null if does not exist
int check_caching_list_directory(const char *path, dir_entry **list)
{
	debugf("check_caching_list_directory(%s)", path);
	//int lock = pthread_mutex_trylock(&dmut);
	//debugf("Mutex lock on caching_list_directory=%d", lock);
	pthread_mutex_lock(&dmut);
	if (!strcmp(path, "/"))
		path = "";
	dir_cache *cw;
	for (cw = dcache; cw; cw = cw->next)
		if (!strcmp(cw->path, path)) {
			//debugf("Found in list directory %s", cw->path);
			*list = cw->entries;
			//cw->entries = *list;
			pthread_mutex_unlock(&dmut);
			debugf("exit 0: check_caching_list_directory(%s) %s[CACHE-DIR-HIT]", path, KGRN);
			return 1;
		}
	pthread_mutex_unlock(&dmut);
	debugf("exit 1: check_caching_list_directory(%s) %s[CACHE-DIR-MISS]", path, KRED);
	return 0;
}

dir_entry * check_parent_folder_for_file(const char *path) {
	char dir[MAX_PATH_SIZE];
	dir_for(path, dir);
	dir_entry *tmp;
	if (!check_caching_list_directory(dir, &tmp))
		return NULL;
	else
		return tmp;
}

//used to check if local path is in cache, without downloading from cloud if not in cache
dir_entry *check_path_info(const char *path)
{
	debugf("check_path_info(%s)", path);
	char dir[MAX_PATH_SIZE];
	dir_for(path, dir);
	dir_entry *tmp;

	//get parent folder cache entry
	if (!check_caching_list_directory(dir, &tmp)) {
		debugf("exit 0: check_path_info(%s) "KRED"[CACHE-MISS]", path);
		return NULL;
	}
	for (; tmp; tmp = tmp->next)
	{
		if (!strcmp(tmp->full_name, path)) {
			//debugf("FOUND in cache %s", tmp->full_name);
			debugf("exit 1: check_path_info(%s) %s[CACHE-HIT]", path, KGRN);
			return tmp;
		}
	}
	if (!strcmp(path, "/")) {
		debugf("exit 2: check_path_info(%s) "KYEL "ignoring root [CACHE-MISS]", path);
	}
	else {
		debugf("exit 3: check_path_info(%s) "KRED"[CACHE-MISS]", path);
	}
	return NULL;
}


char *get_home_dir()
{
  char *home;
  if ((home = getenv("HOME")) && !access(home, R_OK))
    return home;
  struct passwd *pwd = getpwuid(geteuid());
  if ((home = pwd->pw_dir) && !access(home, R_OK))
    return home;
  return "~";
}

void cloudfs_debug(int dbg)
{
	debug = dbg;
}

void debugf(char *fmt, ...)
{
  if (debug)
  {
    pthread_t thread_id = (unsigned int)pthread_self();
    //char thread_name[THREAD_NAMELEN];
    //pthread_getname_np(thread_id, thread_name, THREAD_NAMELEN);
    va_list args;
    char prefix[] = "==DEBUG %s:%d==";
    char line [1024];
    sprintf(line, prefix, "T", thread_id);
    fputs(line, stderr);
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
		fputs(KNRM, stderr);
		putc('\n', stderr);
		putc('\r', stderr);
		/*
		Program received signal SIGSEGV, Segmentation fault.
		0x00007ffff65c1e2c in _IO_vfprintf_internal (s=<optimized out>, format=<optimized out>, ap=<optimized out>) at vfprintf.c:1642
		1642    vfprintf.c: No such file or directory.
		(gdb) back
		#0  0x00007ffff65c1e2c in _IO_vfprintf_internal (s=<optimized out>, format=<optimized out>, ap=<optimized out>) at vfprintf.c:1642
		#1  0x00007ffff65c2b61 in buffered_vfprintf (s=s@entry=0x7ffff691b060 <_IO_2_1_stderr_>, format=format@entry=0x4096d8 "Received http code=%d %s %s[HTTP ERR]",
		args=args@entry=0x7fffffff6718) at vfprintf.c:2348
		#2  0x00007ffff65bd3de in _IO_vfprintf_internal (s=0x7ffff691b060 <_IO_2_1_stderr_>, format=format@entry=0x4096d8 "Received http code=%d %s %s[HTTP ERR]",
		ap=ap@entry=0x7fffffff6718) at vfprintf.c:1296
		#3  0x000000000040827c in debugf (fmt=0x4096d8 "Received http code=%d %s %s[HTTP ERR]") at commonfs.c:447
		#4  0x0000000000404c4e in send_request_size (method=0x408ebd "PUT",
		path=0x7aad41 "backup/movies/Action%20War/Tropa.de.Elite.Elite.Squad.2007.blu-ray.x264.720P.DTS-CHD/Tropa.de.Elite.Elite.Squad.2007.blu-ray.x264.720P.DTS-CHD.mkv", fp=0x20, fp@entry=0x0, xmlctx=0xffffffffffffffff, xmlctx@entry=0x0, extra_headers=0x191, file_size=140737326623226, file_size@entry=0, is_segment=0,
		de_cached_entry=0x0) at cloudfsapi.c:463

		*/
  }
}

