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
#include <sys/syscall.h>
#include <openssl/md5.h>
#include <pwd.h>
#include <fuse.h>
#include <limits.h>
#include <curl/curl.h>
#include <curl/easy.h>
#include <errno.h>
#include <syslog.h>
#include <dirent.h>
#include "commonfs.h"
#include "config.h"

pthread_mutex_t dcachemut;
pthread_mutex_t dcacheuploadmut;
pthread_mutex_t dlockmut;//file locking
pthread_mutexattr_t mutex_attr;
pthread_mutexattr_t segment_mutex_attr;
pthread_mutexattr_t lock_mutex_attr;


dir_cache* dcache;//stores accessed files
dir_cache* dcache_upload;//stores files being modified

open_file* openfile_list = NULL;//stores all opened files

char* temp_dir;
int cache_timeout;
int debug = 0;
int verify_ssl = 2;
long segment_size;//segment file size
long segment_above;//max size of a file before being segmented
bool option_get_extended_metadata = false;
bool option_curl_verbose = false;
int option_cache_statfs_timeout = 0;
int option_debug_level = 0;
int option_curl_progress_state = 1;//1 to disable curl progress
bool option_enable_chown = false;
bool option_enable_chmod = false;
bool option_enable_progressive_upload = false;
bool option_enable_progressive_download = false;
bool option_enable_syslog = false;
long option_min_speed_limit_progressive = 0;//use long not double
long option_min_speed_timeout;
long option_read_ahead = 0;
bool option_enable_chaos_test_monkey = false;//create random errors for testing
bool option_disable_atime_check = false;
char* option_http_log_path;
//if file count more than this do not load meta
int option_fast_list_dir_limit = 0;
bool option_async_delete = false;
pthread_t control_thread = NULL;
char* g_current_op;//current thread operation
int g_thread_id;//current thread id
int g_delete_thread_count = 0;

FuseOptions options =
{
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

ExtraFuseOptions extra_options =
{
  .get_extended_metadata = "false",
  .curl_verbose = "false",
  .cache_statfs_timeout = 0,
  .debug_level = 0,
  .curl_progress_state = "false",
  .enable_chown = "false",
  .enable_chmod = "false",
  .enable_progressive_upload = "false",
  .enable_progressive_download = "false",
  .min_speed_limit_progressive = "0",
  .min_speed_timeout = "3",
  .read_ahead = "0",
  .enable_syslog = "0",
  .enable_chaos_test_monkey = "false",
  .disable_atime_check = "false",
  .http_log_path = "",
  .fast_list_dir_limit = 0,
  .async_delete = "false"
};


// needed to get correct GMT / local time, as it does not work
// http://zhu-qy.blogspot.ro/2012/11/ref-how-to-convert-from-utc-to-local.html
time_t my_timegm(struct tm* tm)
{
  time_t epoch = 0;
  time_t offset = mktime(gmtime(&epoch));
  time_t utc = mktime(tm);
  return difftime(utc, offset);
}

// hubic stores time as GMT so we have to do conversions

/* void time_t set_now_time_to_gmt(){
   struct timespec now;
   clock_gettime(CLOCK_REALTIME, &now);
   http://stackoverflow.com/questions/1764710/converting-string-containing-localtime-into-utc-in-c
   }
*/
//expect time_str as a friendly string format
time_t get_time_from_str_as_gmt(char* time_str)
{
  struct tm val_time_tm;
  time_t val_time_t;
  strptime(time_str, "%FT%T", &val_time_tm);
  val_time_tm.tm_isdst = -1;
  val_time_t = my_timegm(&val_time_tm);
  return val_time_t;
}

/*
   return time as time_t, and if time_str != NULL returns also a string
   representation in time_str
*/
time_t get_time_as_local(time_t time_t_val, char time_str[], int char_buf_size)
{
  struct tm loc_time_tm;
  loc_time_tm = *localtime(&time_t_val);
  if (time_str != NULL)
  {
    //debugf(DBG_NORM, 0,"Local len=%d size=%d pass=%d", strlen(time_str), sizeof(time_str), char_buf_size);
    strftime(time_str, char_buf_size, "%c", &loc_time_tm);
    //debugf(DBG_NORM, 0,"Local timestr=[%s] size=%d", time_str, strlen(time_str));
  }
  //debugf(DBG_NORM, 0,"Local time_t %li", mktime(&loc_time_tm));
  return mktime(&loc_time_tm);
}

int get_time_as_string(time_t time_t_val, long nsec, char* time_str,
                       int time_str_len)
{
  struct tm time_val_tm;
  time_t safe_input_time;
  //if time is incorrect (too long) you get segfault, need to check length and trim
  if (time_t_val > INT_MAX)
  {
    debugf(DBG_NORM, KRED
           "get_time_as_string: input time too long, %lu > max=%lu, trimming!",
           time_t_val, INT_MAX);
    safe_input_time = 0;//(int)time_t_val;
  }
  else
    safe_input_time = time_t_val;
  time_val_tm = *gmtime(&safe_input_time);
  int str_len = strftime(time_str, time_str_len, HUBIC_DATE_FORMAT,
                         &time_val_tm);
  char nsec_str[TIME_CHARS];
  sprintf(nsec_str, "%ld", nsec);
  strcat(time_str, nsec_str);
  return str_len + strlen(nsec_str);
}

time_t get_time_now()
{
  struct timespec now;
  clock_gettime(CLOCK_REALTIME, &now);
  return now.tv_sec;
}

size_t get_time_now_as_str(char* time_str, int time_str_len)
{
  time_t     now = time(0);
  struct tm  tstruct;
  tstruct = *localtime(&now);
  // Visit http://en.cppreference.com/w/cpp/chrono/c/strftime
  // for more information about date/time format
  size_t result = strftime(time_str, time_str_len, HUBIC_DATE_FORMAT, &tstruct);
  return result;
}

/*
   get current time with milisecond precision
   return size of time string
*/
size_t get_time_now_milisec_as_str(char* time_str, int time_str_len)
{
  struct timeval tv;
  time_t curtime;
  char tmp_time_str[TIME_CHARS];
  gettimeofday(&tv, NULL);
  curtime = tv.tv_sec;
  strftime(tmp_time_str, time_str_len, HUBIC_DATE_FORMAT, localtime(&curtime));
  int res = snprintf(time_str, time_str_len, "%s%ld", tmp_time_str, tv.tv_usec);
  return res;
}

int get_timespec_as_str(const struct timespec* times, char* time_str,
                        int time_str_len)
{
  return get_time_as_string(times->tv_sec, times->tv_nsec, time_str,
                            time_str_len);
}

/*
   set dir_entry access time to now
*/
void update_cache_access(dir_entry* de)
{
  if (de)
    de->accessed_in_cache = get_time_now();
}

//solution from http://stackoverflow.com/questions/7627723/how-to-create-a-md5-hash-of-a-string-in-c
char* str2md5(const char* str, int length)
{
  int n;
  MD5_CTX c;
  unsigned char digest[16];
  char* out = (char*)malloc(33);
  MD5_Init(&c);
  while (length > 0)
  {
    if (length > 512)
      MD5_Update(&c, str, 512);
    else
      MD5_Update(&c, str, length);
    length -= 512;
    str += 512;
  }
  MD5_Final(digest, &c);
  for (n = 0; n < 16; ++n)
    snprintf(&(out[n * 2]), 16 * 2, "%02x", (unsigned int)digest[n]);
  return out;
}

/*
   solution from http://stackoverflow.com/questions/10324611/how-to-calculate-the-md5-hash-of-a-large-file-in-c
   carefull with md5_file_str size
*/
int file_md5(FILE* file_handle, char* md5_file_str)
{
  debugf(DBG_EXT, "file_md5: start compute sum fp=%p", file_handle);
  if (file_handle == NULL)
  {
    debugf(DBG_NORM, KRED"file_md5: NULL file handle");
    return 0;
  }
  unsigned char c[MD5_DIGEST_LENGTH];
  int i;
  MD5_CTX mdContext;
  int bytes;
  char mdchar[3];//2 chars for md5 + null string terminator
  unsigned char* data_buf = malloc(1024 * sizeof(unsigned char));
  MD5_Init(&mdContext);
  int seekres = fseek(file_handle, 0, SEEK_SET);
  if (seekres != 0)
  {
    debugf(DBG_EXT, KRED "unable to seek to 0, res=%d", seekres);
    abort();
  }
  while ((bytes = fread(data_buf, 1, 1024, file_handle)) != 0)
    MD5_Update(&mdContext, data_buf, bytes);
  MD5_Final(c, &mdContext);
  for (i = 0; i < MD5_DIGEST_LENGTH; i++)
  {
    snprintf(mdchar, 3, "%02x", c[i]);
    strcat(md5_file_str, mdchar);
    //fprintf(stderr, "%02x", c[i]);
  }
  free(data_buf);
  debugf(DBG_EXT, "file_md5: end compute sum=%s fp=%p",
         md5_file_str, file_handle);
  return 0;
}

/*
   init md5 context before starting
   to calculate md5sum on a http job (upload or download)
*/
bool init_job_md5(thread_job* job)
{
  debugf(DBG_EXT, KMAG "init_job_md5(%s)", job->job_name);
  if (job->md5str)
    free(job->md5str);
  job->md5str = NULL;
  job->is_mdcontext_saved = false;
  return (MD5_Init(&job->mdContext) == 1);
}

/*
   updates md5sum based on data received
*/
bool update_job_md5(thread_job* job, const unsigned char* data_buf,
                    int buf_len)
{
  debugf(DBG_EXTALL, "update_job_md5(%s): len=%lu", job->job_name, buf_len);
  return (MD5_Update(&job->mdContext, data_buf, buf_len) == 1);
}

/*
   saves a snapshot of md5 context
*/
void save_job_md5(thread_job* job)
{
  memcpy(&job->mdContext_saved, &job->mdContext, sizeof(MD5_CTX));
  job->is_mdcontext_saved = true;
}
/*
   restores the snapshot of md5 context
*/
void restore_job_md5(thread_job* job)
{
  assert(job->is_mdcontext_saved);
  memcpy(&job->mdContext, &job->mdContext_saved, sizeof(MD5_CTX));
}
/*
   generates final md5sum for data received so far
*/
bool complete_job_md5(thread_job* job)
{
  int result = 0;
  unsigned char c[MD5_DIGEST_LENGTH];
  result = MD5_Final(c, &job->mdContext);
  if (result == 1)
  {
    char md5_str[MD5_DIGEST_HEXA_STRING_LEN] = "\0";
    int i;
    char mdchar[3];//2 chars for md5 + null string terminator
    for (i = 0; i < MD5_DIGEST_LENGTH; i++)
    {
      snprintf(mdchar, 3, "%02x", c[i]);
      strcat(md5_str, mdchar);
    }
    job->md5str = strdup(md5_str);
  }
  else abort();
  debugf(DBG_EXT, KMAG "complete_job_md5(%s:%s): job %s md5sum=%s",
         job->de ? job->de->name : "nil", job->de_seg ? job->de_seg->name : "nil",
         job->job_name, job->md5str);
  return result;
}

thread_copy_job* init_thread_copy_job()
{
  debugf(DBG_EXTALL, "thread_copy_job: freeing copy job");
  thread_copy_job* job = malloc(sizeof(struct thread_copy_job));
  job->dest = NULL;
  job->de_src = NULL;
  job->manifest = NULL;
  return job;
}

void free_thread_copy_job(thread_copy_job* job)
{
  debugf(DBG_EXTALL, "thread_copy_job: freeing copy job");
  free(job->dest);
  free(job->manifest);
  free(job);
}

thread_job* init_thread_job(char* job_name)
{
  debugf(DBG_EXTALL, "init_thread_job(%s): init job", job_name);
  thread_job* job = malloc(sizeof(struct thread_job));
  job->md5str = NULL;
  job->job_name = job_name;
  job->de = NULL;
  job->de_seg = NULL;
  return job;
}

void free_thread_job(thread_job* job)
{
  debugf(DBG_EXTALL, "free_thread_job(%s): freeing job", job->job_name);
  if (job->md5str)
    free(job->md5str);
  if (job->job_name)
    free(job->job_name);
  job->md5str = NULL;
  job->job_name = NULL;
  job->de = NULL;
  job->de_seg = NULL;
  free(job);
}
/*
   determines if local cache content equals cloud content
*/
bool file_changed_md5(dir_entry* de)
{
  bool result;
  result = (!de->md5sum || !de->md5sum_local
            || strcasecmp(de->md5sum_local, de->md5sum));
  return result;
}

/*
   determines if cached file time is different than cloud time.
   if different this usually means content has changed (write or trunc).
*/
bool file_changed_time(dir_entry* de)
{
  bool result;
  result = (de->ctime.tv_sec != de->ctime_local.tv_sec
            || de->ctime.tv_nsec == de->ctime_local.tv_nsec);
  return result;
}

int update_direntry_md5sum(char* md5sum_str, FILE* fp)
{
  char md5_file_hash_str[MD5_DIGEST_HEXA_STRING_LEN] = "\0";
  file_md5(fp, md5_file_hash_str);
  if (md5sum_str)
    free(md5sum_str);
  md5sum_str = strdup(md5_file_hash_str);
}

int file_md5_by_name(const char* file_name_str, char* md5_file_str)
{
  FILE* fp = fopen(file_name_str, "rb");
  int result = file_md5(fp, md5_file_str);
  fclose(fp);
  return result;
}

void removeSubstr(char* string, char* sub)
{
  char* match;
  int len = strlen(sub);
  while ((match = strstr(string, sub)))
  {
    *match = '\0';
    strcat(string, match + len);
  }
}

/*
   check if http response code means the operation completed ok
*/
bool valid_http_response(int response)
{
  return (response >= 200 && response < 300);
}
/* compose a unique cache file path within max name bounds
   temp_dir = file folder prefix
   parent_dir_path_safe = returns parent dir, optional, set to null if not needed
   segment_part >=0 for segmented files, otherwise use -1
*/
int get_safe_cache_file_path(const char* path, char* file_path_safe,
                             char* parent_dir_path_safe, const char* temp_dir,
                             const int segment_part)
{
  char tmp_path[PATH_MAX];
  strncpy(tmp_path, path, PATH_MAX);
  char* pch;
  while ((pch = strchr(tmp_path, '/')))
    * pch = '.';
  char file_path[PATH_MAX] = "";
  //temp file name had process pid in it, removed as on restart files are left in cache (pid changes)
  snprintf(file_path, PATH_MAX, TEMP_FILE_NAME_FORMAT, temp_dir, tmp_path);
  //fixme check if sizeof or strlen is suitable
  int file_path_len = strlen(file_path);
  //the file path name using this format can go beyond NAME_MAX size and will generate error on fopen
  //solution: cap file length to NAME_MAX, use a prefix from original path for debug purposes and add md5 id
  char* md5_path = str2md5(file_path, file_path_len);
  int md5len = strlen(md5_path);
  int suffix_len = 0;
  char suffix_str[PATH_MAX] = "";
  if (segment_part >= 0)
  {
    snprintf(suffix_str, PATH_MAX, TEMP_SEGMENT_FORMAT, segment_part);
    suffix_len = strlen(suffix_str);
  }
  size_t safe_len_prefix = min(NAME_MAX - md5len - suffix_len,
                               file_path_len);
  strncpy(file_path_safe, file_path, safe_len_prefix);
  strncpy(file_path_safe + safe_len_prefix, md5_path, md5len);
  strncpy(file_path_safe + safe_len_prefix + md5len, suffix_str,
          suffix_len);
  if (parent_dir_path_safe != NULL)
  {
    strncpy(parent_dir_path_safe, file_path, safe_len_prefix);
    strncpy(parent_dir_path_safe + safe_len_prefix, md5_path, md5len);
    parent_dir_path_safe[safe_len_prefix + md5len] = '\0';
    strcat(parent_dir_path_safe, TEMP_SEGMENT_DIR_SUFFIX);
  }
  //properly terminate the string as strncpy does not append {0}
  file_path_safe[safe_len_prefix + md5len + suffix_len] = '\0';
  free(md5_path);
  return strlen(file_path_safe);
}

void get_file_path_from_fd(int fd, char* path, int size_path)
{
  char proc_path[MAX_PATH_SIZE];
  /* Read out the link to our file descriptor. */
  sprintf(proc_path, "/proc/self/fd/%d", fd);
  memset(path, 0, size_path);
  readlink(proc_path, path, size_path - 1);
}

void debug_print_flags(int flags)
{
  int accmode, val;
  accmode = flags & O_ACCMODE;
  if (accmode == O_RDONLY)            debugf(DBG_EXTALL, KYEL"read only");
  else if (accmode == O_WRONLY)   debugf(DBG_EXTALL, KYEL"write only");
  else if (accmode == O_RDWR)     debugf(DBG_EXTALL, KYEL"read write");
  else debugf(DBG_EXT, KYEL"unknown access mode");
  if (val & O_APPEND)         debugf(DBG_EXTALL, KYEL", append");
  if (val & O_NONBLOCK)       debugf(DBG_EXTALL, KYEL", nonblocking");
#if !defined(_POSIX_SOURCE) && defined(O_SYNC)
  if (val & O_SYNC)           debugf(DBG_EXT, 0,
                                       KRED ", synchronous writes");
#endif
}

void debug_print_file_name(FILE* fp)
{
  int MAXSIZE = 0xFFF;
  char proclnk[0xFFF];
  char filename[0xFFF];
  int fno;
  ssize_t r;
  if (fp != NULL)
  {
    fno = fileno(fp);
    sprintf(proclnk, "/proc/self/fd/%d", fno);
    r = readlink(proclnk, filename, MAXSIZE);
    if (r < 0)
      debugf(DBG_EXT, KRED"debug_print_file_name: "KYEL"failed to readlink");
    else
    {
      filename[r] = '\0';
      debugf(DBG_EXT, KMAG"fp -> fno -> filename: %p -> %d -> %s\n",
             fp, fno, filename);
    }
  }
}
void debug_print_descriptor(struct fuse_file_info* info)
{
  return;
  char file_path[MAX_PATH_SIZE];
  get_file_path_from_fd(info->fh, file_path, sizeof(file_path));
  debugf(DBG_EXTALL, KCYN "descriptor localfile=[%s] fd=%d", file_path,
         info->fh);
  debug_print_flags(info->flags);
}

void dir_for(const char* path, char* dir)
{
  strncpy(dir, path, MAX_PATH_SIZE);
  char* slash = strrchr(dir, '/');
  if (slash)
    *slash = '\0';
}

//prints cache content for debug purposes
void debug_list_cache_content()
{
  return;//disabled
  dir_cache* cw;
  dir_entry* de;
  for (cw = dcache; cw; cw = cw->next)
  {
    debugf(DBG_EXT, "LIST-CACHE: DIR[%s]", cw->path);
    for (de = cw->entries; de; de = de->next)
      debugf(DBG_EXT, "LIST-CACHE:   FOLDER[%s]", de->full_name);
  }
}

int delete_file(char* path)
{
  debugf(DBG_NORM, KYEL"delete_file(%s)", path);
  char file_path_safe[NAME_MAX] = "";
  get_safe_cache_file_path(path, file_path_safe, NULL, temp_dir, -1);
  int result = unlink(file_path_safe);
  debugf(DBG_EXT, KYEL "delete_file(%s): local=%s, result=%s", path,
         file_path_safe, strerror(result));
  return result;
}

//adding a directory in cache
dir_cache* internal_new_cache(dir_cache** cache, const char* path)
{
  debugf(DBG_NORM, KCYN"new_cache(%s)", path);
  dir_cache* cw = (dir_cache*)calloc(sizeof(dir_cache), 1);
  cw->path = strdup(path);
  cw->prev = NULL;
  cw->entries = NULL;
  cw->cached = time(NULL);
  //added cache by access
  cw->accessed_in_cache = time(NULL);
  cw->was_deleted = false;
  if (*cache)
    (*cache)->prev = cw;
  cw->next = *cache;
  dir_cache* result;
  result = (*cache = cw);
  debugf(DBG_EXT, "exit: new_cache(%s)", path);
  return result;
}

dir_cache* new_cache(const char* path)
{
  debugf(DBG_NORM, KCYN"new_cache(%s): access cache", path);
  return internal_new_cache(&dcache, path);
}

dir_cache* new_cache_upload(const char* path)
{
  debugf(DBG_NORM, KCYN"new_cache(%s): upload cache", path);
  return internal_new_cache(&dcache_upload, path);
}

//todo: check if the program behaves ok  when free_dir
//is made on a folder that has an operation in progress
void cloudfs_free_dir_list(dir_entry* dir_list)
{
  assert(dir_list);
  //check for NULL as dir might be already removed from cache by other thread
  debugf(DBG_NORM, KMAG "cloudfs_free_dir_list(%s:%s)",
         dir_list->full_name, dir_list->name);
  while (dir_list)
  {
    dir_entry* de = dir_list;
    dir_list = dir_list->next;
    free(de->name);
    de->name = NULL;
    free(de->full_name);
    de->full_name = NULL;
    free(de->content_type);
    de->content_type = NULL;
    free(de->md5sum);
    de->md5sum = NULL;
    free(de->md5sum_local);
    de->md5sum_local = NULL;
    free(de->full_name_hash);
    de->full_name_hash = NULL;
    free(de->manifest_cloud);
    de->manifest_cloud = NULL;
    free(de->manifest_seg);
    de->manifest_seg = NULL;
    free(de->manifest_time);
    de->manifest_time = NULL;
    if (de->segments)
    {
      cloudfs_free_dir_list(de->segments);
      de->segments = NULL;
    }

    //check as some might be freed already
    if (de->upload_buf.sem_list[SEM_EMPTY])
      free_semaphores(&de->upload_buf, SEM_EMPTY);
    if (de->upload_buf.sem_list[SEM_FULL])
      free_semaphores(&de->upload_buf, SEM_FULL);
    if (de->upload_buf.sem_list[SEM_DONE])
      free_semaphores(&de->upload_buf, SEM_DONE);
    //no need to free de->upload_buf.readptr as
    //it is only a pointer to a buffer allocated / managed by fuse
    free(de);
  }
}


/*
   return a segment entry from dir_entry
   it assumes segments are stored in sorted ascending order
   NOTE!: it also sets the segment_part field
*/
dir_entry* get_segment(dir_entry* de, int segment_index)
{
  int de_segment = 0, seg_index_cloud;
  dir_entry* des = de->segments;
  while (des)
  {
    seg_index_cloud = atoi(des->name);
    if (de_segment != seg_index_cloud)
    {
      debugf(DBG_EXT, KYEL
             "get_segment(%s:%d) unexpected segment %s at @%d", de->name,
             segment_index, des->name, de_segment);
      abort();
    }
    if (de_segment == segment_index)
    {
      if (des->segment_part != segment_index)
        des->segment_part = segment_index;
      return des;
    }
    des = des->next;
    de_segment++;
  }
  return des;//this will be NULL
}

/*
   unencode string, convert %2f to /
*/
void decode_path(char* path)
{
  char* slash;
  while ((slash = strstr(path, "%2F")) || (slash = strstr(path, "%2f")))
  {
    *slash = '/';
    memmove(slash + 1, slash + 3, strlen(slash + 3) + 1);
  }
}

void split_path(const char* path, char* seg_base, char* container,
                char* object)
{
  char* string = strdup(path);
  snprintf(seg_base, MAX_URL_SIZE, "%s", strsep(&string, "/"));
  strncat(container, strsep(&string, "/"),
          MAX_URL_SIZE - strnlen(container, MAX_URL_SIZE));
  char* _object = strsep(&string, "/");
  char* remstr;
  while (remstr = strsep(&string, "/"))
  {
    strncat(container, "/",
            MAX_URL_SIZE - strnlen(container, MAX_URL_SIZE));
    strncat(container, _object,
            MAX_URL_SIZE - strnlen(container, MAX_URL_SIZE));
    _object = remstr;
  }
  //fixme: when removing root folders this will generate a segfault, issue #83, https://github.com/TurboGit/hubicfuse/issues/83
  if (_object == NULL)
    _object = object;
  else
    strncpy(object, _object, MAX_URL_SIZE);
  free(string);
}

/*
   get manifest path using main file mane
*/
void get_manifest_path(dir_entry* de, char* manifest_path)
{
  char seg_base[MAX_URL_SIZE] = "";
  char container[MAX_URL_SIZE] = "";
  char object[MAX_URL_SIZE] = "";
  split_path(de->full_name, seg_base, container, object);
  snprintf(manifest_path, MAX_URL_SIZE, "%s_segments", container);
}

void get_segment_manifest(char* manifest_seg, dir_entry* de, int seg_index)
{
  //format segment full path
  snprintf(manifest_seg, MAX_URL_SIZE, "/%s/%08i", de->manifest_time, seg_index);
}


/*
   set manifest fields, usually for a new file
*/
void set_manifest_meta(char* path, dir_entry* de, int man_type)
{
  assert(de->is_segmented);
  char manifest[MAX_URL_SIZE];
  char seg_base[MAX_URL_SIZE] = "";
  char container[MAX_URL_SIZE] = "";
  char object[MAX_URL_SIZE] = "";
  split_path(path, seg_base, container, object);
  struct timespec now;
  clock_gettime(CLOCK_REALTIME, &now);
  char string_float[TIME_CHARS];
  snprintf(string_float, TIME_CHARS, "%lu.%lu", now.tv_sec, now.tv_nsec);
  char meta_mtime[TIME_CHARS];
  snprintf(meta_mtime, TIME_CHARS, "%f", atof(string_float));
  //fixme: manifest path might be too long
  snprintf(manifest, MAX_URL_SIZE, "%s/%s_segments",
           HUBIC_SEGMENT_STORAGE_ROOT, container);
  if (man_type == META_MANIF_SEG || man_type == META_MANIF_ALL)
  {
    if (de->manifest_seg)
      free(de->manifest_seg);
    de->manifest_seg = strdup(manifest);
  }
  if (man_type == META_MANIF_TIME || man_type == META_MANIF_ALL)
  {
    snprintf(manifest, MAX_URL_SIZE, "%s/%s_segments/%s/%s",
             HUBIC_SEGMENT_STORAGE_ROOT, container, object, meta_mtime);
    //ensure len is not to big
    assert(strlen(manifest) + 8 < MAX_URL_SIZE);
    if (!de->manifest_time)
    {
      free(de->manifest_time);
      debugf(DBG_EXT, KCYN "set_manifest_meta(%s): OVERRIDE manifest_time=%s",
             de->name,
             manifest);
    }
    de->manifest_time = strdup(manifest);
    debugf(DBG_EXT, KCYN "set_manifest_meta(%s): manifest_time=%s", de->name,
           manifest);
  }
  if (man_type == META_MANIF_CLOUD || man_type == META_MANIF_ALL)
  {
    //this is initialised in get_meta_dispatch
    if (!de->manifest_cloud)
    {
      snprintf(manifest, MAX_URL_SIZE, "/%s", de->manifest_time);
      de->manifest_cloud = strdup(manifest);
    }
  }
}

/*
   set all manifest fields
*/
void create_manifest_meta(dir_entry* de)
{
  assert(de->is_segmented);
  assert(!de->manifest_cloud);
  assert(!de->manifest_seg);
  assert(!de->manifest_time);
  set_manifest_meta(de->full_name, de, META_MANIF_ALL);
}

/*
   populates segment standard fields
*/
void create_segment_meta(dir_entry* de_seg, int seg_index, dir_entry* de)
{
  assert(de->manifest_time);
  assert(!de_seg->name);
  assert(!de_seg->full_name);
  assert(!de_seg->full_name_hash);
  de_seg->segment_part = seg_index;
  char seg_name[8 + 1] = { 0 };
  snprintf(seg_name, 8 + 1, "%08i", seg_index);
  de_seg->name = strdup(seg_name);
  char seg_path[MAX_URL_SIZE] = { 0 };
  get_segment_manifest(seg_path, de, seg_index);
  de_seg->full_name = strdup(seg_path);
  de_seg->full_name_hash = strdup(str2md5(de_seg->full_name,
                                          strlen(de_seg->full_name)));
  de_seg->parent = de;
  //need to set seg_size so upload knows how much data to upload in a segment
  if (de_seg->segment_part < de->segment_full_count)
    de_seg->segment_size = de->segment_size;
  else de_seg->segment_size = de->segment_remaining;
}
/*
   set dir_entry standard meta using path (like name, full_name, hash)
*/
void create_entry_meta(const char* path, dir_entry* de)
{
  assert(de);
  //assert(!de->full_name);
  //assert(!de->name);
  //assert(!de->full_name_hash);
  char seg_base[MAX_URL_SIZE] = "";
  char container[MAX_URL_SIZE] = "";
  char object[MAX_URL_SIZE] = "";
  split_path(path, seg_base, container, object);
  if (!de->name)
    de->name = strdup(object);
  if (!de->full_name)
    de->full_name = strdup(path);
  //generate hash if was not generated on directory list (on copy_object)
  if (!de->full_name_hash)
    de->full_name_hash = strdup(str2md5(de->full_name, strlen(de->full_name)));
}
/*
   returns the segment.
   if does not exist then a new empty segment is created, used when writing new files.
   removed -> NOTE!: sets de->manifest field
*/
dir_entry* get_create_segment(dir_entry* de, int segment_index)
{
  int de_segment;
  dir_entry* de_seg;
  bool reused = false;
  if (!de->segments)
  {
    debugf(DBG_EXT, "get_create_segment(%s:%d): creating first segment",
           de->name, segment_index);
    de->segments = init_dir_entry();
    de_seg = de->segments;
  }
  else
  {
    int de_segment;
    de_seg = de->segments;
    while (de_seg)
    {
      de_segment = atoi(de_seg->name);
      if (de_segment == segment_index)
      {
        if (de_seg->segment_part != segment_index)
          de_seg->segment_part = segment_index;
        debugf(DBG_EXTALL, "get_create_segment(%s:%d): reusing segment",
               de->name, segment_index);
        reused = true;
        break;
      }
      if (!de_seg->next)
      {
        debugf(DBG_EXT, "get_create_segment(%s:%d): appending segment",
               de->name, segment_index);
        de_seg->next = init_dir_entry();
        de_seg = de_seg->next;
        break;
      }
      else
        de_seg = de_seg->next;
    }
  }
  assert(de_seg);
  if (!reused)
    create_segment_meta(de_seg, segment_index, de);
  return de_seg;
}

/*
   delete segments from memory cache
*/
void dir_decache_segments(dir_entry* de)
{
  if (de->segments)
    cloudfs_free_dir_list(de->segments);
  de->segments = NULL;
}

void lock_mutex(pthread_mutex_t mutex)
{
  debugf(DBG_EXTALL, KYEL "lock_mutex(%p)", &mutex);
  //int try = pthread_mutex_trylock(&mutex);
  //if (try == 0)
  //  debugf(DBG_ERR, KYEL "lock_mutex(%p)", &mutex);
  //    else
  pthread_mutex_lock(&mutex);
  debugf(DBG_EXTALL, KYEL "lock_mutex(%p): locked", &mutex);
}

void unlock_mutex(pthread_mutex_t mutex)
{
  //if (mutex == dcachemut)
  debugf(DBG_EXTALL, KYEL "unlock_mutex(%p)", &mutex);
  pthread_mutex_unlock(&mutex);
}

/*
   removes path from cache, I think only works fine with child objects?
*/
void internal_dir_decache(dir_cache* cache, pthread_mutex_t mutex,
                          const char* path)
{
  dir_cache* cw;
  debugf(DBG_NORM, "dir_decache(%s)", path);
  //pthread_mutex_lock(&mutex);
  lock_mutex(mutex);
  dir_entry* de, *tmpde;
  char dir[MAX_PATH_SIZE];
  dir_for(path, dir);
  for (cw = cache; cw; cw = cw->next)
  {
    //debugf(DBG_EXTALL, "dir_decache: parse(%s)", cw->path);
    if (!strcmp(cw->path, path) || path[0] == '*')
    {
      if (cw == cache)
        dcache = cw->next;
      if (cw->prev)
        cw->prev->next = cw->next;
      if (cw->next)
        cw->next->prev = cw->prev;
      debugf(DBG_EXT, "dir_decache: free_dir1(%s)", cw->path);
      //fix: this sometimes is NULL and generates segfaults, checking first
      if (cw->entries != NULL)
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
        debugf(DBG_EXT, "dir_decache: free_dir2()");
        cloudfs_free_dir_list(de);
      }
      else for (de = cw->entries; de->next; de = de->next)
        {
          if (!strcmp(de->next->full_name, path))
          {
            tmpde = de->next;
            de->next = de->next->next;
            tmpde->next = NULL;
            debugf(DBG_EXT, "dir_decache: free_dir3()", cw->path);
            cloudfs_free_dir_list(tmpde);
            break;
          }
        }
    }
  }
  //pthread_mutex_unlock(&mutex);
  unlock_mutex(mutex);
}

void dir_decache(const char* path)
{
  debugf(DBG_EXT, "dir_decache(%s)", path);
  internal_dir_decache(dcache, dcachemut, path);
}

void dir_decache_upload(const char* path)
{
  debugf(DBG_EXT, "dir_decache_upload(%s)", path);
  internal_dir_decache(dcache_upload, dcacheuploadmut, path);
}


//data_buf exists for dowload and upload
int init_semaphores(struct progressive_data_buf* data_buf, dir_entry* de,
                    char* prefix)
{
  debugf(DBG_EXTALL, "init_semaphores(%s): prefix=%s len=%d",
         de->full_name, prefix, strlen(prefix));
  char semaphore_name[MD5_DIGEST_HEXA_STRING_LEN + MAX_PATH_SIZE] = "\0";
  int errsv, sem_val, i;
  char* sem_name;
  for (i = 0; i <= SEM_DONE; i++)
  {
    if (data_buf->sem_list[i] || data_buf->sem_name_list[i])
    {
      debugf(DBG_NORM, KYEL
             "init_semaphores(%s): semaphore %d not null at init, name=%s",
             de->name, i, data_buf->sem_name_list[i]);
      abort();
    }
    if (i == SEM_EMPTY)
      sem_name = "isempty";
    else if (i == SEM_FULL)
      sem_name = "isfull";
    else if (i == SEM_DONE)
      sem_name = "isdone";
    else
    {
      debugf(DBG_EXTALL, "init_semaphores(%s): " KRED
             "unknown semaphore type=%d", de->full_name, i);
      abort();
    }
    assert(de->full_name_hash);
    snprintf(semaphore_name, sizeof(semaphore_name), "/%s_%s_%s_%s",
             prefix, sem_name, de->full_name_hash, de->name);
    //don't forget to free this
    data_buf->sem_name_list[i] = strdup(semaphore_name);
    debugf(DBG_EXTALL, "init_semaphores(%s): sem_name=%s", de->full_name,
           data_buf->sem_name_list[i]);
    //ensure semaphore does not exist
    //(might be in the system from a previous unclean finished operation)
    sem_unlink(data_buf->sem_name_list[i]);
    if ((data_buf->sem_list[i] = sem_open(data_buf->sem_name_list[i],
                                          O_CREAT | O_EXCL, 0644, 0)) == SEM_FAILED)
    {
      errsv = errno;
      debugf(DBG_NORM, KRED
             "init_semaphores(%s): cannot init isempty semaphore for progressive upload, err=%s",
             de->full_name, strerror(errsv));
      exit(1);
    }
    else
    {
      sem_getvalue(data_buf->sem_list[i], &sem_val);
      debugf(DBG_EXTALL, KCYN
             "init_semaphores(%s): semaphore[%s] created, size_left=%lu, sem_val=%d",
             de->full_name, data_buf->sem_name_list[i], data_buf->work_buf_size, sem_val);
    }
  }
  data_buf->sem_open = true;
  return true;
}

/*
  free semaphores from memory, assume it is not null
*/
void free_semaphores(struct progressive_data_buf* data_buf, int sem_index)
{
  debugf(DBG_EXTALL, KCYN "free_semaphores: %s-%d",
         data_buf->sem_name_list[sem_index], sem_index);
  assert(data_buf->sem_list[sem_index]);
  assert(data_buf->sem_name_list[sem_index]);
  sem_close(data_buf->sem_list[sem_index]);
  sem_unlink(data_buf->sem_name_list[sem_index]);
  data_buf->sem_list[sem_index] = NULL;
  free(data_buf->sem_name_list[sem_index]);
  data_buf->sem_name_list[sem_index] = NULL;
  data_buf->sem_open = false;
}

void free_all_semaphores(struct progressive_data_buf* data_buf)
{
  free_semaphores(data_buf, SEM_EMPTY);
  free_semaphores(data_buf, SEM_FULL);
  free_semaphores(data_buf, SEM_DONE);
}
/*
  post a semaphore and waits until semaphore count changes
  or exits after a period of time (250 milisecond)
*/
void unblock_semaphore(struct progressive_data_buf* data_buf, int sem_index)
{
  sem_t* semaphore = data_buf->sem_list[sem_index];
  char* name = data_buf->sem_name_list[sem_index];
  assert(semaphore);

  //if (semaphore)
  //{
  int sem_val1, sem_val2, i;
  sem_getvalue(semaphore, &sem_val1);
  //debugf(DBG_EXTALL, KMAG "unblock_semaphore(%s) start, val=%d", name, sem_val1);
  sem_post(semaphore);
  for (i = 0; i < 250; i++)
  {
    sem_getvalue(semaphore, &sem_val2);
    if (sem_val2 <= sem_val1)
      break;
    sleep_ms(1);
  }
  debugf(DBG_EXTALL, KMAG "unblock_semaphore(%s) in %d milisec, val %d->%d",
         name, i, sem_val1, sem_val2);
}
//else
//  debugf(DBG_EXT, KMAG "unblock_semaphore(%s) was null", name);
//}

/*
  semaphore is marked as closed, signaling operation completion
*/
void close_semaphore(struct progressive_data_buf* data_buf)
{
  debugf(DBG_EXTALL, KCYN "close_semaphore(%s): state is %d",
         data_buf->sem_name_list[SEM_DONE], data_buf->sem_open);
  assert(data_buf->sem_open);
  data_buf->sem_open = false;
}

bool is_semaphore_open(struct progressive_data_buf* data_buf)
{
  return data_buf->sem_open;
}
/*
  unblock and close all semaphores for this data buf
*/
void unblock_close_all_semaphores(struct progressive_data_buf* data_buf)
{
  unblock_semaphore(data_buf, SEM_EMPTY);
  unblock_semaphore(data_buf, SEM_FULL);
  unblock_semaphore(data_buf, SEM_DONE);
  close_semaphore(data_buf);
}

long random_at_most(long max)
{
  unsigned long
  // max <= RAND_MAX < ULONG_MAX, so this is okay.
  num_bins = (unsigned long)max + 1,
  num_rand = (unsigned long)RAND_MAX + 1,
  bin_size = num_rand / num_bins,
  defect = num_rand % num_bins;
  long x;
  do
  {
    x = random();
  }
  // This is carefully written not to overflow
  while (num_rand - defect <= (unsigned long)x);
  // Truncated division is intentional
  return x / bin_size;
}

/*
   init with cloud values without knowing extended metadata
   this is not safe for operations relaying on extended attribs
*/
void init_entry_lazy(dir_entry* de)
{
  de->lazy_meta = true;
}

/*
   default values for entry
*/
dir_entry* init_dir_entry()
{
  dir_entry* de = (dir_entry*)malloc(sizeof(dir_entry));
  de->metadata_downloaded = false;
  de->name = NULL;
  de->full_name = NULL;
  de->content_type = NULL;
  de->manifest_cloud = NULL;
  de->manifest_time = NULL;
  de->manifest_seg = NULL;
  de->size = 0;
  de->isdir = 0;
  de->islink = 0;
  de->next = NULL;
  de->md5sum = NULL;
  de->md5sum_local = NULL;
  de->manifest_seg = NULL;
  de->manifest_time = NULL;
  de->accessed_in_cache = time(NULL);
  de->last_modified = time(NULL);
  de->mtime.tv_sec = time(NULL);
  de->atime.tv_sec = time(NULL);
  de->ctime.tv_sec = time(NULL);
  de->mtime.tv_nsec = 0;
  de->atime.tv_nsec = 0;
  de->ctime.tv_nsec = 0;
  de->chmod = -1;
  de->gid = -1;
  de->uid = -1;
  de->upload_buf.local_cache_file = NULL;
  de->downld_buf.local_cache_file = NULL;
  de->downld_buf.fuse_read_size = -1;
  de->downld_buf.work_buf_size = -1;
  //de->downld_buf.offset = -1;
  de->downld_buf.mutex_initialised = false;
  de->upload_buf.mutex_initialised = false;
  de->downld_buf.sem_list[SEM_EMPTY] = NULL;
  de->downld_buf.sem_list[SEM_FULL] = NULL;
  de->downld_buf.sem_list[SEM_DONE] = NULL;
  de->downld_buf.sem_open = false;
  de->downld_buf.sem_name_list[SEM_EMPTY] = NULL;
  de->downld_buf.sem_name_list[SEM_FULL] = NULL;
  de->downld_buf.sem_name_list[SEM_DONE] = NULL;
  de->downld_buf.signaled_completion = false;
  de->upload_buf.sem_list[SEM_EMPTY] = NULL;
  de->upload_buf.sem_list[SEM_FULL] = NULL;
  de->upload_buf.sem_list[SEM_DONE] = NULL;
  de->upload_buf.sem_open = false;
  de->upload_buf.sem_name_list[SEM_EMPTY] = NULL;
  de->upload_buf.sem_name_list[SEM_FULL] = NULL;
  de->upload_buf.sem_name_list[SEM_DONE] = NULL;
  de->upload_buf.size_processed = 0;
  de->upload_buf.fuse_buf_size = 0;
  de->upload_buf.signaled_completion = false;
  de->upload_buf.feed_from_cache = false;
  de->downld_buf.ahead_thread_count = 0;
  de->full_name_hash = NULL;
  de->is_segmented = false;
  de->segments = NULL;
  de->segment_count = 0;
  de->segment_part = -1;
  de->segment_size = 0;
  de->size_on_cloud = 0;
  de->has_unvisible_segments = false;
  de->lazy_segment_load = false;
  de->lazy_meta = false;
  de->job = NULL;
  de->job2 = NULL;
  de->parent = NULL;
  //de->object_count_recursive = 0;
  de->object_count = 0;
  return de;
}

void free_de_before_get(dir_entry* de)
{
  debugf(DBG_EXTALL, KCYN "free_de_before_get (%s): md5local was=%s",
         de ? de->name : "nil", de->md5sum_local);
  free(de->md5sum_local);
  de->md5sum_local = NULL;//why not set to null
  free_de_before_head(de);
}

void free_de_before_head(dir_entry* de)
{
  //debugf(DBG_EXTALL, KCYN "free_de_before_head (%s)", de ? de->name : "nil");
  //assumes a file might change from segmented to none
  //fixme: commented out as crashes on post_object
  //free(de->manifest_cloud);
  //de->manifest_cloud = NULL;
}

/*
   create and initialise a dir_entry with now values
*/
void create_dir_entry(dir_entry* de, const char* path)//, mode_t mode)
{
  struct timespec now;
  clock_gettime(CLOCK_REALTIME, &now);
  debugf(DBG_EXT, KCYN"create_dir_entry(%s)", path);
  de->atime.tv_sec = now.tv_sec;
  de->atime.tv_nsec = now.tv_nsec;
  de->mtime.tv_sec = now.tv_sec;
  de->mtime.tv_nsec = now.tv_nsec;
  de->ctime.tv_sec = now.tv_sec;
  de->ctime.tv_nsec = now.tv_nsec;
  de->ctime_local.tv_sec = now.tv_sec;
  de->ctime_local.tv_nsec = now.tv_nsec;
  char time_str[TIME_CHARS] = "";
  get_timespec_as_str(&(de->atime), time_str, sizeof(time_str));
  debugf(DBG_EXT, KCYN"create_dir_entry: atime=[%s]", time_str);
  get_timespec_as_str(&(de->mtime), time_str, sizeof(time_str));
  debugf(DBG_EXT, KCYN"create_dir_entry: mtime=[%s]", time_str);
  get_timespec_as_str(&(de->ctime), time_str, sizeof(time_str));
  debugf(DBG_EXT, KCYN"create_dir_entry: ctime=[%s]", time_str);
  //set chmod & chown
  //de->chmod = mode;
  de->uid = geteuid();
  de->gid = getegid();
  de->size = 0;
  de->is_segmented = false;
  //fill in standard file meta (names, hash)
  create_entry_meta(path, de);
}

/*
   duplicate a dir_entry, does not overwrite name fields
*/
void copy_dir_entry(dir_entry* src, dir_entry* dst, bool copy_manifests)
{
  debugf(DBG_EXT, KCYN"copy_dir_entry(%s->%s)",
         src->name ? src->name : "nul", dst->name ? dst->name : "nul");
  if (!dst->name && src->name)
    dst->name = strdup(src->name);
  if (!dst->full_name && src->full_name)
    dst->full_name = strdup(src->full_name);
  if (!dst->full_name_hash && src->full_name_hash)
    dst->full_name_hash = strdup(src->full_name_hash);
  dst->atime.tv_sec = src->atime.tv_sec;
  dst->atime.tv_nsec = src->atime.tv_nsec;
  dst->mtime.tv_sec = src->mtime.tv_sec;
  dst->mtime.tv_nsec = src->mtime.tv_nsec;
  dst->ctime.tv_sec = src->ctime.tv_sec;
  dst->ctime.tv_nsec = src->ctime.tv_nsec;
  dst->last_modified = src->last_modified;
  dst->chmod = src->chmod;
  dst->uid = src->uid;
  dst->gid = src->gid;
  if (src->md5sum)
  {
    if (dst->md5sum)
      free(dst->md5sum);
    dst->md5sum = strdup(src->md5sum);
  }
  if (src->md5sum_local)
  {
    if (dst->md5sum_local)
      free(dst->md5sum_local);
    dst->md5sum_local = strdup(src->md5sum_local);
  }
  dst->has_unvisible_segments = src->has_unvisible_segments;
  dst->lazy_segment_load = src->lazy_segment_load;
  dst->size = src->size;
  dst->size_on_cloud = src->size_on_cloud;
  dst->is_segmented = src->is_segmented;
  dst->segment_count = src->segment_count;
  dst->segment_full_count = src->segment_full_count;
  dst->segment_part = src->segment_part;
  dst->segment_remaining = src->segment_remaining;
  dst->segment_size = src->segment_size;
  dst->isdir = src->isdir;
  dst->islink = src->islink;
  if (!dst->content_type)
    free(dst->content_type);
  if (src->content_type)
    dst->content_type = strdup(src->content_type);
  if (copy_manifests)
  {
    if (!dst->manifest_cloud)
      free(dst->manifest_cloud);
    if (src->manifest_cloud)
      dst->manifest_cloud = strdup(src->manifest_cloud);
    if (!dst->manifest_time)
      free(dst->manifest_time);
    if (src->manifest_time)
      dst->manifest_time = strdup(src->manifest_time);
    if (!dst->manifest_seg)
      free(dst->manifest_seg);
    if (src->manifest_seg)
      dst->manifest_seg = strdup(src->manifest_seg);
  }
  //fixme: segments not copied ok
  if (src->segments)
  {
    assert(!dst->segments);
    dir_entry* src_seg = src->segments;
    dir_entry* dst_seg = init_dir_entry();
    dst->segments = dst_seg;
    while (src_seg)
    {
      copy_dir_entry(src_seg, dst_seg, false);
      src_seg = src_seg->next;
      if (src_seg)
      {
        dst_seg->next = init_dir_entry();
        dst_seg = dst_seg->next;
      }
    }
  }
}

//check for file in cache, if found size will be updated, if not found
//and this is a dir, a new dir cache entry is created
void internal_update_dir_cache(dir_cache* cache, pthread_mutex_t mutex,
                               bool is_cache_upload,
                               const char* path, off_t size, int isdir, int islink)
{
  debugf(DBG_EXTALL, KCYN
         "update_dir_cache(%s) size=%lu isdir=%d islink=%d isupload=%d",
         path, size, isdir, islink, is_cache_upload);
  //pthread_mutex_lock(&mutex);
  lock_mutex(mutex);
  dir_cache* cw;
  dir_entry* de;
  char dir[MAX_PATH_SIZE];
  dir_for(path, dir);
  for (cw = cache; cw; cw = cw->next)
  {
    if (!strcmp(cw->path, dir))
    {
      for (de = cw->entries; de; de = de->next)
      {
        if (!strcmp(de->full_name, path))
        {
          de->size = size;
          //pthread_mutex_unlock(&mutex);
          unlock_mutex(mutex);
          debugf(DBG_EXTALL, "exit 0: update_dir_cache(%s) file found", path);
          return;
        }
      }
      de = init_dir_entry();
      create_dir_entry(de, path);
      de->size = size;
      de->isdir = isdir;
      de->islink = islink;
      //de->name = strdup(&path[strlen(cw->path) + 1]);
      //de->full_name = strdup(path);
      if (islink)
        de->content_type = strdup("application/link");
      if (isdir)
        de->content_type = strdup("application/directory");
      else
        de->content_type = strdup("application/octet-stream");
      de->next = cw->entries;
      cw->entries = de;
      debugf(DBG_EXTALL, "status: update_dir_cache(%s) file added in cache",
             path);
      if (isdir && !is_cache_upload)
        new_cache(path);
      else if (isdir && is_cache_upload)
        new_cache_upload(path);
      else
        debugf(DBG_EXTALL, "update_dir_cache(%s): no dir added in cache",
               path);
      break;
    }
  }
  debugf(DBG_EXTALL, "exit 1: update_dir_cache(%s) file not found", path);
  //pthread_mutex_unlock(&mutex);
  unlock_mutex(mutex);
}

//check for file in cache, if found size will be updated, if not found
//and this is a dir, a new dir cache entry is created
void update_dir_cache(const char* path, off_t size, int isdir,
                      int islink)
{
  internal_update_dir_cache(dcache, dcachemut, false, path, size, isdir, islink);
}

//check for file in upload cache, if found size will be updated, if not found
//and this is a dir, a new dir cache entry is created in the upload cache
void update_dir_cache_upload(const char* path, off_t size, int isdir,
                             int islink)
{
  char dir[MAX_PATH_SIZE];
  dir_for(path, dir);
  dir_entry* tmp;
  //create a folder in cache if does not exist to hold the file
  if (!check_caching_list_dir_upload(dir, &tmp))
    new_cache_upload(dir);
  internal_update_dir_cache(dcache_upload, dcacheuploadmut, true, path, size,
                            isdir, islink);
}

/*
   return cache entry
*/
dir_cache* get_cache_entry(const char* path)
{
  dir_cache* cw;
  for (cw = dcache; cw; cw = cw->next)
  {
    if (!strcmp(cw->path, path))
      break;
  }
  return cw;
}

//returns first file entry in linked list. if not in cache will be downloaded.
int caching_list_directory(const char* path, dir_entry** list)
{
  debugf(DBG_EXT, "caching_list_directory(%s)", path);
  lock_mutex(dcachemut);
  bool new_entry = false;
  if (!strcmp(path, "/"))path = "";
  dir_cache* cw;
  for (cw = dcache; cw; cw = cw->next)
  {
    if (cw->was_deleted == true)
    {
      debugf(DBG_EXTALL, KMAG
             "caching_list_directory status: dir(%s) empty as cached expired, reload",
             cw->path);
      if (!cloudfs_list_directory(cw->path, list))
        debugf(DBG_EXTALL, KMAG
               "caching_list_directory status: cannot reload dir(%s)", cw->path);
      else
      {
        debugf(DBG_EXTALL, KMAG
               "caching_list_directory status: reloaded dir(%s)", cw->path);
        //cw->entries = *list;
        cw->was_deleted = false;
        cw->cached = time(NULL);
      }
    }
    if (cw->was_deleted == false)
    {
      //debugf(DBG_EXTALL, KYEL
      //       "caching_list_directory: compare cache=[%s] and [%s]", cw->path, path);
      if (!strcmp(cw->path, path))
        break;
    }
  }
  if (!cw)
  {
    //trying to download this entry from cloud, list will point to cached or downloaded entries
    if (!cloudfs_list_directory(path, list))
    {
      //download was not ok
      unlock_mutex(dcachemut);
      debugf(DBG_EXTALL,
             "exit 0: caching_list_directory(%s) "KYEL"[CACHE-DIR-MISS]", path);
      return  0;
    }
    debugf(DBG_EXTALL,
           "caching_list_directory: new_cache(%s) "KYEL"[CACHE-CREATE]", path);
    cw = new_cache(path);
    new_entry = true;
  }
  else if (cache_timeout > 0 && (time(NULL) - cw->cached > cache_timeout))
  {
    debugf(DBG_NORM, KYEL
           "caching_list_directory(%s): Cache expired, cleaning!", path);
    if (!cloudfs_list_directory(path, list))
    {
      //mutex unlock was forgotten
      unlock_mutex(dcachemut);
      debugf(DBG_EXTALL, "exit 1: caching_list_directory(%s)", path);
      return  0;
    }
    //fixme: this frees dir subentries but leaves the dir parent entry,
    //this confuses path_info which believes this dir has no entries
    if (cw->entries != NULL)
    {
      cloudfs_free_dir_list(cw->entries);
      cw->was_deleted = true;
      cw->cached = time(NULL);
      debugf(DBG_EXTALL, "caching_list_directory(%s) "KYEL"[CACHE-EXPIRED]",
             path);
    }
    else
    {
      debugf(DBG_EXTALL,
             "got NULL on caching_list_directory(%s) "KYEL"[CACHE-EXPIRED w NULL]", path);
      unlock_mutex(dcachemut);
      return 0;
    }
  }
  else
  {
    debugf(DBG_EXTALL, "caching_list_directory(%s) "KGRN"[CACHE-DIR-HIT]",
           path);
    *list = cw->entries;
  }
  //adding new dir file list to global cache, now this dir becomes visible in cache
  debugf(DBG_EXTALL, KCYN
         "caching_list_directory(%s): added dir starting with %s",
         path, (*list) ? (*list)->full_name : "nil!");
  cw->entries = *list;
  unlock_mutex(dcachemut);
  debugf(DBG_EXTALL, "exit 2: caching_list_directory(%s)", path);
  return 1;
}

dir_entry* path_info(const char* path)
{
  debugf(DBG_EXTALL, "path_info(%s)", path);
  char dir[MAX_PATH_SIZE];
  dir_for(path, dir);
  dir_entry* tmp;
  if (!caching_list_directory(dir, &tmp))
  {
    debugf(DBG_EXTALL, "exit 0: path_info(%s) "KYEL"[CACHE-DIR-MISS]", dir);
    return NULL;
  }
  else
    debugf(DBG_EXTALL, "path_info(%s) "KGRN"[CACHE-DIR-HIT]", dir);
  //iterate in file list obtained from cache or downloaded
  for (; tmp; tmp = tmp->next)
  {
    if (!strcmp(tmp->full_name, path))
    {
      debugf(DBG_EXTALL, "exit 1: path_info(%s) "KGRN"[CACHE-FILE-HIT]", path);
      return tmp;
    }
  }
  //miss in case the file is not found on a cached folder
  debugf(DBG_EXTALL, "exit 2: path_info(%s) "KYEL"[CACHE-MISS]", path);
  return NULL;
}

/*
   appends a dir entry object (file) in cache
   returns false if parent folder is not found
*/
bool append_dir_entry(dir_entry* de)
{
  debugf(DBG_EXT, KMAG "append_dir_entry(%s)", de->full_name);
  bool result;
  dir_entry* tmp;
  char new_dir[MAX_PATH_SIZE];
  dir_for(de->full_name, new_dir);
  if (!caching_list_directory(new_dir, &tmp))
    result = false;
  else
  {
    if (!tmp)
    {
      //append file to this empty directory
      dir_cache* cache = get_cache_entry(new_dir);
      cache->entries = de;
    }
    else
    {
      //append (at the entries end)
      while (tmp->next)
        tmp = tmp->next;
      tmp->next = de;
    }
  }
  result = true;
  debugf(DBG_EXT, KMAG "exit: append_dir_entry(%s) res=%d", de->full_name,
         result);
  return result;
}
//retrieve folder from local cache if exists, return null if does not exist (rather than download)
int internal_check_caching_list_directory(dir_cache* cache,
    pthread_mutex_t mutex, const char* path, dir_entry** list)
{
  debugf(DBG_EXTALL, "check_caching_list_directory(%s)", path);
  //pthread_mutex_lock(&mutex);
  lock_mutex(mutex);
  if (!strcmp(path, "/"))
    path = "";
  dir_cache* cw;
  for (cw = cache; cw; cw = cw->next)
    if (!strcmp(cw->path, path))
    {
      *list = cw->entries;
      //pthread_mutex_unlock(&mutex);
      unlock_mutex(mutex);
      debugf(DBG_EXTALL, "exit 0: check_caching_list_directory(%s) "
             KGRN "[CACHE-DIR-HIT]", path);
      return 1;
    }
  //pthread_mutex_unlock(&mutex);
  unlock_mutex(mutex);
  debugf(DBG_EXTALL, "exit 1: check_caching_list_directory(%s) "
         KYEL "[CACHE-DIR-MISS]", path);
  return 0;
}

/*
   retrieve folder from local cache if exists,
   return null if does not exist (rather than download)
*/
int check_caching_list_directory(const char* path, dir_entry** list)
{
  return internal_check_caching_list_directory(dcache, dcachemut, path, list);
}

/*
   retrieve folder from upload local cache if exists,
   return null if does not exist
*/
int check_caching_list_dir_upload(const char* path, dir_entry** list)
{
  return internal_check_caching_list_directory(dcache_upload, dcacheuploadmut,
         path, list);
}

dir_entry* check_parent_folder_for_file(const char* path)
{
  char dir[MAX_PATH_SIZE];
  dir_for(path, dir);
  dir_entry* tmp;
  if (!check_caching_list_directory(dir, &tmp))
    return NULL;
  else
    return tmp;
}

/*
   replace an object with a new one in cache.
   returns the old object which must be freed in the caller
*/
/*
   dir_entry*  replace_cache_object(const dir_entry* de, dir_entry* de_new)
   {
   debugf(DBG_EXTALL, "replace_cache_object(%s:%s)", de->name,
         de_new->name);
   char dir[MAX_PATH_SIZE];
   dir_for(de->full_name, dir);
   dir_entry* tmp;
   //get parent folder cache entry
   if (!check_caching_list_directory(dir, &tmp))
   {
    debugf(DBG_EXTALL,
           "exit 0: replace_cache_object(%s) " KYEL "[CACHE-MISS]",
           de->full_name);
    return false;
   }
   dir_entry* prev = NULL;
   for (; tmp; tmp = tmp->next)
   {
    if (!strcmp(tmp->full_name, de->full_name))
    {
      debugf(DBG_EXTALL, "exit 1: replace_cache_object(%s) "KGRN"[CACHE-HIT]",
             de->name);
      if (!prev)
        prev = de_new;
      else
        prev->next = de_new;
      de_new->next = tmp->next;
      //cloudfs_free_dir_list(tmp);
      return tmp;
    }
    prev = tmp;
   }
   return NULL;
   }
*/

/*
   check if local path is in cache, without downloading from cloud if not in cache
*/
dir_entry* internal_check_path_info(const char* path, bool check_upload_cache)
{
  debugf(DBG_EXTALL, "check_path_info(%s): upload=%d", path,
         check_upload_cache);
  char dir[MAX_PATH_SIZE];
  dir_for(path, dir);
  dir_entry* tmp;
  //get parent folder cache entry
  if (!check_upload_cache && !check_caching_list_directory(dir, &tmp))
  {
    debugf(DBG_EXTALL, "exit 0: check_path_info(%s) " KYEL "[CACHE-MISS]",
           path);
    return NULL;
  }
  if (check_upload_cache && !check_caching_list_dir_upload(dir, &tmp))
  {
    debugf(DBG_EXTALL, "exit 0: check_path_info(%s) " KYEL
           "[CACHE-MISS-UPLOAD]", path);
    return NULL;
  }
  for (; tmp; tmp = tmp->next)
  {
    if (!strcmp(tmp->full_name, path))
    {
      debugf(DBG_EXTALL, "exit 1: check_path_info(%s) "KGRN"[CACHE-HIT]",
             path);
      return tmp;
    }
  }
  if (!strcmp(path, "/"))
    debugf(DBG_EXTALL,
           "exit 2: check_path_info(%s) "KYEL"ignoring root [CACHE-MISS]", path);
  else
    debugf(DBG_EXTALL, "exit 3: check_path_info(%s) "KYEL"[CACHE-MISS]",
           path);
  return NULL;
}

/*
   check if local path is in cache, without downloading from cloud if not in cache
*/
dir_entry* check_path_info(const char* path)
{
  return internal_check_path_info(path, false);
}

/*
   check if local path is in upload cache,
   without downloading from cloud if not in cache
*/
dir_entry* check_path_info_upload(const char* path)
{
  return internal_check_path_info(path, true);
}

/*
   unlink a segment file from cache
*/
bool delete_segment_cache(dir_entry* de, dir_entry* de_seg)
{
  char segment_file_path[NAME_MAX] = { 0 };
  char segment_file_dir[NAME_MAX] = { 0 };
  get_safe_cache_file_path(de->full_name, segment_file_path,
                           segment_file_dir, temp_dir,
                           de_seg ? de_seg->segment_part : 0);
  bool file_exist = access(segment_file_path, F_OK) != -1;
  int result = 0;
  if (file_exist)
  {
    result = unlink(segment_file_path);
    int err = errno;
    if (result != 0)
    {
      debugf(DBG_EXT, KYEL
             "delete_segment_cache(%s): cannot unlink, err=%s",
             segment_file_path, strerror(err));
    }
  }
  return result == 0;
}
/*
   look for segment in cache
   if exists, returns file handle to file in cache
   if does not exist, create file and return handle

   de_seg can be null if file is not segmented, work with main file
*/
bool open_segment_in_cache(dir_entry* de, dir_entry* de_seg,
                           FILE** fp_segment, const char* method)
{
  assert(*fp_segment == NULL);
  char segment_file_path[NAME_MAX] = { 0 };
  char segment_file_dir[NAME_MAX] = { 0 };
  get_safe_cache_file_path(de->full_name, segment_file_path, segment_file_dir,
                           temp_dir, de_seg ? de_seg->segment_part : 0);
  struct stat dir_status = { 0 };
  if (stat(segment_file_dir, &dir_status) == -1)
    mkdir(segment_file_dir, 0700);
  bool file_exist = access(segment_file_path, F_OK) != -1;
  // todo: check open modes
  *fp_segment = fopen(segment_file_path, method[0] == 'G' ?
                      (file_exist ? "r+" : "w+") : (file_exist ? "r+" : "w+"));
  int err = errno;
  assert(*fp_segment);
  debugf(DBG_EXT, KMAG
         "open_segment_from_cache(%s): open segment fp=%p segindex=%d",
         de_seg ? de_seg->name : de->name, *fp_segment,
         de_seg ? de_seg->segment_part : 0);
  if (file_exist)
  {
    int fno = fileno(*fp_segment);
    assert(fno != -1);
  }
  return file_exist;
}

/*
   look for segment in cache
   if exists, check md5sum, returns file handle to file in cache
   if does not exist, create file and return handle
*/
bool open_segment_cache_md5(dir_entry* de, dir_entry* de_seg,
                            FILE** fp_segment, const char* method)
{
  bool file_exist = open_segment_in_cache(de, de_seg, fp_segment, method);
  if (file_exist)
  {
    debugf(DBG_EXTALL,
           KMAG "open_segment_from_cache: found segment %d md5=%s",
           de_seg->segment_part, de_seg->md5sum);
    //check if segment is in cache, with md5sum ok
    if (de_seg->md5sum_local == NULL)
    {
      char md5_file_hash_str[MD5_DIGEST_HEXA_STRING_LEN] = "\0";
      file_md5(*fp_segment, md5_file_hash_str);
      de_seg->md5sum_local = strdup(md5_file_hash_str);
      assert(de_seg->md5sum_local);
    }
    else
      debugf(DBG_EXTALL, KMAG
             "open_segment_from_cache: segment md5sum_local=%s md5sum=%s",
             de_seg->md5sum_local, de_seg->md5sum);
    //fixme: sometimes md5 local is NULL
    if (!de_seg->md5sum_local)
      debugf(DBG_NORM, KRED
             "open_segment_from_cache: Unexpected md5local NULL");
    bool match = (de_seg && de_seg->md5sum != NULL && de_seg->md5sum_local
                  && (!strcasecmp(de_seg->md5sum_local, de_seg->md5sum)));
    if (!match)
    {
      debugf(DBG_EXT, "open_segment_from_cache: "
             KYEL "no match, md5sum_local=%s md5sum=%s",
             de_seg->md5sum_local, de_seg->md5sum);
      free(de_seg->md5sum_local);
      de_seg->md5sum_local = NULL;
    }
    return match;
  }
  return false;
}

/*
   verify if file is in cache and has correct content
*/
bool check_segment_cache_md5(dir_entry* de, dir_entry* de_seg, FILE* fp)
{
  assert(fp);
  bool result = false;
  char segment_file_path[PATH_MAX] = { 0 };
  get_safe_cache_file_path(de->full_name, segment_file_path, NULL,
                           temp_dir, de_seg->segment_part);
  bool file_exist = access(segment_file_path, F_OK) != -1;
  if (file_exist)
  {
    int fd = fileno(fp);
    assert(fd != -1);
    size_t seg_size = cloudfs_file_size(fd);
    if (seg_size == de_seg->size)
      result = (de && de->md5sum && de_seg->md5sum_local && de_seg->md5sum
                && (!strcasecmp(de_seg->md5sum_local, de_seg->md5sum)));
  }
  return result;
}
/*
   returns if file was found in cache and sets open fp pointer
*/
bool open_file_in_cache(dir_entry* de, FILE** fp, const char* method)
{
  char file_path[NAME_MAX] = { 0 };
  char segment_file_dir[NAME_MAX] = { 0 };
  //use seg_part=0 (not -1) to ensure data is saved in cache segment folder
  get_safe_cache_file_path(de->full_name, file_path, segment_file_dir, temp_dir,
                           0);
  struct stat dir_status = { 0 };
  if (stat(segment_file_dir, &dir_status) == -1)
    mkdir(segment_file_dir, 0700);
  bool file_exist = access(file_path, F_OK) != -1;
  int err = errno;
  if (!file_exist)
    debugf(DBG_EXTALL, KMAG "open_file_in_cache(%s) cannot access, err=%s",
           file_path, strerror(err));
  *fp = fopen(file_path, method[0] == 'G' ?
              (file_exist ? "r+" : "w+") : (file_exist ? "r+" : "w+"));
  err = errno;
  if (!*fp)
  {
    debugf(DBG_EXTALL, KRED "open_file_in_cache(%s): cannot open, err=%s",
           file_path, strerror(err));
    abort();
  }
  if (file_exist)
  {
    debugf(DBG_EXTALL, KMAG "open_file_in_cache(%s) ok", file_path);
    int fno = fileno(*fp);
    assert(fno != -1);
  }
  return file_exist;
}

/*
   look for file in cache
   if exists, check md5sum, returns file handle to file in cache
   if does not exist, create file and return handle
*/
bool open_file_cache_md5(dir_entry* de, FILE** fp, const char* method)
{
  debugf(DBG_EXTALL, KMAG "open_file_cache_md5(%s): open fp=%p", de->name, *fp);
  bool file_exist = open_file_in_cache(de, fp, method);
  if (file_exist)
  {
    debugf(DBG_EXTALL, KMAG "open_file_cache_md5: found file, md5=%s",
           de->md5sum);
    //check if segment is in cache, with md5sum ok
    //fixme: sometimes md5sum_local = "" (not null)!
    if (de->md5sum_local == NULL)
    {
      char md5_file_hash_str[MD5_DIGEST_HEXA_STRING_LEN] = "\0";
      file_md5(*fp, md5_file_hash_str);
      de->md5sum_local = strdup(md5_file_hash_str);
    }
    else
      debugf(DBG_EXTALL, KMAG
             "open_file_cache_md5: md5sum_local=%s, md5sum=%s",
             de->md5sum_local, de->md5sum);
    bool match = (de && de->md5sum != NULL
                  && (!strcasecmp(de->md5sum_local, de->md5sum)));
    if (!match)
    {
      debugf(DBG_EXT, "open_file_cache_md5: " KYEL
             "no match, md5sum_local=%s, md5sum=%s", de->md5sum_local, de->md5sum);
      free(de->md5sum_local);
      de->md5sum_local = NULL;
    }
    return match;
  }
  else
  {
    assert(*fp);
    debugf(DBG_EXTALL, KMAG
           "open_file_cache_md5(%s): file was not in cache, created fp=%p",
           de->name, *fp);
  }
  return false;
}

bool cleanup_older_segments(thread_clean_segment_job*
                            job)//char* dir_path, char* exclude_path)
{
  char* dir_path = job->dir_path;
  char* exclude_path = job->exclude_path;

  debugf(DBG_EXT, "cleanup_older_segments(%s - %s)", dir_path,
         exclude_path);
  assert(dir_path);
  bool result = false;
  //delete also parent path if no exception is specified
  //(if exception is set it might be a child object so don't remove parent
  if (!exclude_path)
  {
    dir_entry* tmp = init_dir_entry();
    tmp->full_name = strdup(dir_path);
    tmp->name = "";
    tmp->isdir = 1;
    cloudfs_delete_object(tmp);
    free(tmp);
    result = true;
  }
  else
  {
    dir_entry* de_versions, *de_tmp;
    if (cloudfs_list_directory(dir_path, &de_versions))
    {
      while (de_versions)
      {
        if (!exclude_path || !strstr(de_versions->full_name, exclude_path))
        {
          dir_entry* tmp = init_dir_entry();
          tmp->full_name = strdup(de_versions->full_name);
          tmp->name = "";
          tmp->isdir = 1;
          cloudfs_delete_object(tmp);
          free(tmp);
          result = true;
        }
        else
        {
          debugf(DBG_EXT, KMAG "not deleting excluded path %s",
                 de_versions->full_name);
        }
        de_versions = de_versions->next;
      }
    }
  }

  free(job->dir_path);
  free(job->exclude_path);
  return result;
}

void cleanup_older_segments_th(char* dir_path, char* exclude_path)
{
  pthread_t thread;
  thread_clean_segment_job* job = malloc(sizeof(struct
                                         thread_clean_segment_job));
  job->dir_path = strdup(dir_path);
  job->exclude_path = strdup(exclude_path);
  pthread_create(&thread, NULL, (void*)cleanup_older_segments, job);
}
/*
   O_CREAT = 32768
   O_RDONLY = 32768
   O_WRONLY = 32769
   O_RDWR = 32770
   O_APPEND = 33792
*/
void flags_to_openmode(unsigned int flags, char* openmode)
{
  int i = 0;
  if (flags & O_WRONLY)
  {
    debugf(DBG_EXT, "flags_to_openmode: write only detected");
    openmode[i] = 'w';
    i++;
  }
  if (flags & O_APPEND)
  {
    debugf(DBG_EXT, "flags_to_openmode: append detected");
    openmode[i] = 'a';
    i++;
  }
  if (flags & O_RDONLY)
  {
    debugf(DBG_EXT, "flags_to_openmode: read only detected");
    openmode[i] = 'r';
    i++;
  }
  if (flags & O_RDWR)
  {
    debugf(DBG_EXT, "flags_to_openmode: read write detected");
    openmode[i] = 'w';
    i++;
    openmode[i] = 'r';
    i++;
  }
  if (flags & O_TRUNC)
  {
    debugf(DBG_EXT, "flags_to_openmode: truncate detected");
    openmode[i] = 'w';
    i++;
  }
  if (flags & O_CREAT)
  {
    debugf(DBG_EXT, "flags_to_openmode: create detected");
    openmode[i] = 'w';
    i++;
  }
  if (flags & O_EXCL)
  {
    debugf(DBG_EXT, "flags_to_openmode: EXCL detected");
    openmode[i] = '!';
    i++;
  }
  //default open mode is r
  if (i == 0)
  {
    debugf(DBG_EXT, "flags_to_openmode: unknown mode, assume SOFT read");
    openmode[i] = 'r';
    i++;
  }
  openmode[i] = 0;//null terminate string
}


void add_lock_file(const char* path, const char* open_flags,
                   FILE* temp_file, int fd, char* fuse_op)
{
  debugf(DBG_EXT, "add_lock_file(%s): mode=%s fd=%d",
         path, open_flags, fd);
  lock_mutex(dlockmut);
  open_file* of = (open_file*)malloc(sizeof(open_file));
  of->cached_file = temp_file;
  of->fd = fd;
  of->path = strdup(path);
  of->open_flags = strdup(open_flags);
  of->opened = get_time_now();
  of->fuse_operation = strdup(fuse_op);
  //todo: search for process that opened the file in /proc/pid/fd
  //of->process_origin = ? ;
  if (openfile_list)
    of->next = openfile_list;
  else
    of->next = NULL;
  openfile_list = of;
  unlock_mutex(dlockmut);
}

int get_open_locks()
{
  open_file* of = openfile_list;
  int count = 0;
  while (of)
  {
    count++;
    of = of->next;
  }
  return count;
}

bool close_lock_file(const char* path, int fd)
{
  lock_mutex(dlockmut);
  open_file* of = openfile_list;
  open_file* prev = NULL;
  int count = 0;
  bool result = false;
  while (of)
  {
    if (!strcasecmp(of->path, path))
    {
      count++;
      if (of->fd == fd)
      {
        of->fd = -1;
        fclose(of->cached_file);
        of->cached_file = NULL;
        free(of->path);
        of->path = NULL;
        free(of->open_flags);
        of->open_flags = NULL;
        free(of->fuse_operation);
        of->fuse_operation = NULL;
        free(of);
        if (prev)
          prev->next = of->next;
        else
          openfile_list = of->next;
        result = true;
      }
    }
    prev = of;
    of = of->next;
  }
  //last open instance was removed, file in cache to be deleted
  if (count == 1 && result)
  {
    char file_path_safe[NAME_MAX] = "";
    get_safe_cache_file_path(path, file_path_safe, NULL, temp_dir, -1);
    debugf(DBG_EXT, "close_lock_file(%s): deleting %s", path, file_path_safe);
    unlink(file_path_safe);
  }
  debugf(DBG_EXT, "close_lock_file(%s): %d instances were open", path, count);
  unlock_mutex(dlockmut);
  return result;
}

/*
   verifies if lock can be obtained
   if file is open for read, a read lock can be obtained
   if file is open for write, no lock can be obtained
*/
bool can_add_lock(const char* path, char* open_flags, char* fuse_op)
{
  open_file* of = openfile_list;
  while (of)
  {
    debugf(DBG_EXT, KCYN "can_add_lock(%s, %s, flags=%s): iterate [%s, %s, %s]",
           path, fuse_op, open_flags, of->open_flags, of->path, of->fuse_operation);
    if (!strcasecmp(of->path, path))
    {
      //if try to open for write and hard lock exists, fail
      if ((strstr(open_flags, "w") || strstr(open_flags, "a"))
          && (strstr(of->open_flags, "r!") || strstr(of->open_flags, "w")
              || strstr(of->open_flags, "a")))
        return false;
      //if try to open for read and write lock exist, fail
      if (strstr(open_flags, "r")
          && (strstr(of->open_flags, "w") || strstr(of->open_flags, "a")))
        return false;
    }
    of = of->next;
  }
  debugf(DBG_EXT, KCYN "can_add_lock(%s, %s, flags=%s): can add OK",
         path, fuse_op, open_flags);
  return true;
}


/*
   creates or opens a lock file in temp folder with flags mode
   and returns file descriptor.
   return -1 if lock can't be obtained
*/
int open_lock_file(const char* path, unsigned int flags, char* fuse_op)
{
  debugf(DBG_EXT, "open_lock_file(%s): flags=%d", path, flags);
  FILE* temp_file = NULL;
  char open_flags[10];
  char file_path_safe[NAME_MAX];
  get_safe_cache_file_path(path, file_path_safe, NULL, temp_dir, -1);
  flags_to_openmode(flags, open_flags);
  int i;
  bool can_add;
  //wait until lock is removed, can happen on async POST (meta update) operations
  for (i = 0; i < LOCK_WAIT_SEC * (1000 / 250); i++)
  {
    lock_mutex(dlockmut);
    can_add = can_add_lock(path, open_flags, fuse_op);
    if (can_add)
      break;
    else
    {
      unlock_mutex(dlockmut);
      sleep_ms(250);//see for / if change value
    }
  }

  int fd;
  if (!can_add)
  {
    debugf(DBG_EXT, KRED
           "open_lock_file(%s): lock not secured, mode=%s", path, open_flags);
    fd = -1;
  }
  else
  {
    bool file_exist = access(file_path_safe, F_OK) != -1;
    if (!file_exist)
    {
      //create the file in cache
      fclose(fopen(file_path_safe, "w"));
    }
    //this fails if open mode is r, so need to create file first
    temp_file = fopen(file_path_safe, open_flags);
    int errsv = errno;
    if (!temp_file)
    {
      debugf(DBG_EXT, KRED
             "open_lock_file(%s): lock file busy, mode=%s err=%s",
             path, open_flags, strerror(errsv));
      fd = -1;
    }
    else
    {
      fd = fileno(temp_file);
      assert(fd != -1);
      add_lock_file(path, open_flags, temp_file, fd, fuse_op);
    }
    unlock_mutex(dlockmut);
  }
  return fd;
}

bool update_lock_file(const char* path, int fd, const char* search_flag,
                      const char* new_flag)
{
  lock_mutex(dlockmut);
  open_file* of = openfile_list;
  bool result = false;
  while (of)
  {
    if (!strcasecmp(of->path, path) && of->fd == fd)
    {
      if (strstr(of->open_flags, search_flag))
      {
        free(of->open_flags);
        of->open_flags = strdup(new_flag);
        result = true;
        break;
      }
    }
    of = of->next;
  }
  unlock_mutex(dlockmut);
  return result;
}
/*
   delete all segment cached files from disk
*/
void unlink_cache_segments(dir_entry* de)
{
  debugf(DBG_EXT, "unlink_cache_segments(%s)", de->full_name);
  char segment_file_path[PATH_MAX] = { 0 };
  char segment_parent_dir_path[PATH_MAX] = { 0 };
  dir_entry* de_seg = de->segments;
  do
  {
    //ensure we remove first segment
    get_safe_cache_file_path(de->full_name, segment_file_path,
                             segment_parent_dir_path,
                             temp_dir, de_seg ? de_seg->segment_part : 0);
    if (unlink(segment_file_path) != 0)
      debugf(DBG_ERR, "unlink_cache_segments(%s): error del file [%s]",
             segment_file_path, strerror(errno));
    else
      debugf(DBG_EXT, "unlink_cache_segments(%s): removed file ok",
             segment_file_path);
    if (!de_seg)
      break;
    else
      de_seg = de_seg->next;
  }
  while (de_seg);
  if (rmdir(segment_parent_dir_path) != 0)
    debugf(DBG_ERR, "unlink_cache_segments(%s): error rm dir [%s]",
           segment_parent_dir_path, strerror(errno));
  else
    debugf(DBG_EXT, "unlink_cache_segments(%s): removed dir ok",
           segment_parent_dir_path);
}

void sleep_ms(int milliseconds)
{
#ifdef _POSIX_C_SOURCE
  struct timespec ts;
  ts.tv_sec = milliseconds / 1000;
  ts.tv_nsec = (milliseconds % 1000) * 1000000;
  nanosleep(&ts, NULL);
#else
  usleep(milliseconds * 1000);
#endif
}

char* get_home_dir()
{
  char* home;
  if ((home = getenv("HOME")) && !access(home, R_OK))
    return home;
  struct passwd* pwd = getpwuid(geteuid());
  if ((home = pwd->pw_dir) && !access(home, R_OK))
    return home;
  return "~";
}


int file_is_readable(const char* fname)
{
  FILE* file;
  if (file = fopen(fname, "r"))
  {
    fclose(file);
    return 1;
  }
  return 0;
}

off_t get_file_size(FILE* fp)
{
  assert(fp);
  struct stat st;
  int fd = fileno(fp);
  assert(fd != -1);
  assert(fstat(fd, &st) == 0);
  return st.st_size;
}

void close_file(FILE** file)
{
  debugf(DBG_EXT, KCYN "close_file: file=%p", *file);
  assert(*file);
  fclose(*file);
  *file = NULL;
}

//allows memory leaks inspections
void interrupt_handler(int sig)
{
  debugf(DBG_NORM, "Got interrupt signal %d, cleaning memory", sig);
  //TODO: clean memory allocations
  //http://www.cprogramming.com/debugging/valgrind.html
  cloudfs_free();
  //TODO: clear dir cache
  dir_decache("");
  pthread_mutex_destroy(&dcachemut);
  exit(0);
}

/* Catch Signal Handler function */
void sigpipe_callback_handler(int signum)
{
  debugf(DBG_NORM, KRED "Caught signal SIGPIPE, ignoring %d", signum);
}

void clear_full_cache()
{
  dir_decache("*");
}

void print_options()
{
  fprintf(stderr, "temp_dir= %s\n", temp_dir);
  fprintf(stderr, "verify_ssl = %d\n", verify_ssl);
  fprintf(stderr, "curl_progress_state = %d\n", option_curl_progress_state);
  fprintf(stderr, "segment_size = %lu\n", segment_size);
  fprintf(stderr, "segment_above = %lu\n", segment_above);
  fprintf(stderr, "debug_level = %d\n", option_debug_level);
  fprintf(stderr, "get_extended_metadata = %d\n", option_get_extended_metadata);
  fprintf(stderr, "curl_progress_state = %d\n", option_curl_progress_state);
  fprintf(stderr, "enable_chmod = %d\n", option_enable_chmod);
  fprintf(stderr, "enable_chown = %d\n", option_enable_chown);
  fprintf(stderr, "enable_progressive_download = %d\n",
          option_enable_progressive_download);
  fprintf(stderr, "enable_progressive_upload = %d\n",
          option_enable_progressive_upload);
  fprintf(stderr, "min_speed_limit_progressive = %li\n",
          option_min_speed_limit_progressive);
  fprintf(stderr, "min_speed_timeout = %li\n", option_min_speed_timeout);
  fprintf(stderr, "read_ahead = %li\n", option_read_ahead);
  fprintf(stderr, "enable_syslog = %d\n", option_enable_syslog);
  fprintf(stderr, "enable_chaos_test_monkey = %d\n",
          option_enable_chaos_test_monkey);
  fprintf(stderr, "disable_atime_check = %d\n", option_disable_atime_check);
  fprintf(stderr, "http_log_path = %s\n", option_http_log_path);
  fprintf(stderr, "fast_list_dir_limit = %d\n", option_fast_list_dir_limit);
  fprintf(stderr, "async_delete = %d\n", option_async_delete);
}

bool initialise_options(struct fuse_args args)
{
  char settings_filename[MAX_PATH_SIZE] = "";
  FILE* settings;
  snprintf(settings_filename, sizeof(settings_filename), "%s/.hubicfuse",
           get_home_dir());
  if ((settings = fopen(settings_filename, "r")))
  {
    char line[OPTION_SIZE];
    while (fgets(line, sizeof(line), settings))
      parse_option(NULL, line, -1, &args);
    fclose(settings);
  }
  cache_timeout = atoi(options.cache_timeout);
  segment_size = atoll(options.segment_size);
  segment_above = atoll(options.segment_above);
  // this is ok since main is on the stack during the entire execution
  override_storage_url = options.storage_url;
  public_container = options.container;
  temp_dir = options.temp_dir;
  DIR* dir = opendir(temp_dir);
  if (!dir)
  {
    fprintf(stderr, "Unable to access temp folder [%s], aborting", temp_dir);
    abort();
  }
  if (*options.verify_ssl)
    verify_ssl = !strcasecmp(options.verify_ssl, "true") ? 2 : 0;
  if (*extra_options.get_extended_metadata)
    option_get_extended_metadata = !strcasecmp(extra_options.get_extended_metadata,
                                   "true");
  if (*extra_options.curl_verbose)
    option_curl_verbose = !strcasecmp(extra_options.curl_verbose,
                                      "true");
  if (*extra_options.debug_level)
    option_debug_level = atoi(extra_options.debug_level);
  if (*extra_options.cache_statfs_timeout)
    option_cache_statfs_timeout = atoi(extra_options.cache_statfs_timeout);
  if (*extra_options.curl_progress_state)
    option_curl_progress_state = !strcasecmp(extra_options.curl_progress_state,
                                 "true");
  if (*extra_options.enable_chmod)
    option_enable_chmod = !strcasecmp(extra_options.enable_chmod, "true");
  if (*extra_options.enable_chown)
    option_enable_chown = !strcasecmp(extra_options.enable_chown, "true");
  if (*extra_options.enable_progressive_download)
    option_enable_progressive_download = !strcasecmp(
                                           extra_options.enable_progressive_download, "true");
  if (*extra_options.enable_progressive_upload)
    option_enable_progressive_upload = !strcasecmp(
                                         extra_options.enable_progressive_upload, "true");
  if (*extra_options.min_speed_limit_progressive)
    option_min_speed_limit_progressive = atoll(
                                           extra_options.min_speed_limit_progressive);
  if (*extra_options.read_ahead)
    option_read_ahead = atoll(extra_options.read_ahead);
  if (*extra_options.min_speed_timeout)
    option_min_speed_timeout = atoll(extra_options.min_speed_timeout);
  if (*extra_options.enable_syslog)
    option_enable_syslog = !strcasecmp(
                             extra_options.enable_syslog, "true");
  if (*extra_options.enable_chaos_test_monkey)
    option_enable_chaos_test_monkey = !strcasecmp(
                                        extra_options.enable_chaos_test_monkey, "true");
  if (*extra_options.disable_atime_check)
    option_disable_atime_check = !strcasecmp(extra_options.disable_atime_check,
                                 "true");
  option_http_log_path = extra_options.http_log_path;
  option_fast_list_dir_limit = atoi(extra_options.fast_list_dir_limit);
  option_async_delete = !strcasecmp(extra_options.async_delete, "true");

  if (!*options.client_id || !*options.client_secret || !*options.refresh_token)
  {
    fprintf(stderr,
            "Unable to determine client_id, client_secret or refresh_token.\n\n");
    fprintf(stderr, "These can be set either as mount options or in "
            "a file named %s\n\n", settings_filename);
    fprintf(stderr, "  client_id=[App's id]\n");
    fprintf(stderr, "  client_secret=[App's secret]\n");
    fprintf(stderr, "  refresh_token=[Get it running hubic_token]\n");
    fprintf(stderr, "The following settings are optional:\n\n");
    fprintf(stderr,
            "  cache_timeout=[Seconds for directory caching, default 600]\n");
    fprintf(stderr, "  verify_ssl=[false to disable SSL cert verification]\n");
    fprintf(stderr,
            "  segment_size=[Size to use when creating DLOs, default 1073741824]\n");
    fprintf(stderr,
            "  segment_above=[File size at which to use segments, defult 2147483648]\n");
    fprintf(stderr,
            "  storage_url=[Storage URL for other tenant to view container]\n");
    fprintf(stderr,
            "  container=[Public container to view of tenant specified by storage_url]\n");
    fprintf(stderr, "  temp_dir=[Directory to store temp files]\n");
    fprintf(stderr,
            "  get_extended_metadata=[true to enable download of utime, chmod, chown file attributes (but slower)]\n");
    fprintf(stderr,
            "  curl_verbose=[true to debug info on curl requests (lots of output)]\n");
    fprintf(stderr,
            "  curl_progress_state=[true to enable progress callback enabled. Mostly used for debugging]\n");
    fprintf(stderr,
            "  cache_statfs_timeout=[number of seconds to cache requests to statfs (cloud statistics), 0 for no cache]\n");
    fprintf(stderr,
            "  debug_level=[0 to 2, 0 for minimal verbose debugging. No debug if -d or -f option is not provided.]\n");
    fprintf(stderr, "  enable_chmod=[true to enable chmod support on fuse]\n");
    fprintf(stderr, "  enable_chown=[true to enable chown support on fuse]\n");
    fprintf(stderr,
            "  enable_progressive_download=[true to enable progressive operation support]\n");
    fprintf(stderr,
            "  enable_progressive_upload=[true to enable progressive operation support]\n");
    fprintf(stderr,
            "  min_speed_limit_progressive=[0 to disable, or = number of transferred bytes per second limit under which operation will be aborted and resumed]\n");
    fprintf(stderr,
            "  min_speed_timeout=[number of seconds after which slow operation will be aborted and resumed]\n");
    fprintf(stderr,
            "  read_ahead=[Bytes to read ahead on progressive download, 0 for none, -1 for full file read]\n");
    fprintf(stderr,
            "  enable_syslog=[Write error output to syslog]\n");
    fprintf(stderr,
            "  enable_chaos_test_monkey=[Enable creation of random errors to test program stability]\n");
    fprintf(stderr,
            "  disable_atime_check=[Disable atime file check even if is enabled at mount]\n");
    fprintf(stderr,
            "  http_log_path=[file path to log all http request for debug]\n");
    fprintf(stderr,
            "  fast_list_dir_limit=[0 to disable, max number of files in a folder to load meta for]\n");
    fprintf(stderr,
            "  async_delete=[delete operations will run async, very fast]\n");
    return false;
  }
  return true;
}

int parse_option(void* data, const char* arg, int key,
                 struct fuse_args* outargs)
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
      sscanf(arg, " get_extended_metadata = %[^\r\n ]",
             extra_options.get_extended_metadata) ||
      sscanf(arg, " curl_verbose = %[^\r\n ]", extra_options.curl_verbose) ||
      sscanf(arg, " cache_statfs_timeout = %[^\r\n ]",
             extra_options.cache_statfs_timeout) ||
      sscanf(arg, " debug_level = %[^\r\n ]", extra_options.debug_level) ||
      sscanf(arg, " curl_progress_state = %[^\r\n ]",
             extra_options.curl_progress_state) ||
      sscanf(arg, " enable_chmod = %[^\r\n ]", extra_options.enable_chmod) ||
      sscanf(arg, " enable_chown = %[^\r\n ]", extra_options.enable_chown) ||
      sscanf(arg, " enable_progressive_download = %[^\r\n ]",
             extra_options.enable_progressive_download) ||
      sscanf(arg, " enable_progressive_upload = %[^\r\n ]",
             extra_options.enable_progressive_upload) ||
      sscanf(arg, " min_speed_limit_progressive = %[^\r\n ]",
             extra_options.min_speed_limit_progressive) ||
      sscanf(arg, " min_speed_timeout = %[^\r\n ]",
             extra_options.min_speed_timeout) ||
      sscanf(arg, " read_ahead = %[^\r\n ]", extra_options.read_ahead) ||
      sscanf(arg, " enable_syslog = %[^\r\n ]", extra_options.enable_syslog) ||
      sscanf(arg, " enable_chaos_test_monkey = %[^\r\n ]",
             extra_options.enable_chaos_test_monkey) ||
      sscanf(arg, " disable_atime_check = %[^\r\n ]",
             extra_options.disable_atime_check) ||
      sscanf(arg, " http_log_path = %[^\r\n ]", extra_options.http_log_path) ||
      sscanf(arg, " fast_list_dir_limit = %[^\r\n ]",
             extra_options.fast_list_dir_limit) ||
      sscanf(arg, " async_delete = %[^\r\n ]", extra_options.async_delete)
     )
    return 0;
  if (!strcmp(arg, "-f") || !strcmp(arg, "-d") || !strcmp(arg, "debug"))
    debug = 1;
  return 1;
}


void debug_http(const char* method, const char* url)
{
#ifdef SYS_gettid
  pid_t thread_id = syscall(SYS_gettid);
#else
  int thread_id = 0;
#error "SYS_gettid unavailable on this system"
#endif
  if (option_http_log_path && strlen(option_http_log_path) > 0)
  {
    FILE* log = fopen(option_http_log_path, "a");
    if (log)
    {
      char time_str[TIME_CHARS];
      get_time_now_milisec_as_str(time_str, sizeof(time_str));
      fprintf(log, "[%s] %d-%d %s %s %s\n", time_str, g_thread_id, thread_id,
              g_current_op, method, url);
      fclose(log);
    }
  }
}

void set_global_thread_debug(char* operation, const char* path, bool log)
{
  g_current_op = operation;
#ifdef SYS_gettid
  pid_t thread_id = syscall(SYS_gettid);
#else
  int thread_id = 0;
#error "SYS_gettid unavailable on this system"
#endif
  g_thread_id = thread_id;
  if (log)
    debug_http("FUSE", path);
}

void debugf(int level, char* fmt, ...)
{
  if (debug)
  {
    if (level <= option_debug_level || level == DBG_TEST)
    {
#ifdef SYS_gettid
      pid_t thread_id = syscall(SYS_gettid);
#else
      int thread_id = 0;
#error "SYS_gettid unavailable on this system"
#endif
      va_list args;
      //char prefix[] = "==DBG%d [%s]:%d==";
      char* prefix;
      if (level != DBG_TEST)
        prefix = "==DBG%d [%s]:%d==";
      else
        prefix = "==DBG%d [%s]:%d=="KBRED KWHT"Chaos Testing: ";
      char startstr[4096];
      char endstr[4096];
      char time_str[TIME_CHARS];
      get_time_now_milisec_as_str(time_str, sizeof(time_str));
      sprintf(startstr, prefix, level, time_str, thread_id);
      fputs(startstr, stderr);
      va_start(args, fmt);
      //vfprintf(stderr, fmt, args);
      vsprintf(endstr, fmt, args);
      va_end(args);
      fputs(endstr, stderr);
      fputs(KNRM, stderr);
      putc('\n', stderr);
      putc('\r', stderr);
      if (level == DBG_ERR && option_enable_syslog)
      {
        char msgstr[4096];
        snprintf(msgstr, 4096, "%s%s", startstr, endstr);
        openlog(APP_ID, LOG_PID, LOG_USER);
        syslog(LOG_INFO, msgstr);
        closelog();
      }
    }
  }
}
