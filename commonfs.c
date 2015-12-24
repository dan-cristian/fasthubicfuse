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
#include "commonfs.h"
#include "config.h"

pthread_mutex_t dcachemut;
pthread_mutexattr_t mutex_attr;
pthread_mutexattr_t segment_mutex_attr;
dir_cache* dcache;
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
long option_min_speed_limit_progressive = 0;//use long not double
long option_min_speed_timeout;
long option_read_ahead = 0;
size_t file_buffer_size = 0;

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

time_t get_time_as_local(time_t time_t_val, char time_str[], int char_buf_size)
{
  struct tm loc_time_tm;
  loc_time_tm = *localtime(&time_t_val);
  if (time_str != NULL)
  {
    //debugf(DBG_LEVEL_NORM, 0,"Local len=%d size=%d pass=%d", strlen(time_str), sizeof(time_str), char_buf_size);
    strftime(time_str, char_buf_size, "%c", &loc_time_tm);
    //debugf(DBG_LEVEL_NORM, 0,"Local timestr=[%s] size=%d", time_str, strlen(time_str));
  }
  //debugf(DBG_LEVEL_NORM, 0,"Local time_t %li", mktime(&loc_time_tm));
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
    debugf(DBG_LEVEL_NORM,
           KRED"get_time_as_string: input time length too long, %lu > max=%lu, trimming!",
           time_t_val, INT_MAX);
    safe_input_time = 0;//(int)time_t_val;
  }
  else
    safe_input_time = time_t_val;
  time_val_tm = *gmtime(&safe_input_time);
  int str_len = strftime(time_str, time_str_len, HUBIC_DATE_FORMAT,
                         &time_val_tm);
  char nsec_str[TIME_CHARS];
  sprintf(nsec_str, "%d", nsec);
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

int get_timespec_as_str(const struct timespec* times, char* time_str,
                        int time_str_len)
{
  return get_time_as_string(times->tv_sec, times->tv_nsec, time_str,
                            time_str_len);
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
  debugf(DBG_LEVEL_EXT, "file_md5: start compute sum fp=%p", file_handle);
  if (file_handle == NULL)
  {
    debugf(DBG_LEVEL_NORM, KRED"file_md5: NULL file handle");
    return 0;
  }

  unsigned char c[MD5_DIGEST_LENGTH];
  int i;
  MD5_CTX mdContext;
  int bytes;
  char mdchar[3];//2 chars for md5 + null string terminator
  unsigned char* data_buf = malloc(1024 * sizeof(unsigned char));
  MD5_Init(&mdContext);
  assert(fseek(file_handle, 0, SEEK_SET) == 0);
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
  debugf(DBG_LEVEL_EXT, "file_md5: end compute sum=%s fp=%p",
         md5_file_str, file_handle);
  return 0;
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

/*compose a unique cache file path within max name bounds
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
  if (accmode == O_RDONLY)            debugf(DBG_LEVEL_EXTALL, KYEL"read only");
  else if (accmode == O_WRONLY)   debugf(DBG_LEVEL_EXTALL, KYEL"write only");
  else if (accmode == O_RDWR)     debugf(DBG_LEVEL_EXTALL, KYEL"read write");
  else debugf(DBG_LEVEL_EXT, KYEL"unknown access mode");
  if (val & O_APPEND)         debugf(DBG_LEVEL_EXTALL, KYEL", append");
  if (val & O_NONBLOCK)       debugf(DBG_LEVEL_EXTALL, KYEL", nonblocking");
#if !defined(_POSIX_SOURCE) && defined(O_SYNC)
  if (val & O_SYNC)           debugf(DBG_LEVEL_EXT, 0,
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
      debugf(DBG_LEVEL_EXT, KRED"debug_print_file_name: "KYEL"failed to readlink");
    else
    {
      filename[r] = '\0';
      debugf(DBG_LEVEL_EXT, KMAG"fp -> fno -> filename: %p -> %d -> %s\n",
             fp, fno, filename);
    }
  }

}
void debug_print_descriptor(struct fuse_file_info* info)
{
  return;
  char file_path[MAX_PATH_SIZE];
  get_file_path_from_fd(info->fh, file_path, sizeof(file_path));
  debugf(DBG_LEVEL_EXTALL, KCYN "descriptor localfile=[%s] fd=%d", file_path,
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
    debugf(DBG_LEVEL_EXT, "LIST-CACHE: DIR[%s]", cw->path);
    for (de = cw->entries; de; de = de->next)
      debugf(DBG_LEVEL_EXT, "LIST-CACHE:   FOLDER[%s]", de->full_name);
  }
}

int delete_file(char* path)
{
  debugf(DBG_LEVEL_NORM, KYEL"delete_file(%s)", path);
  char file_path_safe[NAME_MAX] = "";
  get_safe_cache_file_path(path, file_path_safe, NULL, temp_dir, -1);
  int result = unlink(file_path_safe);
  debugf(DBG_LEVEL_EXT, KYEL"delete_file(%s) (%s) result=%s", path,
         file_path_safe, strerror(result));
  return result;
}

//adding a directory in cache
dir_cache* new_cache(const char* path)
{
  debugf(DBG_LEVEL_NORM, KCYN"new_cache(%s)", path);
  dir_cache* cw = (dir_cache*)calloc(sizeof(dir_cache), 1);
  cw->path = strdup(path);
  cw->prev = NULL;
  cw->entries = NULL;
  cw->cached = time(NULL);
  //added cache by access
  cw->accessed_in_cache = time(NULL);
  cw->was_deleted = false;
  if (dcache)
    dcache->prev = cw;
  cw->next = dcache;
  dir_cache* result;
  result = (dcache = cw);
  debugf(DBG_LEVEL_EXT, "exit: new_cache(%s)", path);
  return result;
}


//todo: check if the program behaves ok  when free_dir
//is made on a folder that has an operation in progress
void cloudfs_free_dir_list(dir_entry* dir_list)
{
  //check for NULL as dir might be already removed from cache by other thread
  debugf(DBG_LEVEL_NORM, "cloudfs_free_dir_list(%s)", dir_list->full_name);
  while (dir_list)
  {
    dir_entry* de = dir_list;
    dir_list = dir_list->next;
    //remove file from disk cache, fix for issue #89, https://github.com/TurboGit/hubicfuse/issues/89
    delete_file(de->full_name);
    free(de->name);
    free(de->full_name);
    free(de->content_type);
    //TODO free all added fields
    free(de->md5sum);
    free(de->md5sum_local);
    free(de->full_name_hash);
    //no need to free de->upload_buf.readptr as it is only a pointer to a buffer allocated / managed by fuse
    free(de);
  }
}

/*
  return a segment entry from dir_entry
  NOTE!: it also sets the segment_part field
*/
dir_entry* get_segment(dir_entry* de, int segment_index)
{
  int de_segment;
  dir_entry* des = de->segments;
  while (des)
  {
    de_segment = atoi(des->name);
    if (de_segment == segment_index)
    {
      if (des->segment_part != segment_index)
        des->segment_part = segment_index;
      return des;
    }
    des = des->next;
  }
  return des;//this will be NULL
}

/*
  returns the segment.
  if does not exist then a new empty segment is created, used when writing new files.
  NOTE!: sets de->manifest field
*/
dir_entry* get_create_segment(dir_entry* de, int segment_index)
{
  int de_segment;
  dir_entry* de_seg;

  if (!de->segments)
  {
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
        return de_seg;
      }
      if (!de_seg->next)
      {
        de_seg->next = init_dir_entry();
        de_seg = de_seg->next;
        break;
      }
      else
        de_seg = de_seg->next;
    }
  }
  assert(de_seg);
  de_seg->segment_part = segment_index;
  struct timespec now;
  clock_gettime(CLOCK_REALTIME, &now);
  char string_float[TIME_CHARS];
  snprintf(string_float, TIME_CHARS, "%lu.%lu", now.tv_sec, now.tv_nsec);
  char meta_mtime[TIME_CHARS];
  snprintf(meta_mtime, TIME_CHARS, "%f", atof(string_float));
  char seg_base[MAX_URL_SIZE] = "";
  char container[MAX_URL_SIZE] = "";
  char object[MAX_URL_SIZE] = "";
  split_path(de->full_name, seg_base, container, object);
  char manifest[MAX_URL_SIZE];
  snprintf(manifest, MAX_URL_SIZE, "%s_segments", container);
  if (!de->manifest)
    de->manifest = strdup(manifest);
  //fixme: how to get full file size so early?
  snprintf(manifest, MAX_URL_SIZE, "%s_segments/%s/%s/%ld/%ld/",
           container, object, meta_mtime, /* how to get this?*/ 0,
           segment_size);
  char tmp[MAX_URL_SIZE];
  strncpy(tmp, seg_base, MAX_URL_SIZE);
  snprintf(seg_base, MAX_URL_SIZE, "%s/%s", tmp, manifest);

  char seg_name[8 + 1] = { 0 };
  snprintf(seg_name, 8 + 1, "%08i", segment_index);
  de_seg->name = strdup(seg_name);

  char seg_path[MAX_URL_SIZE] = { 0 };
  snprintf(seg_path, MAX_URL_SIZE, "%s%08i", seg_base, segment_index);
  de_seg->full_name = strdup(seg_path);

  return de_seg;
}

void dir_decache(const char* path)
{
  dir_cache* cw;
  debugf(DBG_LEVEL_NORM, "dir_decache(%s)", path);
  pthread_mutex_lock(&dcachemut);
  dir_entry* de, *tmpde;
  char dir[MAX_PATH_SIZE];
  dir_for(path, dir);
  for (cw = dcache; cw; cw = cw->next)
  {
    debugf(DBG_LEVEL_EXT, "dir_decache: parse(%s)", cw->path);
    if (!strcmp(cw->path, path))
    {
      if (cw == dcache)
        dcache = cw->next;
      if (cw->prev)
        cw->prev->next = cw->next;
      if (cw->next)
        cw->next->prev = cw->prev;
      debugf(DBG_LEVEL_EXT, "dir_decache: free_dir1(%s)", cw->path);
      //fixme: this sometimes is NULL and generates segfaults, checking first
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
        debugf(DBG_LEVEL_EXT, "dir_decache: free_dir2()");
        cloudfs_free_dir_list(de);
      }
      else for (de = cw->entries; de->next; de = de->next)
        {
          if (!strcmp(de->next->full_name, path))
          {
            tmpde = de->next;
            de->next = de->next->next;
            tmpde->next = NULL;
            debugf(DBG_LEVEL_EXT, "dir_decache: free_dir3()", cw->path);
            cloudfs_free_dir_list(tmpde);
            break;
          }
        }
    }
  }
  pthread_mutex_unlock(&dcachemut);
}

//data_buf exists for dowload and upload
int init_semaphores(struct progressive_data_buf* data_buf, dir_entry* de,
                    char* prefix)
{
  debugf(DBG_LEVEL_EXTALL, "init_semaphores(%s): prefix=%s len=%d",
         de->full_name,
         prefix, strlen(prefix));
  char semaphore_name[MD5_DIGEST_HEXA_STRING_LEN + 20] = "\0";
  int errsv, sem_val, i;
  char* sem_name;
  for (i = 0; i < 2; i++)
  {
    if (data_buf->sem_list[i] || data_buf->sem_name_list[i])
    {
      debugf(DBG_LEVEL_NORM, KYEL
             "init_semaphores(%s): semaphore %d not null @init", de->name, i);
      abort();
    }
    if (i == SEM_EMPTY)
      sem_name = "isempty";
    else if (i == SEM_FULL)
      sem_name = "isfull";
    else
    {
      debugf(DBG_LEVEL_EXTALL,
             "init_semaphores(%s): " KRED "unknown semaphore type=%d", de->full_name, i);
      return 0;
    }
    snprintf(semaphore_name, sizeof(semaphore_name), "/%s_%s_%s", prefix, sem_name,
             de->full_name_hash);
    debugf(DBG_LEVEL_EXTALL, "init_semaphores(%s): sem_name=%s", de->full_name,
           semaphore_name);
    //don't forget to free this
    data_buf->sem_name_list[i] = strdup(semaphore_name);
    //ensure semaphore does not exist
    //(might be in the system from a previous unclean finished operation)
    sem_unlink(data_buf->sem_name_list[i]);
    if ((data_buf->sem_list[i] = sem_open(data_buf->sem_name_list[i],
                                          O_CREAT | O_EXCL, 0644, 0)) == SEM_FAILED)
    {
      errsv = errno;
      debugf(DBG_LEVEL_NORM,
             KRED"init_semaphores(%s): cannot init isempty semaphore for progressive upload, err=%s",
             de->full_name, strerror(errsv));
      exit(1);
    }
    else
    {
      sem_getvalue(data_buf->sem_list[i], &sem_val);
      debugf(DBG_LEVEL_EXTALL,
             "init_semaphores(%s): semaphore[%s] created, size_left=%lu, sem_val=%d",
             de->full_name, data_buf->sem_name_list[i], data_buf->work_buf_size, sem_val);
    }
  }
  return true;
}

int free_semaphores(struct progressive_data_buf* data_buf, int sem_index)
{
  if (data_buf->sem_list[sem_index])
  {
    sem_post(data_buf->sem_list[sem_index]);
    sem_post(data_buf->sem_list[sem_index]);
    sem_close(data_buf->sem_list[sem_index]);
    sem_unlink(data_buf->sem_name_list[sem_index]);
    free(data_buf->sem_name_list[sem_index]);
    data_buf->sem_list[sem_index] = NULL;
    data_buf->sem_name_list[sem_index] = NULL;
  }
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


dir_entry* init_dir_entry()
{
  dir_entry* de = (dir_entry*)malloc(sizeof(dir_entry));
  de->metadata_downloaded = false;
  de->size = 0;
  de->next = NULL;
  de->md5sum = NULL;
  de->md5sum_local = NULL;
  de->manifest = NULL;
  de->accessed_in_cache = time(NULL);
  de->last_modified = time(NULL);
  de->mtime.tv_sec = time(NULL);
  de->atime.tv_sec = time(NULL);
  de->ctime.tv_sec = time(NULL);
  de->mtime.tv_nsec = 0;
  de->atime.tv_nsec = 0;
  de->ctime.tv_nsec = 0;
  de->chmod = 0;
  de->gid = 0;
  de->uid = 0;
  //de->upload_buf.upload_completed = false;
  //de->upload_buf.write_completed = false;
  de->upload_buf.local_cache_file = NULL;
  //de->downld_buf.download_started = false;
  de->downld_buf.local_cache_file = NULL;
  //de->downld_buf.reading_ahead = false;
  de->downld_buf.fuse_read_size = -1;
  de->downld_buf.work_buf_size = -1;
  de->downld_buf.offset = -1;
  de->downld_buf.mutex_initialised = false;
  de->downld_buf.sem_list[SEM_EMPTY] = NULL;
  de->downld_buf.sem_list[SEM_FULL] = NULL;
  de->downld_buf.sem_name_list[SEM_EMPTY] = NULL;
  de->downld_buf.sem_name_list[SEM_FULL] = NULL;
  de->upload_buf.sem_list[SEM_EMPTY] = NULL;
  de->upload_buf.sem_list[SEM_FULL] = NULL;
  de->upload_buf.sem_name_list[SEM_EMPTY] = NULL;
  de->upload_buf.sem_name_list[SEM_FULL] = NULL;
  de->downld_buf.ahead_thread_count = 0;
  de->full_name_hash = NULL;
  de->is_segmented = false;
  de->segments = NULL;
  de->segment_count = 0;
  de->segment_part = -1;
  return de;
}

void copy_dir_entry(dir_entry* src, dir_entry* dst)
{
  dst->atime.tv_sec = src->atime.tv_sec;
  dst->atime.tv_nsec = src->atime.tv_nsec;
  dst->mtime.tv_sec = src->mtime.tv_sec;
  dst->mtime.tv_nsec = src->mtime.tv_nsec;
  dst->ctime.tv_sec = src->ctime.tv_sec;
  dst->ctime.tv_nsec = src->ctime.tv_nsec;
  dst->chmod = src->chmod;
  if (src->md5sum != NULL)
  {
    //TODO: copy md5sum
  }
  //dst->md5sum = src->md5sum;
}

//check for file in cache, if found size will be updated, if not found
//and this is a dir, a new dir cache entry is created
void update_dir_cache(const char* path, off_t size, int isdir, int islink)
{
  debugf(DBG_LEVEL_EXTALL,
         KCYN "update_dir_cache(%s) size=%lu isdir=%d islink=%d", path, size, isdir,
         islink);
  pthread_mutex_lock(&dcachemut);
  dir_cache* cw;
  dir_entry* de;
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
          pthread_mutex_unlock(&dcachemut);
          debugf(DBG_LEVEL_EXTALL, "exit 0: update_dir_cache(%s)", path);
          return;
        }
      }
      de = init_dir_entry();
      de->size = size;
      de->isdir = isdir;
      de->islink = islink;
      de->name = strdup(&path[strlen(cw->path) + 1]);
      de->full_name = strdup(path);

      if (islink)
        de->content_type = strdup("application/link");
      if (isdir)
        de->content_type = strdup("application/directory");
      else
        de->content_type = strdup("application/octet-stream");
      de->next = cw->entries;
      cw->entries = de;
      if (isdir)
        new_cache(path);
      break;
    }
  }
  debugf(DBG_LEVEL_EXTALL, "exit 1: update_dir_cache(%s)", path);
  pthread_mutex_unlock(&dcachemut);
}

//returns first file entry in linked list. if not in cache will be downloaded.
int caching_list_directory(const char* path, dir_entry** list)
{
  debugf(DBG_LEVEL_EXTALL, "caching_list_directory(%s)", path);
  pthread_mutex_lock(&dcachemut);
  bool new_entry = false;
  if (!strcmp(path, "/"))
    path = "";
  dir_cache* cw;
  for (cw = dcache; cw; cw = cw->next)
  {
    if (cw->was_deleted == true)
    {
      debugf(DBG_LEVEL_EXTALL,
             KMAG"caching_list_directory status: dir(%s) is empty as cached expired, reload from cloud",
             cw->path);
      if (!cloudfs_list_directory(cw->path, list))
        debugf(DBG_LEVEL_EXTALL,
               KMAG"caching_list_directory status: cannot reload dir(%s)", cw->path);
      else
      {
        debugf(DBG_LEVEL_EXTALL, KMAG"caching_list_directory status: reloaded dir(%s)",
               cw->path);
        //cw->entries = *list;
        cw->was_deleted = false;
        cw->cached = time(NULL);
      }
    }
    if (cw->was_deleted == false)
    {
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
      pthread_mutex_unlock(&dcachemut);
      debugf(DBG_LEVEL_EXTALL,
             "exit 0: caching_list_directory(%s) "KYEL"[CACHE-DIR-MISS]", path);
      return  0;
    }
    debugf(DBG_LEVEL_EXTALL,
           "caching_list_directory: new_cache(%s) "KYEL"[CACHE-CREATE]", path);
    cw = new_cache(path);
    new_entry = true;
  }
  else if (cache_timeout > 0 && (time(NULL) - cw->cached > cache_timeout))
  {
    if (!cloudfs_list_directory(path, list))
    {
      //mutex unlock was forgotten
      pthread_mutex_unlock(&dcachemut);
      debugf(DBG_LEVEL_EXTALL, "exit 1: caching_list_directory(%s)", path);
      return  0;
    }
    //fixme: this frees dir subentries but leaves the dir parent entry, this confuses path_info
    //which believes this dir has no entries
    if (cw->entries != NULL)
    {
      cloudfs_free_dir_list(cw->entries);
      cw->was_deleted = true;
      cw->cached = time(NULL);
      debugf(DBG_LEVEL_EXTALL, "caching_list_directory(%s) "KYEL"[CACHE-EXPIRED]",
             path);
    }
    else
    {
      debugf(DBG_LEVEL_EXTALL,
             "got NULL on caching_list_directory(%s) "KYEL"[CACHE-EXPIRED w NULL]", path);
      pthread_mutex_unlock(&dcachemut);
      return 0;
    }
  }
  else
  {
    debugf(DBG_LEVEL_EXTALL, "caching_list_directory(%s) "KGRN"[CACHE-DIR-HIT]",
           path);
    *list = cw->entries;
  }
  //adding new dir file list to global cache, now this dir becomes visible in cache
  cw->entries = *list;
  pthread_mutex_unlock(&dcachemut);
  debugf(DBG_LEVEL_EXTALL, "exit 2: caching_list_directory(%s)", path);
  return 1;
}

dir_entry* path_info(const char* path)
{
  debugf(DBG_LEVEL_EXTALL, "path_info(%s)", path);
  char dir[MAX_PATH_SIZE];
  dir_for(path, dir);
  dir_entry* tmp;
  if (!caching_list_directory(dir, &tmp))
  {
    debugf(DBG_LEVEL_EXTALL, "exit 0: path_info(%s) "KYEL"[CACHE-DIR-MISS]", dir);
    return NULL;
  }
  else
    debugf(DBG_LEVEL_EXTALL, "path_info(%s) "KGRN"[CACHE-DIR-HIT]", dir);
  //iterate in file list obtained from cache or downloaded
  for (; tmp; tmp = tmp->next)
  {
    if (!strcmp(tmp->full_name, path))
    {
      debugf(DBG_LEVEL_EXTALL, "exit 1: path_info(%s) "KGRN"[CACHE-FILE-HIT]", path);
      return tmp;
    }
  }
  //miss in case the file is not found on a cached folder
  debugf(DBG_LEVEL_EXTALL, "exit 2: path_info(%s) "KYEL"[CACHE-MISS]", path);
  return NULL;
}


//retrieve folder from local cache if exists, return null if does not exist (rather than download)
int check_caching_list_directory(const char* path, dir_entry** list)
{
  debugf(DBG_LEVEL_EXTALL, "check_caching_list_directory(%s)", path);
  pthread_mutex_lock(&dcachemut);
  if (!strcmp(path, "/"))
    path = "";
  dir_cache* cw;
  for (cw = dcache; cw; cw = cw->next)
    if (!strcmp(cw->path, path))
    {
      *list = cw->entries;
      pthread_mutex_unlock(&dcachemut);
      debugf(DBG_LEVEL_EXTALL,
             "exit 0: check_caching_list_directory(%s) "KGRN"[CACHE-DIR-HIT]", path);
      return 1;
    }
  pthread_mutex_unlock(&dcachemut);
  debugf(DBG_LEVEL_EXTALL,
         "exit 1: check_caching_list_directory(%s) "KYEL"[CACHE-DIR-MISS]", path);
  return 0;
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

//check if local path is in cache, without downloading from cloud if not in cache
dir_entry* check_path_info(const char* path)
{
  debugf(DBG_LEVEL_EXTALL, "check_path_info(%s)", path);
  char dir[MAX_PATH_SIZE];
  dir_for(path, dir);
  dir_entry* tmp;
  //get parent folder cache entry
  if (!check_caching_list_directory(dir, &tmp))
  {
    debugf(DBG_LEVEL_EXTALL, "exit 0: check_path_info(%s) "KYEL"[CACHE-MISS]",
           path);
    return NULL;
  }
  for (; tmp; tmp = tmp->next)
  {
    if (!strcmp(tmp->full_name, path))
    {
      debugf(DBG_LEVEL_EXTALL, "exit 1: check_path_info(%s) "KGRN"[CACHE-HIT]",
             path);
      return tmp;
    }
  }
  if (!strcmp(path, "/"))
    debugf(DBG_LEVEL_EXTALL,
           "exit 2: check_path_info(%s) "KYEL"ignoring root [CACHE-MISS]", path);
  else
    debugf(DBG_LEVEL_EXTALL, "exit 3: check_path_info(%s) "KYEL"[CACHE-MISS]",
           path);
  return NULL;
}

/*
  look for segment in cache
  if exists, returns file handle to file in cache
  if does not exist, create file and return handle
*/
bool open_segment_in_cache(dir_entry* de, dir_entry* de_seg,
                           FILE** fp_segment, const char* method)
{
  assert(*fp_segment == NULL);
  char segment_file_path[NAME_MAX] = { 0 };
  char segment_file_dir[NAME_MAX] = { 0 };
  get_safe_cache_file_path(de->full_name, segment_file_path, segment_file_dir,
                           temp_dir, de_seg->segment_part);
  struct stat dir_status = { 0 };
  if (stat(segment_file_dir, &dir_status) == -1)
    mkdir(segment_file_dir, 0700);
  bool file_exist = access(segment_file_path, F_OK) != -1;
  // todo: check open modes
  *fp_segment = fopen(segment_file_path, method[0] == 'G' ?
                      (file_exist ? "r+" : "w+") : (file_exist ? "r+" : "w+"));
  int err = errno;
  assert(*fp_segment);
  debugf(DBG_LEVEL_EXTALL,
         KMAG"open_segment_from_cache: open segment fp=%p segindex=%d",
         *fp_segment, de_seg->segment_part);
  if (file_exist)
  {
    debugf(DBG_LEVEL_EXTALL,
           KMAG"open_segment_from_cache: found segment %d md5=%s",
           de_seg->segment_part, de_seg->md5sum);
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
    debugf(DBG_LEVEL_EXTALL,
           KMAG"open_segment_from_cache: found segment %d md5=%s",
           de_seg->segment_part, de_seg->md5sum);
    //check if segment is in cache, with md5sum ok
    if (de_seg->md5sum_local == NULL)
    {
      char md5_file_hash_str[MD5_DIGEST_HEXA_STRING_LEN] = "\0";
      file_md5(*fp_segment, md5_file_hash_str);
      de_seg->md5sum_local = strdup(md5_file_hash_str);
    }
    else
      debugf(DBG_LEVEL_EXTALL, KMAG
             "open_segment_from_cache: segment md5sum_local=%s md5sum=%s",
             de_seg->md5sum_local, de_seg->md5sum);
    bool match = (de && de->md5sum != NULL
                  && (!strcasecmp(de_seg->md5sum_local, de_seg->md5sum)));
    if (!match)
    {
      debugf(DBG_LEVEL_EXT, "open_segment_from_cache: "
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
  bool result = false;
  char segment_file_path[NAME_MAX] = { 0 };
  get_safe_cache_file_path(de->full_name, segment_file_path, NULL,
                           temp_dir, de_seg->segment_part);
  bool file_exist = access(segment_file_path, F_OK) != -1;
  if (file_exist)
  {
    size_t seg_size = cloudfs_file_size(fileno(fp));
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
  assert(*fp == NULL);
  char file_path[NAME_MAX] = { 0 };
  get_safe_cache_file_path(de->full_name, file_path, NULL, temp_dir, -1);
  bool file_exist = access(file_path, F_OK) != -1;
  *fp = fopen(file_path, method[0] == 'G' ?
              (file_exist ? "r+" : "w+") : (file_exist ? "r+" : "w+"));
  int err = errno;
  assert(*fp);
  if (file_exist)
  {
    debugf(DBG_LEVEL_EXTALL, KMAG "open_file_in_cache(%s) ok", file_path);
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
  bool file_exist = open_file_in_cache(de, fp, method);
  debugf(DBG_LEVEL_EXTALL, KMAG"open_file_cache_md5: open fp=%p", *fp);
  if (file_exist)
  {
    debugf(DBG_LEVEL_EXTALL, KMAG "open_file_cache_md5: found file md5=%s",
           de->md5sum);
    //check if segment is in cache, with md5sum ok
    if (de->md5sum_local == NULL)
    {
      char md5_file_hash_str[MD5_DIGEST_HEXA_STRING_LEN] = "\0";
      file_md5(*fp, md5_file_hash_str);
      de->md5sum_local = strdup(md5_file_hash_str);
    }
    else
      debugf(DBG_LEVEL_EXTALL, KMAG
             "open_file_cache_md5: md5sum_local=%s md5sum=%s",
             de->md5sum_local, de->md5sum);
    bool match = (de && de->md5sum != NULL
                  && (!strcasecmp(de->md5sum_local, de->md5sum)));
    if (!match)
    {
      debugf(DBG_LEVEL_EXT, "open_file_cache_md5: "
             KYEL "no match, md5sum_local=%s md5sum=%s",
             de->md5sum_local, de->md5sum);
      free(de->md5sum_local);
      de->md5sum_local = NULL;
    }
    return match;
  }
  return false;
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

void cloudfs_debug(int dbg)
{
  debug = dbg;
}

void debugf(int level, char* fmt, ...)
{
  if (debug)
  {
    if (level <= option_debug_level)
    {
#ifdef SYS_gettid
      pid_t thread_id = syscall(SYS_gettid);
#else
      int thread_id = 0;
#error "SYS_gettid unavailable on this system"
#endif
      va_list args;
      char prefix[] = "==DBG %d [%s]:%d==";
      char line[4096];
      char time_str[TIME_CHARS];
      get_time_now_as_str(time_str, sizeof(time_str));
      sprintf(line, prefix, level, time_str, thread_id);
      fputs(line, stderr);
      va_start(args, fmt);
      vfprintf(stderr, fmt, args);
      va_end(args);
      fputs(KNRM, stderr);
      putc('\n', stderr);
      putc('\r', stderr);
    }
  }
}
