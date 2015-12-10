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
#include <libxml/tree.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <json.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <errno.h>
#include <fuse.h>
#include "commonfs.h"
#include "cloudfsapi.h"
#include "config.h"

#define RHEL5_LIBCURL_VERSION 462597
#define RHEL5_CERTIFICATE_FILE "/etc/pki/tls/certs/ca-bundle.crt"
#define REQUEST_RETRIES 3
#define MAX_FILES 10000
// size of buffer for writing to disk look at ioblksize.h in coreutils
// and try some values on your own system if you want the best performance
#define DISK_BUFF_SIZE 32768

static char storage_url[MAX_URL_SIZE];
static char storage_token[MAX_HEADER_SIZE];
static pthread_mutex_t pool_mut;
static CURL* curl_pool[1024];
static int curl_pool_count = 0;
extern int debug;
extern int verify_ssl;
extern bool option_get_extended_metadata;
extern bool option_curl_verbose;
extern int option_curl_progress_state;
extern int option_cache_statfs_timeout;
extern bool option_extensive_debug;
extern bool option_enable_chown;
extern bool option_enable_chmod;
extern bool option_enable_progressive_upload;
extern bool option_enable_progressive_download;
extern char* temp_dir;
static int rhel5_mode = 0;
static struct statvfs statcache =
{
  .f_bsize = 4096,
  .f_frsize = 4096,
  .f_blocks = INT_MAX,
  .f_bfree = INT_MAX,
  .f_bavail = INT_MAX,
  .f_files = MAX_FILES,
  .f_ffree = 0,
  .f_favail = 0,
  .f_namemax = INT_MAX
};
static time_t last_stat_read_time = 0;//used to compute cache interval
extern FuseOptions options;

struct MemoryStruct
{
  char* memory;
  size_t size;
};

#ifdef HAVE_OPENSSL
#include <openssl/crypto.h>
static pthread_mutex_t* ssl_lockarray;
static void lock_callback(int mode, int type, char* file, int line)
{
  if (mode & CRYPTO_LOCK)
    pthread_mutex_lock(&(ssl_lockarray[type]));
  else
    pthread_mutex_unlock(&(ssl_lockarray[type]));
}

static unsigned long thread_id()
{
  return (unsigned long)pthread_self();
}
#endif

static size_t xml_dispatch(void* ptr, size_t size, size_t nmemb, void* stream)
{
  xmlParseChunk((xmlParserCtxtPtr)stream, (char*)ptr, size * nmemb, 0);
  return size * nmemb;
}

static CURL* get_connection(const char* path)
{
  pthread_mutex_lock(&pool_mut);
  CURL* curl = curl_pool_count ? curl_pool[--curl_pool_count] : curl_easy_init();
  if (!curl)
  {
    debugf(DBG_LEVEL_NORM, KRED"curl alloc failed");
    abort();
  }
  pthread_mutex_unlock(&pool_mut);
  return curl;
}

static void return_connection(CURL* curl)
{
  pthread_mutex_lock(&pool_mut);
  curl_pool[curl_pool_count++] = curl;
  pthread_mutex_unlock(&pool_mut);
}

static void add_header(curl_slist** headers, const char* name,
                       const char* value)
{
  char x_header[MAX_HEADER_SIZE];
  char safe_value[256];
  const char* value_ptr;
  debugf(DBG_LEVEL_EXTALL, "add_header(%s:%s)", name, value);
  if (strlen(value) > 256)
  {
    debugf(DBG_LEVEL_NORM, KRED"add_header: warning, value size > 256 (%s:%s) ",
           name, value);
    //hubic will throw an HTTP 400 error on X-Copy-To operation
    //if X-Object-Meta-FilePath header value is larger than 256 chars
    //fix for issue #95 https://github.com/TurboGit/hubicfuse/issues/95
    if (!strcasecmp(name, "X-Object-Meta-FilePath"))
    {
      debugf(DBG_LEVEL_NORM,
             KRED"add_header: trimming header (%s) value to max allowed", name);
      //trim header size to max allowed
      strncpy(safe_value, value, 256 - 1);
      safe_value[255] = '\0';
      value_ptr = safe_value;
    }
    else
      value_ptr = value;
  }
  else
    value_ptr = value;
  snprintf(x_header, sizeof(x_header), "%s: %s", name, value_ptr);
  *headers = curl_slist_append(*headers, x_header);
}

static size_t header_dispatch(void* ptr, size_t size, size_t nmemb,
                              void* dir_entry)
{
  char* header = (char*)alloca(size * nmemb + 1);
  char* head = (char*)alloca(size * nmemb + 1);
  char* value = (char*)alloca(size * nmemb + 1);
  memcpy(header, (char*)ptr, size * nmemb);
  header[size * nmemb] = '\0';
  if (sscanf(header, "%[^:]: %[^\r\n]", head, value) == 2)
  {
    if (!strncasecmp(head, "x-auth-token", size * nmemb))
      strncpy(storage_token, value, sizeof(storage_token));
    if (!strncasecmp(head, "x-storage-url", size * nmemb))
      strncpy(storage_url, value, sizeof(storage_url));
    if (!strncasecmp(head, "x-account-meta-quota", size * nmemb))
      statcache.f_blocks = (unsigned long) (strtoull(value, NULL,
                                            10) / statcache.f_frsize);
    if (!strncasecmp(head, "x-account-bytes-used", size * nmemb))
      statcache.f_bfree = statcache.f_bavail = statcache.f_blocks - (unsigned long) (
                            strtoull(value, NULL, 10) / statcache.f_frsize);
    if (!strncasecmp(head, "x-account-object-count", size * nmemb))
    {
      unsigned long object_count = strtoul(value, NULL, 10);
      statcache.f_ffree = MAX_FILES - object_count;
      statcache.f_favail = MAX_FILES - object_count;
    }
  }
  return size * nmemb;
}

static void header_set_time_from_str(char* time_str,
                                     struct timespec* time_entry)
{
  char sec_value[TIME_CHARS];
  char nsec_value[TIME_CHARS];
  time_t sec;
  long nsec;
  sscanf(time_str, "%[^.].%[^\n]", sec_value, nsec_value);
  sec = strtoll(sec_value, NULL, 10);//to allow for larger numbers
  nsec = atol(nsec_value);
  debugf(DBG_LEVEL_EXTALL, "Received time=%s.%s / %li.%li, existing=%li.%li",
         sec_value, nsec_value, sec, nsec, time_entry->tv_sec, time_entry->tv_nsec);
  if (sec != time_entry->tv_sec || nsec != time_entry->tv_nsec)
  {
    debugf(DBG_LEVEL_EXTALL,
           "Time changed, setting new time=%li.%li, existing was=%li.%li",
           sec, nsec, time_entry->tv_sec, time_entry->tv_nsec);
    time_entry->tv_sec = sec;
    time_entry->tv_nsec = nsec;
    char time_str_local[TIME_CHARS] = "";
    get_time_as_string((time_t)sec, nsec, time_str_local, sizeof(time_str_local));
    debugf(DBG_LEVEL_EXTALL, "header_set_time_from_str received time=[%s]",
           time_str_local);
    get_timespec_as_str(time_entry, time_str_local, sizeof(time_str_local));
    debugf(DBG_LEVEL_EXTALL, "header_set_time_from_str set time=[%s]",
           time_str_local);
  }
}

/*
   get file metadata from HTTP response headers
*/
static size_t header_get_meta_dispatch(void* ptr, size_t size, size_t nmemb,
                                       void* userdata)
{
  char* header = (char*)alloca(size * nmemb + 1);
  char* head = (char*)alloca(size * nmemb + 1);
  char* value = (char*)alloca(size * nmemb + 1);
  memcpy(header, (char*)ptr, size * nmemb);
  header[size * nmemb] = '\0';
  static char storage[MAX_HEADER_SIZE];
  if (sscanf(header, "%[^:]: %[^\r\n]", head, value) == 2)
  {
    //sometimes etag is formated on hubic with "" (for segmented files?), check inconsistency!
    char* quote_lptr = strchr(value, '"');
    char* quote_rptr = strrchr(value, '"');
    if (quote_lptr || quote_rptr)
    {
      debugf(DBG_LEVEL_NORM, "header_get_meta_dispatch: " KRED
             "header value incorrectly formated on cloud, head=[%s], value=[%s]", head,
             value);

      if (quote_lptr && quote_rptr)
      {
        debugf(DBG_LEVEL_NORM, "header_get_meta_dispatch: " KYEL
               "fixing by stripping quotes, value=[%s]", value);
        removeSubstr(value, "\"");
        debugf(DBG_LEVEL_NORM, "header_get_meta_dispatch: " KGRN
               "fixed value=[%s]", value);
      }
      else
        debugf(DBG_LEVEL_NORM, "header_get_meta_dispatch: " KRED
               "unable to fix value=[%s]", value);
    }
    strncpy(storage, head, sizeof(storage));
    //debugf(DBG_LEVEL_EXTALL, "header_get_meta_dispatch: " KCYN "head=[%s] val=[%s]", head, value);
    dir_entry* de = (dir_entry*)userdata;
    if (de != NULL)
    {
      if (!strncasecmp(head, HEADER_TEXT_ATIME, size * nmemb))
        header_set_time_from_str(value, &de->atime);
      if (!strncasecmp(head, HEADER_TEXT_CTIME, size * nmemb))
        header_set_time_from_str(value, &de->ctime);
      if (!strncasecmp(head, HEADER_TEXT_MTIME, size * nmemb))
        header_set_time_from_str(value, &de->mtime);
      if (!strncasecmp(head, HEADER_TEXT_CHMOD, size * nmemb))
        de->chmod = atoi(value);
      if (!strncasecmp(head, HEADER_TEXT_GID, size * nmemb))
        de->gid = atoi(value);
      if (!strncasecmp(head, HEADER_TEXT_UID, size * nmemb))
        de->uid = atoi(value);
      if (!strncasecmp(head, HEADER_TEXT_MD5HASH, size * nmemb))
      {
        if (de->md5sum == NULL)
        {
          de->md5sum = strdup(value);
          debugf(DBG_LEVEL_EXT, "header_get_meta_dispatch: set md5sum=%s", de->md5sum);
        }
        else if (strcasecmp(de->md5sum, value))
        {
          //todo: hash is different, usually on large segmented files
          debugf(DBG_LEVEL_NORM, "header_get_meta_dispatch: " KYEL
                 "hash difference, unreliable data, cache=%s cloud=%s", de->md5sum, value);
          //fixme: sometimes etag on hubic is incorrect, noticed on segmented files
          //free(de->md5sum);
          //de->md5sum = NULL;
        }
      }
      if (!strncasecmp(head, HEADER_TEXT_IS_SEGMENTED, size * nmemb))
      {
        de->is_segmented = atoi(value);
        debugf(DBG_LEVEL_EXT, "header_get_meta_dispatch: manual is_segmented=%d",
               de->is_segmented);
      }
    }
    else
      debugf(DBG_LEVEL_EXT,
             "Unexpected NULL dir_entry on header(%s), file should be in cache already",
             storage);
  }
  else
  {
    //debugf(DBG_LEVEL_NORM, "Received unexpected header line");
  }
  return size * nmemb;
}

void set_direntry_headers(dir_entry* de, curl_slist* headers)
{
  char atime_str_nice[TIME_CHARS] = "";
  char mtime_str_nice[TIME_CHARS] = "";
  char ctime_str_nice[TIME_CHARS] = "";
  get_timespec_as_str(&(de->atime), atime_str_nice, sizeof(atime_str_nice));
  debugf(DBG_LEVEL_EXTALL, KCYN"send_request_size: atime=[%s]", atime_str_nice);
  get_timespec_as_str(&(de->mtime), mtime_str_nice, sizeof(mtime_str_nice));
  debugf(DBG_LEVEL_EXTALL, KCYN"send_request_size: mtime=[%s]", mtime_str_nice);
  get_timespec_as_str(&(de->ctime), ctime_str_nice, sizeof(ctime_str_nice));
  debugf(DBG_LEVEL_EXTALL, KCYN"send_request_size: ctime=[%s]", ctime_str_nice);
  char mtime_str[TIME_CHARS];
  char atime_str[TIME_CHARS];
  char ctime_str[TIME_CHARS];
  char string_float[TIME_CHARS];
  snprintf(mtime_str, TIME_CHARS, "%lu.%lu", de->mtime.tv_sec,
           de->mtime.tv_nsec);
  snprintf(atime_str, TIME_CHARS, "%lu.%lu", de->atime.tv_sec,
           de->atime.tv_nsec);
  snprintf(ctime_str, TIME_CHARS, "%lu.%lu", de->ctime.tv_sec,
           de->ctime.tv_nsec);
  add_header(&headers, HEADER_TEXT_FILEPATH, de->full_name);//orig_path);
  add_header(&headers, HEADER_TEXT_MTIME, mtime_str);
  add_header(&headers, HEADER_TEXT_ATIME, atime_str);
  add_header(&headers, HEADER_TEXT_CTIME, ctime_str);
  add_header(&headers, HEADER_TEXT_MTIME_DISPLAY, mtime_str_nice);
  add_header(&headers, HEADER_TEXT_ATIME_DISPLAY, atime_str_nice);
  add_header(&headers, HEADER_TEXT_CTIME_DISPLAY, ctime_str_nice);
  char gid_str[INT_CHAR_LEN], uid_str[INT_CHAR_LEN], chmod_str[INT_CHAR_LEN];
  char is_segmented_str[INT_CHAR_LEN];
  snprintf(gid_str, INT_CHAR_LEN, "%d", de->gid);
  snprintf(uid_str, INT_CHAR_LEN, "%d", de->uid);
  snprintf(chmod_str, INT_CHAR_LEN, "%d", de->chmod);
  snprintf(is_segmented_str, INT_CHAR_LEN, "%d", de->is_segmented);
  add_header(&headers, HEADER_TEXT_GID, gid_str);
  add_header(&headers, HEADER_TEXT_UID, uid_str);
  add_header(&headers, HEADER_TEXT_CHMOD, chmod_str);
  add_header(&headers, HEADER_TEXT_IS_SEGMENTED, is_segmented_str);
}
/*
   write data to file from segmented download
*/
size_t fwrite2(void* ptr, size_t size, size_t nmemb, FILE* filep)
{
  //debug_print_file_name(filep);
  return fwrite((const void*)ptr, size, nmemb, filep);
}

/*
   pass data from a file for uploading multiple segments
*/
static size_t rw_callback(size_t (*rw)(void*, size_t, size_t, FILE*),
                          void* ptr,
                          size_t size, size_t nmemb, void* userp)
{
  struct segment_info* info = (struct segment_info*)userp;
  size_t mem = size * nmemb;
  if (mem < 1 || info->size < 1)
    return 0;
  size_t amt_read = rw(ptr, 1, info->size < mem ? info->size : mem, info->fp);
  info->size -= amt_read;
  return amt_read;
}

/*
   pass data for uploading multiple segments
*/
static size_t read_callback(void* ptr, size_t size, size_t nmemb, void* userp)
{
  return rw_callback(fread, ptr, size, nmemb, userp);
}

/*
   write data to file from segmented download
*/
static size_t write_callback_progressive(void* ptr, size_t size, size_t nmemb,
    void* userp)
{
  size_t http_size = size * nmemb;
  size_t result = http_size;
  int rnd = random_at_most(50);

  debugf(DBG_LEVEL_EXT, KMAG"write_callback_progrs: enter http_size=%lu rnd=%d",
         http_size, rnd);
  sleep_ms(rnd);
  struct segment_info* info = (struct segment_info*)userp;
  //todo: in case of progressive ops signal we have data to cfs_read
  debugf(DBG_LEVEL_EXT,
         KMAG"write_callback_progrs: http buffer full, fuse_size=%lu, wait empty",
         info->de->downld_buf.fuse_read_size);
  size_t data_copy_size;
  size_t http_ptr_index = 0;
  const void* src;
  const void* dest;
  int sem_val;

  sem_wait(info->de->downld_buf.sem_list[SEM_EMPTY]);

  //copy data to fuse buffer until is full OR until no data left to copy in http buf
  while (info->de->downld_buf.work_buf_size < info->de->downld_buf.fuse_read_size
         && (http_size - http_ptr_index > 0))
  {
    //data left needed
    data_copy_size = min(info->de->downld_buf.fuse_read_size -
                         info->de->downld_buf.work_buf_size,
                         http_size - http_ptr_index);
    src = ptr + http_ptr_index;
    dest = info->de->downld_buf.readptr + info->de->downld_buf.work_buf_size;
    memcpy((void*)dest, src, data_copy_size);
    info->de->downld_buf.work_buf_size += data_copy_size;
    http_ptr_index += data_copy_size;
    debugf(DBG_LEVEL_EXT, KCYN
           "write_callback_progrs: data_copy_size=%lu ptr=%lu src=%lu dest=%lu wrksize=%lu lefthttp=%lu",
           data_copy_size, ptr, src, dest, info->de->downld_buf.work_buf_size,
           http_size - http_ptr_index);

    if ((info->de->downld_buf.work_buf_size == info->de->downld_buf.fuse_read_size)
        && (http_size != http_ptr_index))
    {
      sem_getvalue(info->de->downld_buf.sem_list[SEM_FULL], &sem_val);
      //fuse buffer full, http data remains
      debugf(DBG_LEVEL_EXT, KMAG
             "write_callback_progrs: copied, post full, some http data left=%lu sem=%d",
             http_size - http_ptr_index, sem_val);
      sem_post(info->de->downld_buf.sem_list[SEM_FULL]);
      sem_getvalue(info->de->downld_buf.sem_list[SEM_EMPTY], &sem_val);
      debugf(DBG_LEVEL_EXT, KMAG
             "write_callback_progrs: wait [1] fuse buffer empty, sem=%d", sem_val);
      sem_wait(info->de->downld_buf.sem_list[SEM_EMPTY]);
      //after this work_buf_size = 0, set by cfs_read
      debugf(DBG_LEVEL_EXT, KMAG
             "write_callback_progrs: done wait empty [1] work_buf=%lu",
             info->de->downld_buf.work_buf_size);
    }

    if (data_copy_size == http_size)
    {
      //http buffer fully copied, more http data needed
      debugf(DBG_LEVEL_EXT, KMAG
             "write_callback_progrs: http buffer fully copied");
      break;
    }
    //fuse size can change from time to time in cfs_read (why?)
  }
  //exit here if http buffer was fully copied

  //fuse buffer full
  if (info->de->downld_buf.work_buf_size == info->de->downld_buf.fuse_read_size)
  {
    sem_getvalue(info->de->downld_buf.sem_list[SEM_FULL], &sem_val);
    //fuse buffer is full, http fully copied, signal cfs_read to return it in user space
    debugf(DBG_LEVEL_EXT, KMAG"write_callback_progrs: post full sem=%d",
           sem_val);
    sem_post(info->de->downld_buf.sem_list[SEM_FULL]);
    sem_getvalue(info->de->downld_buf.sem_list[SEM_EMPTY], &sem_val);
    debugf(DBG_LEVEL_EXT, KMAG
           "write_callback_progrs: wait [2] fuse buffer to get empty sem=%d", sem_val);
    sem_wait(info->de->downld_buf.sem_list[SEM_EMPTY]);
    debugf(DBG_LEVEL_EXT, KMAG
           "write_callback_progrs: done wait empty [2] work_buf=%lu",
           info->de->downld_buf.work_buf_size);
    //post to avoid being stuck on this callback
    sem_post(info->de->downld_buf.sem_list[SEM_EMPTY]);
  }
  else
  {
    debugf(DBG_LEVEL_EXT, KMAG
           "write_callback_progrs: incomplete fuse_buf, need more http data work_buf=%lu",
           info->de->downld_buf.work_buf_size);
    //post to avoid being stuck on this callback
    sem_post(info->de->downld_buf.sem_list[SEM_EMPTY]);
  }

  debugf(DBG_LEVEL_EXT, KMAG"exit: write_callback_progrs result=%lu", result);
  return result;
}

static size_t write_callback(void* ptr, size_t size, size_t nmemb, void* userp)
{
  struct segment_info* info = (struct segment_info*)userp;
  debugf(DBG_LEVEL_EXT, KMAG"write_callback: progressive=%d",
         info->de->is_progressive);
  //send data to fuse buffer
  if (info->de->is_progressive)
    write_callback_progressive(ptr, size, nmemb, userp);

  //write data to local cache file
  size_t result = rw_callback(fwrite2, ptr, size, nmemb, userp);
  if (result == 0 && !info->de->is_progressive)
  {
    //signal cfs_read to wake
    sem_post(info->de->downld_buf.sem_list[SEM_FULL]);
  }
  return result;
}

/*
   called during http operations, currently used only for debug purposes
   http://curl.haxx.se/libcurl/c/CURLOPT_XFERINFOFUNCTION.html
*/
int progress_callback_xfer(void* clientp, curl_off_t dltotal, curl_off_t dlnow,
                           curl_off_t ultotal, curl_off_t ulnow)
{
  struct curl_progress* myp = (struct curl_progress*)clientp;
  CURL* curl = myp->curl;
  double curtime = 0;
  double dspeed = 0, uspeed = 0;
  curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &curtime);
  curl_easy_getinfo(curl, CURLINFO_SPEED_DOWNLOAD, &dspeed);
  curl_easy_getinfo(curl, CURLINFO_SPEED_UPLOAD, &uspeed);
  /* under certain circumstances it may be desirable for certain functionality
     to only run every N seconds, in order to do this the transaction time can
     be used */
  //http://curl.haxx.se/cvssource/src/tool_cb_prg.c
  if ((curtime - myp->lastruntime) >= MINIMAL_PROGRESS_FUNCTIONALITY_INTERVAL)
  {
    myp->lastruntime = curtime;
    curl_off_t total;
    curl_off_t point;
    double frac, percent;
    total = dltotal + ultotal;
    point = dlnow + ulnow;
    frac = (double)point / (double)total;
    percent = frac * 100.0f;
    debugf(DBG_LEVEL_EXT, "TOTAL TIME: %.0f sec Down=%.0f Kbps UP=%.0f Kbps",
           curtime, dspeed / 1024, uspeed / 1024);
    debugf(DBG_LEVEL_EXT, "UP: %lld of %lld DOWN: %lld/%lld Completion %.1f %%",
           ulnow, ultotal, dlnow, dltotal, percent);
  }
  return 0;
}

/*
   for compatibility purposes, will be deprecated
   http://curl.haxx.se/libcurl/c/CURLOPT_PROGRESSFUNCTION.html
*/
int progress_callback(void* clientp, double dltotal, double dlnow,
                      double ultotal, double ulnow)
{
  return progress_callback_xfer(clientp, (curl_off_t)dltotal, (curl_off_t)dlnow,
                                (curl_off_t)ultotal, (curl_off_t)ulnow);
}

/*
   get the response from HTTP requests, mostly for debug purposes
   http://stackoverflow.com/questions/2329571/c-libcurl-get-output-into-a-string
   http://curl.haxx.se/libcurl/c/getinmemory.html
*/
size_t writefunc_callback(void* contents, size_t size, size_t nmemb,
                          void* userp)
{
  size_t realsize = size * nmemb;
  struct MemoryStruct* mem = (struct MemoryStruct*)userp;
  mem->memory = realloc(mem->memory, mem->size + realsize + 1);
  if (mem->memory == NULL)
  {
    /* out of memory! */
    debugf(DBG_LEVEL_NORM, KRED"writefunc_callback: realloc() failed");
    return 0;
  }
  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;
  return realsize;
}

// provides progressive data on upload for PUT/POST
static size_t progressive_read_callback(void* ptr, size_t size, size_t nmemb,
                                        void* userp)
{
  dir_entry* de = (dir_entry*)userp;
  debugf(DBG_LEVEL_EXTALL,
         "progressive_read_callback: entering for path(%s) size=%lu nmemb=%lu",
         de->full_name, size, nmemb);
  struct progressive_data_buf* upload_buf = &de->upload_buf;
  if (size * nmemb < 1)
  {
    debugf(DBG_LEVEL_EXT,
           "progressive_read_callback: "KYEL"exit as size*nmemb < 1");
    return 0;
  }
  if (upload_buf == NULL)
  {
    //just to be extra safe
    debugf(DBG_LEVEL_NORM,
           "progressive_read_callback: "KRED"got unexpected NULL data buffer");
    return 0;
  }
  size_t max_size_to_upload;
  int sem_val_empty, sem_val_full;
  upload_buf->upload_completed = false;
  if (upload_buf->offset == 0 && upload_buf->work_buf_size != 0)
  {
    //opening semaphores might not be needed - same process?
    if ((de->upload_buf.isempty_semaphore = sem_open(
        de->upload_buf.isempty_semaphore_name, O_CREAT, 0644, 0)) == SEM_FAILED)
    {
      int errsv = errno;
      debugf(DBG_LEVEL_NORM,
             KRED"progressive_read_callback: cannot open isempty_semaphore, err=%s",
             strerror(errsv));
    }
    else
      debugf(DBG_LEVEL_EXTALL,
             "progressive_read_callback: isempty_semaphore opened");
    if ((de->upload_buf.isfull_semaphore = sem_open(
        de->upload_buf.isfull_semaphore_name, O_CREAT, 0644, 0)) == SEM_FAILED)
    {
      int errsv = errno;
      debugf(DBG_LEVEL_NORM,
             KRED"progressive_read_callback: cannot open isfull_semaphore, err=%s",
             strerror(errsv));
    }
    else
      debugf(DBG_LEVEL_EXTALL, "progressive_read_callback: isfull_semaphore opened");
  }
  sem_getvalue(de->upload_buf.isempty_semaphore, &sem_val_empty);
  sem_getvalue(de->upload_buf.isfull_semaphore, &sem_val_full);
  debugf(DBG_LEVEL_EXTALL,
         "progressive_read_callback: prep to process, sizeleft=%lu, sem_val_empty=%d, sem_val_full=%d bufaddr=%lu",
         upload_buf->work_buf_size, sem_val_empty, sem_val_full, upload_buf->readptr);
  sem_wait(de->upload_buf.isfull_semaphore);
  max_size_to_upload = min(size * nmemb, de->upload_buf.work_buf_size);
  if (upload_buf->work_buf_size)
  {
    //todo: check if this mem copy can be removed
    //http://sourceforge.net/p/fuse/mailman/message/29119987/
    memcpy(ptr, upload_buf->readptr, max_size_to_upload);
    upload_buf->readptr += max_size_to_upload;
    upload_buf->work_buf_size -= max_size_to_upload;
    debugf(DBG_LEVEL_EXTALL,
           "progressive_read_callback: "KMAG"feed for upload data size=%lu",
           max_size_to_upload);
    if (upload_buf->work_buf_size == 0)
      sem_post(de->upload_buf.isempty_semaphore);
    else
      debugf(DBG_LEVEL_NORM,
             "progressive_read_callback: "KRED"chunked buffer sizeleft=%lu",
             upload_buf->work_buf_size);
    //debugf(DBG_LEVEL_EXTALL, KYEL"BUF=[%s]", (char*)ptr);
    //sleep_ms(2000);
    return max_size_to_upload;
  }
  sem_getvalue(de->upload_buf.isempty_semaphore, &sem_val_empty);
  sem_getvalue(de->upload_buf.isfull_semaphore, &sem_val_full);
  if (!upload_buf->write_completed)
  {
    debugf(DBG_LEVEL_NORM,
           "progressive_read_callback: " KRED
           "unexpected data upload done on write in progress, sem_val_empty=%d, sem_val_full=%d",
           sem_val_empty, sem_val_full);
  }
  //all data uploaded and write completed, exit
  debugf(DBG_LEVEL_EXT, KMAG
         "progressive_read_callback: full file upload completed");
  sem_post(de->upload_buf.isempty_semaphore);
  upload_buf->upload_completed = true;
  sem_close(de->upload_buf.isempty_semaphore);
  sem_close(de->upload_buf.isfull_semaphore);
  sem_unlink(de->upload_buf.isempty_semaphore_name);
  sem_unlink(de->upload_buf.isfull_semaphore_name);
  free(de->upload_buf.isempty_semaphore_name);
  free(de->upload_buf.isfull_semaphore_name);
  de->upload_buf.isempty_semaphore_name = NULL;
  de->upload_buf.isfull_semaphore_name = NULL;
  return 0; //no more data left to deliver
}

/*
   de_cached_entry must be NULL when the file is already in global cache
   otherwise point to a new dir_entry that will be added
   to the cache (usually happens on first dir load)
*/
static int send_request_size(const char* method, const char* path, void* fp,
                             xmlParserCtxtPtr xmlctx, curl_slist* extra_headers,
                             off_t file_size, int is_segment,
                             dir_entry* de_cached_entry, const char* unencoded_path)
{
  debugf(DBG_LEVEL_NORM, "send_request_size(%s) (%s)", method, path);
  char url[MAX_URL_SIZE];
  char orig_path[MAX_URL_SIZE];
  char header_data[MAX_HEADER_SIZE];
  char* slash;
  long response = -1;
  int tries = 0;
  double total_time;
  //needed to keep the response data, for debug purposes
  struct MemoryStruct chunk;
  if (!storage_url[0])
  {
    debugf(DBG_LEVEL_NORM, KRED"send_request with no storage_url?");
    abort();
  }
  while ((slash = strstr(path, "%2F")) || (slash = strstr(path, "%2f")))
  {
    *slash = '/';
    memmove(slash + 1, slash + 3, strlen(slash + 3) + 1);
  }
  while (*path == '/')
    path++;
  snprintf(url, sizeof(url), "%s/%s", storage_url, path);
  snprintf(orig_path, sizeof(orig_path), "/%s", path);
  // retry on HTTP failures
  for (tries = 0; tries < REQUEST_RETRIES; tries++)
  {
    chunk.memory = malloc(1);  /* will be grown as needed by the realloc above */
    chunk.size = 0;    /* no data at this point */
    CURL* curl = get_connection(path);
    if (rhel5_mode)
      curl_easy_setopt(curl, CURLOPT_CAINFO, RHEL5_CERTIFICATE_FILE);
    curl_slist* headers = NULL;
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HEADER, 0);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
    //reversed logic, 0 to enable progress
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS,
                     option_curl_progress_state ? 0 : 1);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, USER_AGENT);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, verify_ssl ? 1 : 0);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, verify_ssl);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10);
    curl_easy_setopt(curl, CURLOPT_VERBOSE, option_curl_verbose ? 1 : 0);
    add_header(&headers, "X-Auth-Token", storage_token);
    dir_entry* de;
    if (de_cached_entry == NULL)
      de = check_path_info(unencoded_path);
    else
    {
      // updating metadata on a file to be added to cache
      de = de_cached_entry;
      debugf(DBG_LEVEL_EXTALL, "send_request_size: using param dir_entry(%s)",
             orig_path);
    }
    if (!de)
      debugf(DBG_LEVEL_EXTALL,
             "send_request_size: file not in cache (%s)(%s)"KYEL"(%s)", orig_path, path,
             unencoded_path);
    else
    {
      // add headers to save utimens attribs only on upload
      if (!strcasecmp(method, "PUT") || !strcasecmp(method, "MKDIR"))
      {
        debugf(DBG_LEVEL_EXTALL, "send_request_size: Saving utimens for file %s",
               orig_path);
        //debugf(DBG_LEVEL_NORM, "File found in cache, path=%s", de->full_name);
        debugf(DBG_LEVEL_EXTALL,
               "send_request_size: Cached utime for path=%s ctime=%li.%li mtime=%li.%li atime=%li.%li",
               orig_path,
               de->ctime.tv_sec, de->ctime.tv_nsec, de->mtime.tv_sec, de->mtime.tv_nsec,
               de->atime.tv_sec, de->atime.tv_nsec);
        set_direntry_headers(de, headers);
      }
      else
        debugf(DBG_LEVEL_EXTALL, "send_request_size: not setting utimes (%s)",
               orig_path);
    }
    if (!strcasecmp(method, "MKDIR"))
    {
      curl_easy_setopt(curl, CURLOPT_UPLOAD, 1);
      curl_easy_setopt(curl, CURLOPT_INFILESIZE, 0);
      add_header(&headers, "Content-Type", "application/directory");
    }
    else if (!strcasecmp(method, "MKLINK") && fp)
    {
      rewind(fp);
      curl_easy_setopt(curl, CURLOPT_UPLOAD, 1);
      curl_easy_setopt(curl, CURLOPT_INFILESIZE, file_size);
      curl_easy_setopt(curl, CURLOPT_READDATA, fp);
      add_header(&headers, "Content-Type", "application/link");
    }
    else if (!strcasecmp(method, "PUT"))
    {
      //todo: read response headers and update file meta (etag & last-modified)
      //http://blog.chmouel.com/2012/02/06/anatomy-of-a-swift-put-query-to-object-server/
      debugf(DBG_LEVEL_EXT, "send_request_size: PUT (%s) size=%lu", orig_path,
             file_size);
      //don't do progressive on file creation, when size=0
      //http://curl.haxx.se/libcurl/c/post-callback.html
      if (option_enable_progressive_upload && file_size > 0)
      {
        curl_easy_setopt(curl, CURLOPT_UPLOAD, 1); //1=upload
        debugf(DBG_LEVEL_EXT, "send_request_size: progressive PUT (%s)", orig_path);
        //todo: placeholder to init progressing upload of a local file
        curl_easy_setopt(curl, CURLOPT_READFUNCTION, progressive_read_callback);
        curl_easy_setopt(curl, CURLOPT_READDATA, (void*)de);
      }
      else
      {
        curl_easy_setopt(curl, CURLOPT_UPLOAD, 1); //1=upload
        if (fp)
        {
          curl_easy_setopt(curl, CURLOPT_INFILESIZE, file_size);
          debugf(DBG_LEVEL_EXT,
                 "send_request_size: standard bulk PUT or create file (%s)", orig_path);
          curl_easy_setopt(curl, CURLOPT_READDATA, fp);
        }
        else
        {
          debugf(DBG_LEVEL_EXT,
                 "send_request_size: 0 content PUT, for updating meta (%s)", orig_path);
          curl_easy_setopt(curl, CURLOPT_INFILESIZE, 0);
        }
      }
      if (is_segment)
      {
        //fixme: progressive upload not working if file is segmented. conflict on read_callback.
        debugf(DBG_LEVEL_EXT,
               "send_request_size(%s): PUT is segmented, "KYEL"readcallback used", orig_path);
        curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);
      }
      //get the response for debug purposes.
      //fixme: carefull as conflicts with progressive download (GET)
      //send all data to this function
      curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc_callback);
      curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&chunk);
    }
    else if (!strcasecmp(method, "GET"))
    {
      if (is_segment)
      {
        debugf(DBG_LEVEL_EXT, "send_request_size: GET SEGMENT (%s)", orig_path);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
      }
      else if (fp)
      {
        debugf(DBG_LEVEL_EXT, "send_request_size: GET FP (%s)", orig_path);
        rewind(fp); // make sure the file is ready for a-writin'
        fflush(fp);
        if (ftruncate(fileno(fp), 0) < 0)
        {
          debugf(DBG_LEVEL_NORM,
                 KRED"ftruncate failed.  I don't know what to do about that.");
          abort();
        }
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, &header_get_meta_dispatch);
        // header sample by UThreadCurl.cpp, https://bitbucket.org/pamungkas5/bcbcurl/src
        // and http://www.codeproject.com/Articles/838366/BCBCurl-a-LibCurl-based-download-manager
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, (void*)de);
      }
      else if (xmlctx)
      {
        debugf(DBG_LEVEL_EXT, "send_request_size: GET XML (%s)", orig_path);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, xmlctx);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &xml_dispatch);
      }
      else
      {
        //asumming retrieval of headers only
        debugf(DBG_LEVEL_EXT, "send_request_size: GET HEADERS (%s)");
        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, &header_get_meta_dispatch);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, (void*)de);
        curl_easy_setopt(curl, CURLOPT_NOBODY, 1);
      }
    }
    else
    {
      debugf(DBG_LEVEL_EXT, "send_request_size: catch_all (%s)");
      // this posts an HEAD request (e.g. for statfs)
      curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
      curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, &header_dispatch);
    }
    //common code for all operations
    if (false)//option_curl_progress_state)
    {
      //enable progress reporting
      //http://curl.haxx.se/libcurl/c/progressfunc.html
      struct curl_progress prog;
      prog.lastruntime = 0;
      prog.curl = curl;
      curl_easy_setopt(curl, CURLOPT_PROGRESSFUNCTION, progress_callback);
      /* pass the struct pointer into the progress function */
      curl_easy_setopt(curl, CURLOPT_PROGRESSDATA, &prog);
    }
    /* add the headers from extra_headers if any */
    curl_slist* extra;
    for (extra = extra_headers; extra; extra = extra->next)
    {
      debugf(DBG_LEVEL_EXT, "adding header: %s", extra->data);
      headers = curl_slist_append(headers, extra->data);
    }
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    debugf(DBG_LEVEL_EXTALL, "status: send_request_size(%s) started HTTP(%s)",
           orig_path, url);
    curl_easy_perform(curl);

    char* effective_url;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response);
    curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &effective_url);
    curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &total_time);
    debugf(DBG_LEVEL_EXTALL,
           "status: send_request_size(%s) completed HTTP REQ:%s total_time=%.1f seconds",
           orig_path, effective_url, total_time);
    curl_slist_free_all(headers);
    curl_easy_reset(curl);
    return_connection(curl);
    if (response != 404 && (response >= 400 || response < 200))
    {
      /*
         Now, our chunk.memory points to a memory block that is chunk.size
         bytes big and contains the remote file.
      */
      //printf("%lu bytes retrieved\n", (long)chunk.size);
      debugf(DBG_LEVEL_NORM,
             KRED"send_request_size: error message, size=%lu, [HTTP %d] (%s)(%s)",
             (long)chunk.size, response, method, path);
      debugf(DBG_LEVEL_NORM, KRED"send_request_size: error message=[%s]",
             chunk.memory);
    }
    free(chunk.memory);
    if ((response >= 200 && response < 400) || (!strcasecmp(method, "DELETE")
        && response == 409))
    {
      debugf(DBG_LEVEL_NORM,
             "exit 0: send_request_size(%s) speed=%.1f sec "KCYN"(%s) "KGRN"[HTTP OK]",
             orig_path, total_time, method);
      return response;
    }
    //handle cases when file is not found, no point in retrying, should exit
    if (response == 404)
    {
      debugf(DBG_LEVEL_NORM,
             "send_request_size: not found error for (%s)(%s), ignored "KYEL"[HTTP 404]",
             method, path);
      return response;
    }
    else
    {
      debugf(DBG_LEVEL_NORM,
             "send_request_size: httpcode=%d (%s)(%s), retrying "KRED"[HTTP ERR]", response,
             method, path);
      //todo: try to list response content for debug purposes
      sleep(8 << tries); // backoff
    }
    if (response == 401 && !cloudfs_connect())   // re-authenticate on 401s
    {
      debugf(DBG_LEVEL_NORM, KYEL"exit 1: send_request_size(%s) (%s) [HTTP REAUTH]",
             path, method);
      return response;
    }
    if (xmlctx)
      xmlCtxtResetPush(xmlctx, NULL, 0, NULL, NULL);
  }
  debugf(DBG_LEVEL_NORM,
         "exit 2: send_request_size(%s)"KCYN"(%s) response=%d total_time=%.1f seconds",
         path, method, response, total_time);
  return response;
}

int send_request(char* method, const char* path, FILE* fp,
                 xmlParserCtxtPtr xmlctx, curl_slist* extra_headers, dir_entry* de_cached_entry,
                 const char* unencoded_path)
{
  long flen = 0;
  if (fp)
  {
    // if we don't flush the size will probably be zero
    fflush(fp);
    flen = cloudfs_file_size(fileno(fp));
  }
  return send_request_size(method, path, fp, xmlctx, extra_headers, flen, 0,
                           de_cached_entry, unencoded_path);
}

//thread that downloads or uploads large file segments
void* upload_segment(void* seginfo)
{
  struct segment_info* info = (struct segment_info*)seginfo;
  debugf(DBG_LEVEL_EXT,
         "upload_segment: started segment part=%d seginfo=%p",
         info->part, seginfo);
  //debugf(DBG_LEVEL_NORM,
  //       KMAG"upload_segment: started segment part=%d seginfo=%p fp=%p prog=%d",
  //       info->part, seginfo, info->fp, info->is_progressive);
  char seg_path[MAX_URL_SIZE] = { 0 };
  //set pointer to the segment start index in the complete
  //large file (several threads will write/read to/from same large file)
  fseek(info->fp, info->part * info->segment_size, SEEK_SET);
  //debugf(DBG_LEVEL_NORM,
  //      KMAG"upload_segment: step 1 part=%d seginfo=%p fp=%p prog=%d",
  //       info->part, seginfo, info->fp, info->is_progressive);
  setvbuf(info->fp, NULL, _IOFBF, DISK_BUFF_SIZE);
  //debugf(DBG_LEVEL_NORM,
  //       KMAG"upload_segment: step 2 part=%d seginfo=%p fp=%p prog=%d",
  //       info->part, seginfo, info->fp, info->is_progressive);
  snprintf(seg_path, MAX_URL_SIZE, "%s%08i", info->seg_base, info->part);
  /*debugf(DBG_LEVEL_NORM,
         KMAG"upload_segment: step 3 part=%d seginfo=%p fp=%p prog=%d",
         info->part, seginfo, info->fp, info->is_progressive);
  */
  char* encoded = curl_escape(seg_path, 0);
  debugf(DBG_LEVEL_EXT, KCYN "upload_segment(%s) part=%d size=%d seg_size=%d %s",
         info->method, info->part, info->size, info->segment_size, seg_path);
  int response = send_request_size(info->method, encoded, info, NULL, NULL,
                                   info->size, 1, NULL, seg_path);
  if (!(response >= 200 && response < 300))
    fprintf(stderr, "Segment %s failed with response %d", seg_path,
            response);
  curl_free(encoded);
  debugf(DBG_LEVEL_NORM,
         KMAG"upload_segment: completed, part=%d, http response=%d, progressive=%d",
         info->part, response, info->de->is_progressive);
  fclose(info->fp);
  // exit only when this is a child thread started on a segmented file
  if (!info->de->is_single_thread)
  {
    debugf(DBG_LEVEL_NORM,
           KMAG"upload_segment: closing thread part=%d, http response=%d, progressive=%d",
           info->part, response, info->de->is_progressive);
    pthread_exit(NULL);
  }
}

//thread that downloads or uploads large file segments
void* upload_segment_progressive(void* seginfo)
{
  struct segment_info* info = (struct segment_info*)seginfo;
  debugf(DBG_LEVEL_EXT,
         "upload_segment_progressive: started segment part=%d seginfo=%p",
         info->part, seginfo);
  //debugf(DBG_LEVEL_NORM,
  //       KMAG"upload_segment: started segment part=%d seginfo=%p fp=%p prog=%d",
  //       info->part, seginfo, info->fp, info->is_progressive);
  char seg_path[MAX_URL_SIZE] = { 0 };
  //changed!
  fseek(info->fp, 0, SEEK_SET);
  //debugf(DBG_LEVEL_NORM,
  //      KMAG"upload_segment: step 1 part=%d seginfo=%p fp=%p prog=%d",
  //       info->part, seginfo, info->fp, info->is_progressive);
  setvbuf(info->fp, NULL, _IOFBF, DISK_BUFF_SIZE);
  //debugf(DBG_LEVEL_NORM,
  //       KMAG"upload_segment: step 2 part=%d seginfo=%p fp=%p prog=%d",
  //       info->part, seginfo, info->fp, info->is_progressive);
  snprintf(seg_path, MAX_URL_SIZE, "%s%08i", info->seg_base, info->part);
  /*debugf(DBG_LEVEL_NORM,
    KMAG"upload_segment: step 3 part=%d seginfo=%p fp=%p prog=%d",
    info->part, seginfo, info->fp, info->is_progressive);
  */
  char* encoded = curl_escape(seg_path, 0);
  debugf(DBG_LEVEL_EXT, KCYN
         "upload_segment_progressive(%s) part=%d size=%d seg_size=%d %s",
         info->method, info->part, info->size, info->segment_size, seg_path);
  int response = send_request_size(info->method, encoded, info, NULL, NULL,
                                   info->size, 1, NULL, seg_path);
  if (!(response >= 200 && response < 300))
    fprintf(stderr, "Segment %s failed with response %d", seg_path,
            response);
  curl_free(encoded);
  debugf(DBG_LEVEL_NORM,
         KMAG"upload_segment_progressive: done, part=%d, http response=%d",
         info->part, response);
  fclose(info->fp);
  // exit only when this is a child thread started on a segmented file
  if (!info->de->is_single_thread)
  {
    debugf(DBG_LEVEL_NORM,
           KMAG"upload_segment_progressive: closing thread part=%d, http response=%d",
           info->part, response);
    pthread_exit(NULL);
  }
}

/*
  segment_size is the globabl config variable and size_of_segment is local
  TODO: return whether the upload/download failed or not
  Changed function to support progressive operations, where multiple threads are not
  desired as on download you want to get first segment faster than the rest
*/
void run_segment_threads_progressive(const char* method, char* seg_base,
                                     thread_job* job)
{
  debugf(DBG_LEVEL_NORM,
         "run_segment_threads_progressive(%s) segments=%d fp=%p size=%d",
         method, job->segments, job->fp, job->size_of_segments);
  char file_path[PATH_MAX] = { 0 };

  //debug_print_file_name(fp);
#ifdef __linux__
  snprintf(file_path, PATH_MAX, "/proc/self/fd/%d", fileno(job->fp));
  debugf(DBG_LEVEL_NORM, KMAG"run_segment_threads_progressive: filepath=%s",
         file_path);
#else
  //TODO: I haven't actually tested this
  if (fcntl(fileno(job->fp), F_GETPATH, file_path) == -1)
    fprintf(stderr, "couldn't get the path name\n");
  debugf(DBG_LEVEL_NORM, KMAG"run_segment_threads_progressive: ALT filepath=%s",
         file_path);
#endif
  int ret;
  bool multi_thread = false;
  FILE* seg_file;
  struct segment_info info;
  //find segment number containing needed offset. get offset from de (is it thread safe?)
  info.method = method;
  info.part = *job->segment_part;
  info.segment_size = *job->size_of_segments;
  info.size = *job->segment_part < *job->full_segments ? *job->size_of_segments :
              *job->remaining;
  info.seg_base = seg_base;
  info.de = job->de;
  dir_entry* de_seg = get_segment(job->de, *job->segment_part);
  if (job->de->is_segmented)
  {
    info.fp = de_seg->downld_buf.local_cache_file;
    /*int fno = fileno(info.fp);
      if (fno == -1)
      {
      debugf(DBG_LEVEL_NORM, KRED
             "run_segment_threads_progressive: segment fno is -1");
      sleep_ms(5000);
      }
      snprintf(file_path, PATH_MAX, "/proc/self/fd/%d", fno);
    */
    if (info.fp == NULL)
    {
      debugf(DBG_LEVEL_NORM, KRED
             "run_segment_threads_progressive: can't open segment cache file");
    }
    else
      debugf(DBG_LEVEL_NORM, KMAG"run_segment_threads_progressive: segm filepath=%s",
             file_path);
  }
  //info[i].de->is_progressive = true;
  info.de->is_single_thread = true;
  debugf(DBG_LEVEL_NORM, KMAG
         "run_segment_threads_progressive: progressive, single thread part=%d/%d, info=%p",
         job->segment_part, job->segments, info);
  upload_segment_progressive((void*) & (info));
  if (job->de->is_segmented)
  {
    //post to flush potential incomplete read
    sem_post(de_seg->downld_buf.sem_list[SEM_FULL]);
    //post with 0 data to ensure a force read exit
    sem_post(de_seg->downld_buf.sem_list[SEM_FULL]);
    //todo: check what close/clean ops with download_buf needs done
    //fflush(fp);
    //rewind(fp);
  }
  job->de->downld_buf.download_started = false;
  debugf(DBG_LEVEL_EXT, "exit: run_segment_threads_progressive(%s)", method);
}

/*
  segment_size is the globabl config variable and size_of_segment is local
  TODO: return whether the upload/download failed or not
  Changed function to support progressive operations, where multiple threads are not
  desired as on download you want to get first segment faster than the rest
*/
void run_segment_threads(const char* method, int segments, int full_segments,
                         int remaining,
                         FILE* fp, char* seg_base, int size_of_segments, dir_entry* de)
{
  debugf(DBG_LEVEL_NORM, "run_segment_threads(%s) segments=%d fp=%p", method,
         segments, fp);
  char file_path[PATH_MAX] = { 0 };
  struct segment_info* info = (struct segment_info*)
                              malloc(segments * sizeof(struct segment_info));
  pthread_t* threads = (pthread_t*)malloc(segments * sizeof(pthread_t));

  //debug_print_file_name(fp);
#ifdef __linux__
  snprintf(file_path, PATH_MAX, "/proc/self/fd/%d", fileno(fp));
  debugf(DBG_LEVEL_NORM, KMAG"run_segment_threads: filepath=%s", file_path);
#else
  //TODO: I haven't actually tested this
  if (fcntl(fileno(fp), F_GETPATH, file_path) == -1)
    fprintf(stderr, "couldn't get the path name\n");
  debugf(DBG_LEVEL_NORM, KMAG"run_segment_threads: ALT filepath=%s", file_path);
#endif
  sleep_ms(2000);
  int i, ret;
  bool multi_thread = false;

  for (i = 0; i < segments; i++)
  {
    info[i].method = method;
    info[i].fp = fopen(file_path, method[0] == 'G' ? "r+" : "r");
    debugf(DBG_LEVEL_NORM, KMAG"run_segment_threads() part=%d fp=%p", i,
           info[i].fp);
    info[i].part = i;
    info[i].segment_size = size_of_segments;
    info[i].size = i < full_segments ? size_of_segments : remaining;
    info[i].seg_base = seg_base;
    info[i].de = de;
    if (full_segments > MAX_SEGMENT_THREADS)
    {
      info[i].de->is_single_thread = true;
      info[i].de->is_progressive = false;
      debugf(DBG_LEVEL_NORM, KMAG
             "run_segment_threads: single thread part=%d/%d, info=%p",
             i, segments, info);
      upload_segment((void*) & (info[i]));
    }
    else
    {
      debugf(DBG_LEVEL_NORM, KMAG
             "run_segment_threads: going multi-threaded part=%d",
             i);
      info[i].de->is_progressive = false;
      info[i].de->is_single_thread = false;
      pthread_create(&threads[i], NULL, upload_segment, (void*) & (info[i]));
      multi_thread = true;
    }
  }
  if (multi_thread)
    for (i = 0; i < segments; i++)
    {
      if ((ret = pthread_join(threads[i], NULL)) != 0)
        fprintf(stderr, "error waiting for thread %d, status = %d\n", i, ret);
    }
  free(info);
  free(threads);
  debugf(DBG_LEVEL_EXT, "exit: run_segment_threads(%s)", method);
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

//checks on the cloud if this file (seg_path) have an associated segment folder
int internal_is_segmented(const char* seg_path, const char* object,
                          const char* parent_path)
{
  debugf(DBG_LEVEL_EXT, "internal_is_segmented seg_path(%s) object(%s)",
         seg_path, object);
  //try to avoid one additional http request for small files
  bool potentially_segmented;
  dir_entry* de = check_path_info(parent_path);
  if (!de)
  {
    //when files in folders are first loaded the path will not be yet in cache, so need
    //to force segment meta download for segmented files
    debugf(DBG_LEVEL_EXTALL,
           "internal_is_segmented: potentially YES as (%s) not in cache", parent_path);
    potentially_segmented = true;
  }
  else
  {
    //potentially segmented, assumption is that 0 size files are potentially segmented
    //while size>0 is for sure not segmented, so no point in making an expensive HTTP GET call
    //UPDATE: above assumption is invalid for segmented files composed of small segments (e.g. 10 MB)
    if (de->is_segmented)
      potentially_segmented = true;//force for files we know we're uploaded segmented
    else
      potentially_segmented = (de->size_on_cloud == 0 && !de->isdir) ? true : false;
    debugf(DBG_LEVEL_EXTALL,
           "internal_is_segmented: size_cloud=%lu isdir=%d for (%s)", de->size_on_cloud,
           de->isdir, parent_path);
  }
  debugf(DBG_LEVEL_EXT, "internal_is_segmented: potentially segmented=%d",
         potentially_segmented);
  dir_entry* seg_dir;
  if (potentially_segmented && cloudfs_list_directory(seg_path, &seg_dir))
  {
    if (seg_dir && seg_dir->isdir)
    {
      do
      {
        if (!strncmp(seg_dir->name, object, MAX_URL_SIZE))
        {
          debugf(DBG_LEVEL_EXT, "exit 0: internal_is_segmented(%s) "KGRN"TRUE",
                 seg_path);
          return 1;
        }
      }
      while ((seg_dir = seg_dir->next));
    }
  }
  debugf(DBG_LEVEL_EXT, "exit 1: internal_is_segmented(%s) "KYEL"FALSE",
         seg_path);
  return 0;
}

int is_segmented(const char* path)
{
  debugf(DBG_LEVEL_EXT, "is_segmented(%s)", path);
  char container[MAX_URL_SIZE] = "";
  char object[MAX_URL_SIZE] = "";
  char seg_base[MAX_URL_SIZE] = "";
  split_path(path, seg_base, container, object);
  char seg_path[MAX_URL_SIZE];
  snprintf(seg_path, MAX_URL_SIZE, "%s/%s_segments", seg_base, container);
  return internal_is_segmented(seg_path, object, path);
}

/*returns segmented file properties by parsing and retrieving the folder structure on the cloud
  added totalsize as parameter to return the file size on list directory for segmented files
  old implementation returns file size=0 (issue #91)
  populates parent file with link to segment list
*/
int format_segments(const char* path, char* seg_base,  long* segments,
                    long* full_segments, long* remaining, long* size_of_segments, long* total_size)
{
  debugf(DBG_LEVEL_EXT, "format_segments(%s) seg_base(%s)", path, seg_base);
  char container[MAX_URL_SIZE] = "";
  char object[MAX_URL_SIZE] = "";
  split_path(path, seg_base, container, object);
  char seg_path[MAX_URL_SIZE];
  snprintf(seg_path, MAX_URL_SIZE, "%s/%s_segments", seg_base, container);
  if (internal_is_segmented(seg_path, object, path))
  {
    //operations with segments
    //http://docs.openstack.org/developer/swift/overview_large_objects.html
    char manifest[MAX_URL_SIZE];
    //fixme: memory is not freed for seg_dir after cloudfs_list_directory()
    dir_entry* seg_dir;
    snprintf(manifest, MAX_URL_SIZE, "%s/%s", seg_path, object);
    debugf(DBG_LEVEL_EXTALL, "format_segments manifest(%s)", manifest);
    if (!cloudfs_list_directory(manifest, &seg_dir))
    {
      debugf(DBG_LEVEL_EXTALL, "exit 0: format_segments(%s)", path);
      return 0;
    }
    // snprintf seesaw between manifest and seg_path to get
    // the total_size and the segment size as well as the actual objects
    char* timestamp = seg_dir->name;
    snprintf(seg_path, MAX_URL_SIZE, "%s/%s", manifest, timestamp);
    debugf(DBG_LEVEL_EXTALL, "format_segments seg_path(%s)", seg_path);
    if (!cloudfs_list_directory(seg_path, &seg_dir))
    {
      debugf(DBG_LEVEL_EXTALL, "exit 1: format_segments(%s)", path);
      return 0;
    }
    char* str_size = seg_dir->name;//fixme: sometimes seg_dir is null
    snprintf(manifest, MAX_URL_SIZE, "%s/%s", seg_path, str_size);
    debugf(DBG_LEVEL_EXTALL, KMAG"format_segments manifest2(%s) size=%s", manifest,
           str_size);
    if (!cloudfs_list_directory(manifest, &seg_dir))
    {
      debugf(DBG_LEVEL_EXTALL, "exit 2: format_segments(%s)", path);
      return 0;
    }
    //following folder name actually represents the parent file size
    char* str_segment = seg_dir->name;
    snprintf(seg_path, MAX_URL_SIZE, "%s/%s", manifest, str_segment);
    debugf(DBG_LEVEL_EXTALL, KMAG"format_segments seg_path2(%s)", seg_path);
    //here is where we get a list with all segment files composing the parent large file
    if (!cloudfs_list_directory(seg_path, &seg_dir))
    {
      debugf(DBG_LEVEL_EXTALL, "exit 3: format_segments(%s)", path);
      return 0;
    }
    else
    {
      //save segments dir list into parent file entry
      //fixme: unsafe as it get's overwritten and data is lost
      dir_entry* de = check_path_info(path);
      if (de)
      {
        if (!de->segments)//free if a list already exists
          //cloudfs_free_dir_list(de->segments);
          de->segments = seg_dir;
      }
    }
    *total_size = strtoll(str_size, NULL, 10);
    *size_of_segments = strtoll(str_segment, NULL, 10);
    *remaining = *total_size % *size_of_segments;
    *full_segments = *total_size / *size_of_segments;
    *segments = *full_segments + (*remaining > 0);
    snprintf(manifest, MAX_URL_SIZE, "%s_segments/%s/%s/%s/%s/",
             container, object, timestamp, str_size, str_segment);
    char tmp[MAX_URL_SIZE];
    strncpy(tmp, seg_base, MAX_URL_SIZE);
    snprintf(seg_base, MAX_URL_SIZE, "%s/%s", tmp, manifest);
    debugf(DBG_LEVEL_EXT, KMAG"format_segments: seg_base=(%s)", seg_base);
    debugf(DBG_LEVEL_EXT,
           "exit 4: format_segments(%s) total=%d size_of_segments=%d remaining=%d, full_segments=%d segments=%d",
           path, *total_size, *size_of_segments, *remaining, *full_segments, *segments);
    return 1;
  }
  else
  {
    debugf(DBG_LEVEL_EXT, "exit 5: format_segments(%s) not segmented?", path);
    return 0;
  }
}

/*
   Public interface
*/

void cloudfs_init()
{
  LIBXML_TEST_VERSION
  xmlXPathInit();
  curl_global_init(CURL_GLOBAL_ALL);
  pthread_mutex_init(&pool_mut, NULL);
  curl_version_info_data* cvid = curl_version_info(CURLVERSION_NOW);
  // CentOS/RHEL 5 get stupid mode, because they have a broken libcurl
  if (cvid->version_num == RHEL5_LIBCURL_VERSION)
  {
    debugf(DBG_LEVEL_NORM, "RHEL5 mode enabled.");
    rhel5_mode = 1;
  }
  if (!strncasecmp(cvid->ssl_version, "openssl", 7))
  {
#ifdef HAVE_OPENSSL
    int i;
    ssl_lockarray = (pthread_mutex_t*)OPENSSL_malloc(CRYPTO_num_locks() *
                    sizeof(pthread_mutex_t));
    for (i = 0; i < CRYPTO_num_locks(); i++)
      pthread_mutex_init(&(ssl_lockarray[i]), NULL);
    CRYPTO_set_id_callback((unsigned long (*)())thread_id);
    CRYPTO_set_locking_callback((void (*)())lock_callback);
#endif
  }
  else if (!strncasecmp(cvid->ssl_version, "nss", 3))
  {
    // allow https to continue working after forking (for RHEL/CentOS 6)
    setenv("NSS_STRICT_NOFORK", "DISABLED", 1);
  }
}

void cloudfs_free()
{
  debugf(DBG_LEVEL_EXT, "Destroy mutex");
  pthread_mutex_destroy(&pool_mut);
  int n;
  for (n = 0; n < curl_pool_count; ++n)
  {
    debugf(DBG_LEVEL_EXT, "Cleaning curl conn %d", n);
    curl_easy_cleanup(curl_pool[n]);
  }
}


int file_is_readable(const char* fname)
{
  FILE* file;
  if ( file = fopen( fname, "r" ) )
  {
    fclose( file );
    return 1;
  }
  return 0;
}

const char* get_file_mimetype ( const char* path )
{
  if ( file_is_readable( path ) == 1 )
  {
    magic_t magic;
    const char* mime;
    magic = magic_open( MAGIC_MIME_TYPE );
    magic_load( magic, NULL );
    magic_compile( magic, NULL );
    mime = magic_file( magic, path );
    magic_close( magic );
    return mime;
  }
  const char* error = "application/octet-stream";
  return error;
}

/*
  progressive upload to cloud, works only for not segmented files
  todo: how to return upload status
*/
void cloudfs_object_upload_progressive(const char* path)
{
  debugf(DBG_LEVEL_EXT, "cloudfs_object_upload_progressive(%s)", path);
  char* encoded = curl_escape(path, 0);
  //mark file size = 1 to signal we have some data coming in
  int response = send_request_size("PUT", encoded, NULL, NULL, NULL, 1, 0, NULL,
                                   path);
  curl_free(encoded);
  debugf(DBG_LEVEL_EXT, "exit: cloudfs_object_upload_progressive(%s)", path);
  //return (response >= 200 && response < 300);
}

//uploads file to cloud
int cloudfs_object_read_fp(const char* path, FILE* fp)
{
  debugf(DBG_LEVEL_EXT, "cloudfs_object_read_fp(%s)", path);
  long flen;
  fflush(fp);
  const char* filemimetype = get_file_mimetype( path );
  // determine the size of the file and segment if it is above the threshhold
  fseek(fp, 0, SEEK_END);
  flen = ftell(fp);
  // delete the previously uploaded segments
  if (is_segmented(path))
  {
    if (!cloudfs_delete_object(path))
      debugf(DBG_LEVEL_NORM,
             KRED"cloudfs_object_read_fp: couldn't delete existing file");
    else
      debugf(DBG_LEVEL_EXT, KYEL"cloudfs_object_read_fp: deleted existing file");
  }
  struct timespec now;
  dir_entry* de = path_info(path);
  if (!de)
    debugf(DBG_LEVEL_EXT, "cloudfs_object_read_fp(%s) "KYEL"not in cache", path);
  //check if file is qualified to be segmented
  if (flen >= segment_above)
  {
    //segmenting file for upload, mark as segmented
    if (de)
      de->is_segmented = true;
    int i;
    long remaining = flen % segment_size;
    int full_segments = flen / segment_size;
    int segments = full_segments + (remaining > 0);
    // The best we can do here is to get the current time that way tools that
    // use the mtime can at least check if the file was changing after now
    clock_gettime(CLOCK_REALTIME, &now);
    char string_float[TIME_CHARS];
    snprintf(string_float, TIME_CHARS, "%lu.%lu", now.tv_sec, now.tv_nsec);
    char meta_mtime[TIME_CHARS];
    snprintf(meta_mtime, TIME_CHARS, "%f", atof(string_float));
    char seg_base[MAX_URL_SIZE] = "";
    char container[MAX_URL_SIZE] = "";
    char object[MAX_URL_SIZE] = "";
    split_path(path, seg_base, container, object);
    char manifest[MAX_URL_SIZE];
    snprintf(manifest, MAX_URL_SIZE, "%s_segments", container);
    // create the segments container
    cloudfs_create_directory(manifest);
    // reusing manifest
    // TODO: check how addition of meta_mtime in manifest impacts utimens implementation
    snprintf(manifest, MAX_URL_SIZE, "%s_segments/%s/%s/%ld/%ld/",
             container, object, meta_mtime, flen, segment_size);
    char tmp[MAX_URL_SIZE];
    strncpy(tmp, seg_base, MAX_URL_SIZE);
    snprintf(seg_base, MAX_URL_SIZE, "%s/%s", tmp, manifest);
    //uploading all segments in separate threads
    run_segment_threads("PUT", segments, full_segments, remaining, fp,
                        seg_base, segment_size, de);
    char* encoded = curl_escape(path, 0);
    curl_slist* headers = NULL;
    add_header(&headers, "x-object-manifest", manifest);
    //due to utimens changes, not needed anymore
    //add_header(&headers, "x-object-meta-mtime", meta_mtime);
    add_header(&headers, "Content-Length", "0");
    add_header(&headers, "Content-Type", filemimetype);
    //if path is encoded cache entry will not be found
    //complete upload (write parent file, 0 size?)
    int response = send_request_size("PUT", encoded, NULL, NULL, headers, 0, 0,
                                     NULL, path);
    curl_slist_free_all(headers);
    curl_free(encoded);
    debugf(DBG_LEVEL_EXT,
           "exit 0: cloudfs_object_read_fp(%s) uploaded ok, response=%d", path, response);
    return (response >= 200 && response < 300);
  }
  else
  {
    // assume enters here when file is composed of only one segment (small files)
    debugf(DBG_LEVEL_EXT, "cloudfs_object_read_fp(%s) "KYEL"unknown state", path);
  }
  rewind(fp);
  char* encoded = curl_escape(path, 0);

  //if path is encoded cache entry will not be found
  int response = send_request("PUT", encoded, fp, NULL, NULL, NULL, path);
  curl_free(encoded);
  debugf(DBG_LEVEL_EXT, "exit 1: cloudfs_object_read_fp(%s)", path);
  return (response >= 200 && response < 300);
}

/*
   download file from cloud and write to local file
*/
int cloudfs_object_write_fp(const char* path, FILE* fp)
{
  debugf(DBG_LEVEL_EXT, "cloudfs_object_write_fp(%s) fp=%p", path, fp);
  char* encoded = curl_escape(path, 0);
  char seg_base[MAX_URL_SIZE] = "";
  long segments;
  long full_segments;
  long remaining;
  long size_of_segments;
  long total_size;
  //checks if this file is a segmented one
  if (format_segments(path, seg_base, &segments, &full_segments, &remaining,
                      &size_of_segments, &total_size))
  {
    rewind(fp);
    fflush(fp);
    if (ftruncate(fileno(fp), 0) < 0)
    {
      debugf(DBG_LEVEL_NORM, KMAG
             "cloudfs_object_write_fp: ftruncate failed, aborting!");
      abort();
    }
    dir_entry* de = check_path_info(path);
    //download all segments from cloud to local file, wait until completed
    run_segment_threads("GET", segments, full_segments, remaining, fp,
                        seg_base, size_of_segments, de);
    debugf(DBG_LEVEL_EXT, "exit 0: cloudfs_object_write_fp(%s)", path);
    return 1;
  }

  //get not segmented file
  int response = send_request("GET", encoded, fp, NULL, NULL, NULL, path);
  curl_free(encoded);
  fflush(fp);
  if ((response >= 200 && response < 300) || ftruncate(fileno(fp), 0))
  {
    debugf(DBG_LEVEL_EXT, "exit 1: cloudfs_object_write_fp(%s)", path);
    return 1;
  }
  rewind(fp);
  debugf(DBG_LEVEL_EXT, "exit 2: cloudfs_object_write_fp(%s) " KRED" error",
         path);
  return 0;
}

/*
  progressive download from cloud
*/
void* cloudfs_object_downld_progressive(void* arg)// //const char* path)
{
  struct thread_job* job = arg;
  debugf(DBG_LEVEL_NORM, "cloudfs_object_downld_progressive(%s)",
         job->de->full_name);
  char* encoded = curl_escape(job->de->full_name, 0);
  char seg_base[MAX_URL_SIZE] = "";
  /*long segments;
    long full_segments;
    long remaining;
    long size_of_segments;
    long total_size;
  */
  //dir_entry* de = check_path_info(path);
  //FILE* fp = de->downld_buf.local_cache_file;

  //checks if this file is a segmented one
  /*if (format_segments(job->de->full_name, seg_base, &segments, &full_segments,
                      &remaining,
                      &size_of_segments, &total_size))
  */
  if (format_segments(job->de->full_name, seg_base, job->segments,
                      job->full_segments,
                      job->remaining,
                      job->size_of_segments, job->total_size))
  {
    debugf(DBG_LEVEL_NORM,
           "cloudfs_object_downld_progressive(%s): started segmented download fp=%p",
           job->de->full_name, job->fp);
    rewind(job->fp);
    fflush(job->fp);
    if (ftruncate(fileno(job->fp), 0) < 0)
    {
      debugf(DBG_LEVEL_NORM, KRED
             "cloudfs_object_downld_progressive: ftruncate failed, aborting!");
      abort();
    }
    //download all segments from cloud to local file, single or multi threaded
    run_segment_threads_progressive("GET", seg_base, job);
    debugf(DBG_LEVEL_NORM,
           KMAG"cloudfs_object_downld_progressive: post buffer signal full");


    debugf(DBG_LEVEL_NORM, "exit 0: cloudfs_object_downld_progressive(%s)",
           job->de->full_name);
    sleep_ms(5000);
    //return 1;
  }
  else
  {
    debugf(DBG_LEVEL_NORM,
           "cloudfs_object_downld_progressive(%s): started non-segmented download",
           job->de->full_name);
    //get not segmented file
    int response = send_request("GET", encoded, job->fp, NULL, NULL, NULL,
                                job->de->full_name);
    curl_free(encoded);
    fflush(job->fp);
    if ((response >= 200 && response < 300) || ftruncate(fileno(job->fp), 0))
    {
      debugf(DBG_LEVEL_NORM, "exit 1: cloudfs_object_downld_progressive(%s)",
             job->de->full_name);
      //return 1;
    }
    else
    {
      rewind(job->fp);
      debugf(DBG_LEVEL_NORM, "exit 2: cloudfs_object_downld_progressive(%s) "
             KRED"error", job->de->full_name);
      //return 0;
    }
  }
}

int cloudfs_object_truncate(const char* path, off_t size)
{
  char* encoded = curl_escape(path, 0);
  int response;
  if (size == 0)
  {
    FILE* fp = fopen("/dev/null", "r");
    response = send_request("PUT", encoded, fp, NULL, NULL, NULL, path);
    fclose(fp);
  }
  else
  {
    //TODO: this is busted
    response = send_request("GET", encoded, NULL, NULL, NULL, NULL, path);
  }
  curl_free(encoded);
  return (response >= 200 && response < 300);
}

//get metadata from cloud, like time attribs. create new entry if not cached yet.
//todo: not thread-safe?
void get_file_metadata(dir_entry* de)
{
  if ((de->size_on_cloud == 0 || de->is_segmented) && !de->isdir
      && !de->metadata_downloaded)
  {
    //this can be a potential segmented file, try to read segments size
    debugf(DBG_LEVEL_EXT, KMAG"get_file_metadata: get segments file=%s",
           de->full_name);
    char seg_base[MAX_URL_SIZE] = "";
    long segments;
    long full_segments;
    long remaining;
    long size_of_segments;
    long total_size;
    if (format_segments(de->full_name, seg_base, &segments, &full_segments,
                        &remaining,
                        &size_of_segments, &total_size))
    {
      de->size = total_size;
      de->segment_size = size_of_segments;
      de->is_segmented = true;
    }
  }
  else debugf(DBG_LEVEL_EXT,
                KCYN "get_file_metadata(%s) not looking for segments, size_cloud=%lu",
                de->full_name, de->size_on_cloud);
  if (option_get_extended_metadata)
  {
    debugf(DBG_LEVEL_EXT, KCYN "get_file_metadata(%s) size_cloud=%lu",
           de->full_name, de->size_on_cloud);
    //retrieve additional file metadata with a quick HEAD query
    char* encoded = curl_escape(de->full_name, 0);
    de->metadata_downloaded = true;
    int response = send_request("GET", encoded, NULL, NULL, NULL, de,
                                de->full_name);
    curl_free(encoded);
    debugf(DBG_LEVEL_EXT, KCYN "exit: get_file_metadata(%s)", de->full_name);
  }
  return;
}

//get list of folders from cloud
// return 1 for OK, 0 for error
int cloudfs_list_directory(const char* path, dir_entry** dir_list)
{
  debugf(DBG_LEVEL_EXT, "cloudfs_list_directory(%s)", path);
  char container[MAX_PATH_SIZE * 3] = "";
  char object[MAX_PATH_SIZE] = "";
  char last_subdir[MAX_PATH_SIZE] = "";
  int prefix_length = 0;
  int response = 0;
  int retval = 0;
  int entry_count = 0;
  *dir_list = NULL;
  xmlNode* onode = NULL, *anode = NULL, *text_node = NULL;
  xmlParserCtxtPtr xmlctx = xmlCreatePushParserCtxt(NULL, NULL, "", 0, NULL);
  if (!strcmp(path, "") || !strcmp(path, "/"))
  {
    path = "";
    strncpy(container, "/?format=xml", sizeof(container));
  }
  else
  {
    sscanf(path, "/%[^/]/%[^\n]", container, object);
    char* encoded_container = curl_escape(container, 0);
    char* encoded_object = curl_escape(object, 0);
    // The empty path doesn't get a trailing slash, everything else does
    char* trailing_slash;
    prefix_length = strlen(object);
    if (object[0] == 0)
      trailing_slash = "";
    else
    {
      trailing_slash = "/";
      prefix_length++;
    }
    snprintf(container, sizeof(container), "%s?format=xml&delimiter=/&prefix=%s%s",
             encoded_container, encoded_object, trailing_slash);
    curl_free(encoded_container);
    curl_free(encoded_object);
  }
  if ((!strcmp(path, "") || !strcmp(path, "/")) && *override_storage_url)
    response = 404;
  else
  {
    // this was generating 404 err on non segmented files (small files)
    response = send_request("GET", container, NULL, xmlctx, NULL, NULL, path);
  }
  if (response >= 200 && response < 300)
    xmlParseChunk(xmlctx, "", 0, 1);
  if (response >= 200 && response < 300 && xmlctx->wellFormed )
  {
    xmlNode* root_element = xmlDocGetRootElement(xmlctx->myDoc);
    for (onode = root_element->children; onode; onode = onode->next)
    {
      if (onode->type != XML_ELEMENT_NODE) continue;
      char is_object = !strcasecmp((const char*)onode->name, "object");
      char is_container = !strcasecmp((const char*)onode->name, "container");
      char is_subdir = !strcasecmp((const char*)onode->name, "subdir");
      if (is_object || is_container || is_subdir)
      {
        entry_count++;
        dir_entry* de = init_dir_entry();
        // useful docs on nodes here: http://developer.openstack.org/api-ref-objectstorage-v1.html
        if (is_container || is_subdir)
          de->content_type = strdup("application/directory");
        for (anode = onode->children; anode; anode = anode->next)
        {

          char* content = "<?!?>";
          for (text_node = anode->children; text_node; text_node = text_node->next)
          {
            if (text_node->type == XML_TEXT_NODE)
            {
              content = (char*)text_node->content;
              //debugf(DBG_LEVEL_NORM, "List dir anode=%s content=%s", (const char *)anode->name, content);
            }
            else
            {
              //debugf(DBG_LEVEL_NORM, "List dir anode=%s", (const char *)anode->name);
            }
          }
          debugf(DBG_LEVEL_EXTALL, KCYN"cloudfs_list_directory(%s): anode [%s]=[%s]",
                 path,
                 (const char*)anode->name, content);
          if (!strcasecmp((const char*)anode->name, "name"))
          {
            de->name = strdup(content + prefix_length);
            // Remove trailing slash
            char* slash = strrchr(de->name, '/');
            if (slash && (0 == *(slash + 1)))
              *slash = 0;
            if (asprintf(&(de->full_name), "%s/%s", path, de->name) < 0)
              de->full_name = NULL;
            //need a unique file id for semaphores
            de->full_name_hash = strdup(str2md5(de->full_name, strlen(de->full_name)));
          }
          if (!strcasecmp((const char*)anode->name, "bytes"))
          {
            //this will be overwriten with true size if file is segmented
            de->size = strtoll(content, NULL, 10);
            //need the original size to check if file is segmented
            de->size_on_cloud = strtoll(content, NULL, 10);
          }
          if (!strcasecmp((const char*)anode->name, "content_type"))
          {
            de->content_type = strdup(content);
            char* semicolon = strchr(de->content_type, ';');
            if (semicolon)
              *semicolon = '\0';
          }
          if (!strcasecmp((const char*)anode->name, "hash"))
            de->md5sum = strdup(content);
          if (!strcasecmp((const char*)anode->name, "last_modified"))
          {
            time_t last_modified_t = get_time_from_str_as_gmt(content);
            char local_time_str[64];
            time_t local_time_t = get_time_as_local(last_modified_t, local_time_str,
                                                    sizeof(local_time_str));
            de->last_modified = local_time_t;
            de->ctime.tv_sec = local_time_t;
            de->ctime.tv_nsec = 0;
            //initialise all fields with hubic last modified date in case the file does not have extended attributes set
            de->mtime.tv_sec = local_time_t;
            de->mtime.tv_nsec = 0;
            de->atime.tv_sec = local_time_t;
            de->atime.tv_nsec = 0;
            // TODO check if I can retrieve nano seconds?
          }
        }
        de->isdir = de->content_type &&
                    ((strstr(de->content_type, "application/folder") != NULL) ||
                     (strstr(de->content_type, "application/directory") != NULL));
        de->islink = de->content_type &&
                     ((strstr(de->content_type, "application/link") != NULL));
        if (de->isdir)
        {
          //i guess this will remove a dir_entry from cache if is there already?
          if (!strncasecmp(de->name, last_subdir, sizeof(last_subdir)))
          {
            //not sure when / why this is called, seems to generate many missed delete ops.
            //cloudfs_free_dir_list(de);
            debugf(DBG_LEVEL_EXT,
                   "cloudfs_list_directory: "KYEL"ignore "KNRM"cloudfs_free_dir_list(%s) command",
                   de->name);
            continue;
          }
          strncpy(last_subdir, de->name, sizeof(last_subdir));
        }
        de->next = *dir_list;
        *dir_list = de;
        char time_str[TIME_CHARS] = "";
        get_timespec_as_str(&(de->mtime), time_str, sizeof(time_str));
        debugf(DBG_LEVEL_NORM,
               KCYN"new dir_entry %s size=%d %s dir=%d lnk=%d mod=[%s] md5=%s",
               de->full_name, de->size, de->content_type, de->isdir, de->islink, time_str,
               de->md5sum);
        //attempt to read extended attributes on each dir entry
        //commented out as lazzy metadata read is implemented in cfs_getattr()
        //get_file_metadata(de);
      }
      else
        debugf(DBG_LEVEL_EXT, "unknown element: %s", onode->name);
    }
    retval = 1;
  }
  else if ((!strcmp(path, "") || !strcmp(path, "/")) && *override_storage_url)
  {
    entry_count = 1;
    debugf(DBG_LEVEL_NORM, "Init cache entry container=[%s]", public_container);
    dir_entry* de = init_dir_entry();
    de->name = strdup(public_container);
    struct tm last_modified;
    // TODO check what this default time means?
    strptime("1388434648.01238", "%FT%T", &last_modified);
    de->last_modified = mktime(&last_modified);
    de->content_type = strdup("application/directory");
    if (asprintf(&(de->full_name), "%s/%s", path, de->name) < 0)
      de->full_name = NULL;
    //need a unique file id for semaphores
    de->full_name_hash = strdup(str2md5(de->full_name, strlen(de->full_name)));
    de->isdir = 1;
    de->islink = 0;
    de->size = 4096;
    de->next = *dir_list;
    *dir_list = de;
    retval = 1;
  }
  xmlFreeDoc(xmlctx->myDoc);
  xmlFreeParserCtxt(xmlctx);
  debugf(DBG_LEVEL_EXT, "exit: cloudfs_list_directory(%s)", path);
  return retval;
}


int cloudfs_delete_object(const char* path)
{
  debugf(DBG_LEVEL_EXT, "cloudfs_delete_object(%s)", path);
  char seg_base[MAX_URL_SIZE] = "";
  long segments;
  long full_segments;
  long remaining;
  long size_of_segments;
  long total_size;
  if (format_segments(path, seg_base, &segments, &full_segments, &remaining,
                      &size_of_segments, &total_size))
  {
    int response;
    int i;
    char seg_path[MAX_URL_SIZE] = "";
    for (i = 0; i < segments; i++)
    {
      snprintf(seg_path, MAX_URL_SIZE, "%s%08i", seg_base, i);
      char* encoded = curl_escape(seg_path, 0);
      response = send_request("DELETE", encoded, NULL, NULL, NULL, NULL, seg_path);
      if (response < 200 || response >= 300)
      {
        debugf(DBG_LEVEL_EXT, "exit 1: cloudfs_delete_object(%s) response=%d", path,
               response);
        return 0;
      }
    }
  }
  char* encoded = curl_escape(path, 0);
  int response = send_request("DELETE", encoded, NULL, NULL, NULL, NULL, path);
  curl_free(encoded);
  int ret = (response >= 200 && response < 300);
  debugf(DBG_LEVEL_EXT, "status: cloudfs_delete_object(%s) response=%d", path,
         response);
  if (response == 409)
  {
    debugf(DBG_LEVEL_EXT, "status: cloudfs_delete_object(%s) NOT EMPTY", path);
    ret = -1;
  }
  return ret;
}

//fixme: this op does not preserve src attributes (e.g. will make rsync not work well)
// https://ask.openstack.org/en/question/14307/is-there-a-way-to-moverename-an-object/
// this operation also causes an HTTP 400 error if X-Object-Meta-FilePath value is larger than 256 chars
int cloudfs_copy_object(const char* src, const char* dst)
{
  debugf(DBG_LEVEL_EXT, "cloudfs_copy_object(%s, %s) lensrc=%d, lendst=%d", src,
         dst, strlen(src), strlen(dst));
  char* dst_encoded = curl_escape(dst, 0);
  char* src_encoded = curl_escape(src, 0);
  //convert encoded string (slashes are encoded as well) to encoded string with slashes
  char* slash;
  while ((slash = strstr(src_encoded, "%2F"))
         || (slash = strstr(src_encoded, "%2f")))
  {
    *slash = '/';
    memmove(slash + 1, slash + 3, strlen(slash + 3) + 1);
  }
  curl_slist* headers = NULL;
  add_header(&headers, "X-Copy-From", src_encoded);
  add_header(&headers, "Content-Length", "0");
  //get source file entry
  dir_entry* de_src = check_path_info(src);
  if (de_src)
    debugf(DBG_LEVEL_EXT, "status cloudfs_copy_object(%s, %s): src file found",
           src, dst);
  else
    debugf(DBG_LEVEL_NORM,
           KRED"status cloudfs_copy_object(%s, %s): src file NOT found", src, dst);
  //pass src metadata so that PUT will set time attributes of the src file
  int response = send_request("PUT", dst_encoded, NULL, NULL, headers, de_src,
                              dst);
  curl_free(dst_encoded);
  curl_free(src_encoded);
  curl_slist_free_all(headers);
  debugf(DBG_LEVEL_EXT, "exit: cloudfs_copy_object(%s,%s) response=%d", src, dst,
         response);
  return (response >= 200 && response < 300);
}

// http://developer.openstack.org/api-ref-objectstorage-v1.html#updateObjectMeta
int cloudfs_update_meta(dir_entry* de)
{
  int response = cloudfs_copy_object(de->full_name, de->full_name);
  return response;
}

//optimised with cache
int cloudfs_statfs(const char* path, struct statvfs* stat)
{
  time_t now = get_time_now();
  int lapsed = now - last_stat_read_time;
  if (lapsed > option_cache_statfs_timeout)
  {
    //todo: check why stat head request is always set to /, why not path?
    int response = send_request("HEAD", "/", NULL, NULL, NULL, NULL, "/");
    *stat = statcache;
    debugf(DBG_LEVEL_EXT,
           "exit: cloudfs_statfs (new recent values, was cached since %d seconds)",
           lapsed);
    last_stat_read_time = now;
    return (response >= 200 && response < 300);
  }
  else
  {
    debugf(DBG_LEVEL_EXT,
           "exit: cloudfs_statfs (old values, cached since %d seconds)", lapsed);
    return 1;
  }
}

int cloudfs_create_symlink(const char* src, const char* dst)
{
  char* dst_encoded = curl_escape(dst, 0);
  FILE* lnk = tmpfile();
  fwrite(src, 1, strlen(src), lnk);
  fwrite("\0", 1, 1, lnk);
  int response = send_request("MKLINK", dst_encoded, lnk, NULL, NULL, NULL, dst);
  curl_free(dst_encoded);
  fclose(lnk);
  return (response >= 200 && response < 300);
}

int cloudfs_create_directory(const char* path)
{
  debugf(DBG_LEVEL_EXT, "cloudfs_create_directory(%s)", path);
  char* encoded = curl_escape(path, 0);
  int response = send_request("MKDIR", encoded, NULL, NULL, NULL, NULL, path);
  curl_free(encoded);
  debugf(DBG_LEVEL_EXT, "cloudfs_create_directory(%s) response=%d", path,
         response);
  return (response >= 200 && response < 300);
}

off_t cloudfs_file_size(int fd)
{
  struct stat buf;
  fstat(fd, &buf);
  return buf.st_size;
}

void cloudfs_verify_ssl(int vrfy)
{
  verify_ssl = vrfy ? 2 : 0;
}

void cloudfs_option_get_extended_metadata(int option)
{
  option_get_extended_metadata  = option ? true : false;
}

void cloudfs_option_curl_verbose(int option)
{
  option_curl_verbose = option ? true : false;
}

static struct
{
  char client_id    [MAX_HEADER_SIZE];
  char client_secret[MAX_HEADER_SIZE];
  char refresh_token[MAX_HEADER_SIZE];
} reconnect_args;

void cloudfs_set_credentials(char* client_id, char* client_secret,
                             char* refresh_token)
{
  strncpy(reconnect_args.client_id    , client_id    ,
          sizeof(reconnect_args.client_id    ));
  strncpy(reconnect_args.client_secret, client_secret,
          sizeof(reconnect_args.client_secret));
  strncpy(reconnect_args.refresh_token, refresh_token,
          sizeof(reconnect_args.refresh_token));
}

struct htmlString
{
  char* text;
  size_t size;
};

static size_t writefunc_string(void* contents, size_t size, size_t nmemb,
                               void* data)
{
  struct htmlString* mem = (struct htmlString*) data;
  size_t realsize = size * nmemb;
  mem->text = realloc(mem->text, mem->size + realsize + 1);
  if (mem->text == NULL)   /* out of memory! */
  {
    perror(__FILE__);
    exit(EXIT_FAILURE);
  }
  memcpy(&(mem->text[mem->size]), contents, realsize);
  mem->size += realsize;
  return realsize;
}

char* htmlStringGet(CURL* curl)
{
  struct htmlString chunk;
  chunk.text = malloc(sizeof(char));
  chunk.size = 0;
  chunk.text[0] = '\0';//added to avoid valgrind unitialised warning
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &chunk);
  do
  {
    curl_easy_perform(curl);
  }
  while (chunk.size == 0);
  chunk.text[chunk.size] = '\0';
  return chunk.text;
}

/* thanks to http://devenix.wordpress.com */
char* unbase64(unsigned char* input, int length)
{
  BIO* b64, *bmem;
  char* buffer = (char*)malloc(length);
  memset(buffer, 0, length);
  b64 = BIO_new(BIO_f_base64());
  bmem = BIO_new_mem_buf(input, length);
  bmem = BIO_push(b64, bmem);
  BIO_set_flags(bmem, BIO_FLAGS_BASE64_NO_NL);
  BIO_read(bmem, buffer, length);
  BIO_free_all(bmem);
  return buffer;
}

int safe_json_string(json_object* jobj, char* buffer, char* name)
{
  int result = 0;
  if (jobj)
  {
    json_object* o;
    int found;
    found = json_object_object_get_ex(jobj, name, &o);
    if (found)
    {
      strcpy (buffer, json_object_get_string(o));
      result = 1;
    }
  }
  if (!result)
    debugf(DBG_LEVEL_NORM, KRED"HUBIC cannot get json field '%s'\n", name);
  return result;
}

int cloudfs_connect()
{
#define HUBIC_TOKEN_URL     "https://api.hubic.com/oauth/token"
#define HUBIC_CRED_URL      "https://api.hubic.com/1.0/account/credentials"
#define HUBIC_CLIENT_ID     (reconnect_args.client_id)
#define HUBIC_CLIENT_SECRET (reconnect_args.client_secret)
#define HUBIC_REFRESH_TOKEN (reconnect_args.refresh_token)
#define HUBIC_OPTIONS_SIZE  2048
  long response = -1;
  char url[HUBIC_OPTIONS_SIZE];
  char payload[HUBIC_OPTIONS_SIZE];
  struct json_object* json_obj;
  pthread_mutex_lock(&pool_mut);
  debugf(DBG_LEVEL_NORM, "Authenticating... (client_id = '%s')",
         HUBIC_CLIENT_ID);
  storage_token[0] = storage_url[0] = '\0';
  CURL* curl = curl_easy_init();
  /* curl default options */
  curl_easy_setopt(curl, CURLOPT_VERBOSE, debug);
  curl_easy_setopt(curl, CURLOPT_USERAGENT, USER_AGENT);
  curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, verify_ssl ? 1 : 0);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, verify_ssl);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10);
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10);
  curl_easy_setopt(curl, CURLOPT_FORBID_REUSE, 1);
  curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L);
  curl_easy_setopt(curl, CURLOPT_POST, 0L);
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc_string);
  /* Step 1 : request a token  - Not needed anymore with refresh_token */
  /* Step 2 : get request code - Not needed anymore with refresh_token */
  /* Step 3 : get access token */
  sprintf(payload, "refresh_token=%s&grant_type=refresh_token",
          HUBIC_REFRESH_TOKEN);
  curl_easy_setopt(curl, CURLOPT_URL, HUBIC_TOKEN_URL);
  curl_easy_setopt(curl, CURLOPT_POST, 1L);
  curl_easy_setopt(curl, CURLOPT_HEADER, 0);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, strlen(payload));
  curl_easy_setopt(curl, CURLOPT_USERNAME, HUBIC_CLIENT_ID);
  curl_easy_setopt(curl, CURLOPT_PASSWORD, HUBIC_CLIENT_SECRET);
  curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
  char* json_str = htmlStringGet(curl);
  json_obj = json_tokener_parse(json_str);
  debugf(DBG_LEVEL_NORM, "HUBIC TOKEN_URL result: '%s'\n", json_str);
  free(json_str);
  char access_token[HUBIC_OPTIONS_SIZE];
  char token_type[HUBIC_OPTIONS_SIZE];
  int expire_sec;
  int found;
  json_object* o;
  if (!safe_json_string(json_obj, access_token, "access_token"))
    return 0;
  if (!safe_json_string(json_obj, token_type, "token_type"))
    return 0;
  found = json_object_object_get_ex(json_obj, "expires_in", &o);
  expire_sec = json_object_get_int(o);
  debugf(DBG_LEVEL_NORM, "HUBIC Access token: %s\n", access_token);
  debugf(DBG_LEVEL_NORM, "HUBIC Token type  : %s\n", token_type);
  debugf(DBG_LEVEL_NORM, "HUBIC Expire in   : %d\n", expire_sec);
  /* Step 4 : request OpenStack storage URL */
  curl_easy_setopt(curl, CURLOPT_URL, HUBIC_CRED_URL);
  curl_easy_setopt(curl, CURLOPT_POST, 0L);
  curl_easy_setopt(curl, CURLOPT_HEADER, 0);
  curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_NONE);
  /* create the Bearer authentication header */
  curl_slist* headers = NULL;
  sprintf (payload, "Bearer %s", access_token);
  add_header(&headers, "Authorization", payload);
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  char token[HUBIC_OPTIONS_SIZE];
  char endpoint[HUBIC_OPTIONS_SIZE];
  char expires[HUBIC_OPTIONS_SIZE];
  json_str = htmlStringGet(curl);
  json_obj = json_tokener_parse(json_str);
  debugf(DBG_LEVEL_NORM, "CRED_URL result: '%s'\n", json_str);
  free(json_str);
  if (!safe_json_string(json_obj, token, "token"))
    return 0;
  if (!safe_json_string(json_obj, endpoint, "endpoint"))
    return 0;
  if (!safe_json_string(json_obj, expires, "expires"))
    return 0;
  /* set the global storage_url and storage_token, the only parameters needed for swift */
  strcpy (storage_url, endpoint);
  strcpy (storage_token, token);
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response);
  curl_easy_cleanup(curl);
  pthread_mutex_unlock(&pool_mut);
  return (response >= 200 && response < 300 && storage_token[0]
          && storage_url[0]);
}
