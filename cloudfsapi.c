#define _GNU_SOURCE
#include <stdio.h>
#include <magic.h>
#include <string.h>
#include <stdarg.h>
#include <stdarg.h>
#include <math.h>
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
#include <assert.h>
#include <signal.h>
#include <openssl/md5.h>
#include "commonfs.h"
#include "cloudfsapi.h"
#include "config.h"

#define RHEL5_LIBCURL_VERSION 462597
#define RHEL5_CERTIFICATE_FILE "/etc/pki/tls/certs/ca-bundle.crt"
#define MAX_FILES 10000
// size of buffer for writing to disk look at ioblksize.h in coreutils
// and try some values on your own system if you want the best performance
#define DISK_BUFF_SIZE 32768

static char storage_url[MAX_URL_SIZE];
static char storage_token[MAX_HEADER_SIZE];
static pthread_mutex_t pool_mut;
extern pthread_mutexattr_t segment_mutex_attr;
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
extern long option_min_speed_limit_progressive;
extern long option_min_speed_timeout;
extern char* temp_dir;
extern long option_read_ahead;
extern bool option_enable_chaos_test_monkey;
extern int option_fast_list_dir_limit;

static int rhel5_mode = 0;
extern int g_delete_thread_count;

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
    debugf(DBG_NORM, KRED"curl alloc failed");
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
  debugf(DBG_EXT, "add_header(%s:%s)", name, value);
  if (strlen(value) > 256)
  {
    debugf(DBG_NORM, KRED"add_header: warning, value size > 256 (%s:%s) ",
           name, value);
    //hubic will throw an HTTP 400 error on X-Copy-To operation
    //if X-Object-Meta-FilePath header value is larger than 256 chars
    //fix for issue #95 https://github.com/TurboGit/hubicfuse/issues/95
    if (!strcasecmp(name, "X-Object-Meta-FilePath"))
    {
      debugf(DBG_NORM,
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
  debugf(DBG_EXTALL, "Received time=%s.%s / %li.%li, existing=%li.%li",
         sec_value, nsec_value, sec, nsec, time_entry->tv_sec, time_entry->tv_nsec);
  if (sec != time_entry->tv_sec || nsec != time_entry->tv_nsec)
  {
    debugf(DBG_EXTALL,
           "Time changed, setting new time=%li.%li, existing was=%li.%li",
           sec, nsec, time_entry->tv_sec, time_entry->tv_nsec);
    time_entry->tv_sec = sec;
    time_entry->tv_nsec = nsec;
    char time_str_local[TIME_CHARS] = "";
    get_time_as_string((time_t)sec, nsec, time_str_local, sizeof(time_str_local));
    debugf(DBG_EXTALL, "header_set_time_from_str received time=[%s]",
           time_str_local);
    get_timespec_as_str(time_entry, time_str_local, sizeof(time_str_local));
    debugf(DBG_EXTALL, "header_set_time_from_str set time=[%s]",
           time_str_local);
  }
}

/*
   get segment metadata from HTTP response headers (usually after put to check md5)
*/
static size_t header_get_segment_meta(void* ptr, size_t size, size_t nmemb,
                                      void* userdata)
{
  size_t memsize = size * nmemb;
  char* header = (char*)alloca(memsize + 1);
  char* head = (char*)alloca(memsize + 1);
  char* value = (char*)alloca(memsize + 1);
  memcpy(header, (char*)ptr, memsize);
  header[memsize] = '\0';
  char storage[MAX_HEADER_SIZE];
  if (sscanf(header, "%[^:]: %[^\r\n]", head, value) == 2)
  {
    //sometimes etag is formated on hubic with "" (for segmented files?), check inconsistency!
    char* quote_lptr = strchr(value, '"');
    char* quote_rptr = strrchr(value, '"');
    if (quote_lptr || quote_rptr)
    {
      debugf(DBG_NORM, "header_get_segment_meta: " KRED
             "header value incorrectly formated on cloud, head=[%s], value=[%s]",
             head, value);
      if (quote_lptr && quote_rptr)
      {
        debugf(DBG_NORM, "header_get_segment_meta: " KYEL
               "fixing by stripping quotes, value=[%s]", value);
        removeSubstr(value, "\"");
        debugf(DBG_NORM, "header_get_segment_meta: " KGRN
               "fixed value=[%s]", value);
      }
      else
        debugf(DBG_NORM, "header_get_segment_meta: " KRED
               "unable to fix value=[%s]", value);
    }
    strncpy(storage, head, sizeof(storage));
    debugf(DBG_EXTALL, "header_get_segment_meta: " KCYN
           "head=[%s] val=[%s]", head, value);
    dir_entry* de = (dir_entry*)userdata;
    assert(de->name);
    if (de != NULL)
    {
      if (!strncasecmp(head, HEADER_TEXT_MD5HASH, memsize))
      {
        debugf(DBG_EXT, "header_get_segment_meta(%s): got md5sum=%s",
               de->name, value);
        if (de->md5sum == NULL)
        {
          de->md5sum = strdup(value);
          debugf(DBG_EXT, "header_get_segment_meta(%s): set md5sum=%s",
                 de->name, de->md5sum);
        }
        else if (strcasecmp(de->md5sum, value))
        {
          //todo: hash is different, usually on large segmented files
          debugf(DBG_NORM, "header_get_segment_meta(%s): " KYEL
                 "unexpected md5sum, cache=[%s] cloud=%s", de->name,
                 de->md5sum, value);
          //fixme: sometimes etag on hubic is incorrect,
          //noticed on segmented files or newly uploaded files (rigth after PUT)
          free(de->md5sum);
          de->md5sum = strdup(value);//this is ok for PUT
        }
      }
    }
    else abort();
  }
  else
  {
    //debugf(DBG_NORM, "Received unexpected header line");
  }
  return memsize;
}

/*
   get segment metadata from HTTP response headers (usually after put to check md5)
*/
static size_t header_get_container_meta(void* ptr, size_t size, size_t nmemb,
                                        void* userdata)
{
  size_t memsize = size * nmemb;
  char* header = (char*)alloca(memsize + 1);
  char* head = (char*)alloca(memsize + 1);
  char* value = (char*)alloca(memsize + 1);
  memcpy(header, (char*)ptr, memsize);
  header[memsize] = '\0';
  char storage[MAX_HEADER_SIZE];
  if (sscanf(header, "%[^:]: %[^\r\n]", head, value) == 2)
  {
    strncpy(storage, head, sizeof(storage));
    debugf(DBG_EXTALL, "header_get_container_meta: " KCYN
           "head=[%s] val=[%s]", head, value);
    if (userdata)
    {
      dir_entry* de = (dir_entry*)userdata;
      assert(de->name);
      assert(de->isdir);
      if (de != NULL)
      {
        if (!strncasecmp(head, HEADER_TEXT_CONTAINER_OBJ_COUNT, memsize))
        {
          //debugf(DBG_EXT, "header_get_container_meta: got objcount=%s",
          //       value);
          //de->object_count_recursive = atoi(value);
        }
      }
      else abort();
    }
    /* else
       debugf(DBG_EXT, KYEL
             "header_get_container_meta: NO USERDATA SPECIFIED (%s=%s)",
             head, value);
    */
  }
  else
  {
    //debugf(DBG_NORM, "Received unexpected header line");
  }
  return memsize;
}


/*
   get file metadata from HTTP response headers
*/
static size_t header_get_meta_dispatch(void* ptr, size_t size, size_t nmemb,
                                       void* userdata)
{
  size_t memsize = size * nmemb;
  char* header = (char*)alloca(memsize + 1);
  char* head = (char*)alloca(memsize + 1);
  char* value = (char*)alloca(memsize + 1);
  memcpy(header, (char*)ptr, memsize);
  header[memsize] = '\0';
  char storage[MAX_HEADER_SIZE];
  if (sscanf(header, "%[^:]: %[^\r\n]", head, value) == 2)
  {
    //sometimes etag is formated on hubic with "" (for segmented files?), check inconsistency!
    char* quote_lptr = strchr(value, '"');
    char* quote_rptr = strrchr(value, '"');
    if (quote_lptr || quote_rptr)
    {
      debugf(DBG_EXT, "header_get_meta_dispatch: "
             "header value incorrectly formated on cloud, head=[%s], value=[%s]",
             head, value);
      if (quote_lptr && quote_rptr)
      {
        debugf(DBG_EXT, "header_get_meta_dispatch: "
               "fixing by stripping quotes, value=[%s]", value);
        removeSubstr(value, "\"");
        debugf(DBG_EXT, "header_get_meta_dispatch: fixed value=[%s]", value);
      }
      else
        debugf(DBG_NORM, "header_get_meta_dispatch: " KRED
               "unable to fix value=[%s]", value);
    }
    strncpy(storage, head, sizeof(storage));
    debugf(DBG_EXTALL, "header_get_meta_dispatch: " KCYN
           "head=[%s] val=[%s]", head, value);
    dir_entry* de = (dir_entry*)userdata;
    if (de != NULL)
    {
      if (!strncasecmp(head, HEADER_TEXT_ATIME, memsize))
        header_set_time_from_str(value, &de->atime);
      else if (!strncasecmp(head, HEADER_TEXT_CTIME, memsize))
      {
        header_set_time_from_str(value, &de->ctime);
        header_set_time_from_str(value, &de->ctime_local);
      }
      else if (!strncasecmp(head, HEADER_TEXT_MTIME, memsize))
        header_set_time_from_str(value, &de->mtime);
      else if (!strncasecmp(head, HEADER_TEXT_CHMOD, memsize))
        de->chmod = atoi(value);
      else if (!strncasecmp(head, HEADER_TEXT_GID, memsize))
        de->gid = atoi(value);
      else if (!strncasecmp(head, HEADER_TEXT_UID, memsize))
        de->uid = atoi(value);
      else if (!strncasecmp(head, HEADER_TEXT_MD5HASH, memsize))
      {
        if (de->md5sum == NULL)
        {
          de->md5sum = strdup(value);
          debugf(DBG_EXT, "header_get_meta_dispatch(%s): set md5sum=%s",
                 de->name, de->md5sum);
        }
        else if (strcasecmp(de->md5sum, value))
        {
          if (strcasecmp(de->md5sum, MD5SUM_EMPTY_FILE))
          {
            //todo: hash is different, usually on large segmented files
            debugf(DBG_NORM, "header_get_meta_dispatch(%s): " KYEL
                   "hash difference, cache=%s cloud=%s",
                   de->name, de->md5sum, value);
          }
          free(de->md5sum);
          de->md5sum = strdup(value);
          debugf(DBG_EXT, "header_get_meta_dispatch(%s): set md5sum=%s",
                 de->name, de->md5sum);
        }
      }
      else if (!strncasecmp(head, HEADER_TEXT_IS_SEGMENTED, memsize))
      {
        //FIX: do not rely on this optional field
        de->is_segmented = atoi(value);
        debugf(DBG_EXT, "header_get_meta_dispatch: manual is_segmented=%d",
               de->is_segmented);
      }
      else if (!strncasecmp(head, HEADER_TEXT_MANIFEST, memsize))
      {
        free(de->manifest_cloud);
        char manifest[MAX_URL_SIZE] = "";
        //manifest path needs to start with / on HEAD (list) operations
        snprintf(manifest, MAX_URL_SIZE, "/%s", value);
        decode_path(manifest);
        de->manifest_cloud = strdup(manifest);
        debugf(DBG_EXT, "header_get_meta_dispatch: manifest=%s",
               de->manifest_cloud);
      }
      //else if (!strncasecmp(head, HEADER_TEXT_SEGMENT_SIZE, memsize))
      //  de->segment_size = atol(value);
      else if (!strncasecmp(head, HEADER_TEXT_FILE_SIZE, memsize))
      {
        //FIX: do not rely on this optional field
        if (de->is_segmented)
        {
          size_t file_size = atol(value);
          if (de->size != 0 && (file_size != de->size))
            debugf(DBG_EXT, KRED
                   "header_get_meta: file size needs update, curr=%lu meta=%lu",
                   de->size, file_size);
          debugf(DBG_EXT, "header_get_meta: set file size from meta=%lu",
                 file_size);
          de->lazy_segment_load = true;
          de->size = atol(value);
        }
      }
    }
    else abort();
    //debugf(DBG_EXT,
    //       "Unexpected NULL dir_entry on header(%s), file should be in cache already",
    //       storage);
  }
  else
  {
    //debugf(DBG_NORM, "Received unexpected header line");
  }
  return memsize;
}

void set_direntry_headers(dir_entry* de, curl_slist* headers)
{
  char atime_str_nice[TIME_CHARS] = "";
  char mtime_str_nice[TIME_CHARS] = "";
  char ctime_str_nice[TIME_CHARS] = "";
  get_timespec_as_str(&(de->atime), atime_str_nice, sizeof(atime_str_nice));
  debugf(DBG_EXTALL, KCYN"send_request_size: atime=[%s]", atime_str_nice);
  get_timespec_as_str(&(de->mtime), mtime_str_nice, sizeof(mtime_str_nice));
  debugf(DBG_EXTALL, KCYN"send_request_size: mtime=[%s]", mtime_str_nice);
  get_timespec_as_str(&(de->ctime), ctime_str_nice, sizeof(ctime_str_nice));
  debugf(DBG_EXTALL, KCYN"send_request_size: ctime=[%s]", ctime_str_nice);
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
  char is_segmented_str[INT_CHAR_LEN];// , seg_size_str[INT_CHAR_LEN];
  char file_size_str[INT_CHAR_LEN];
  snprintf(gid_str, INT_CHAR_LEN, "%d", de->gid);
  snprintf(uid_str, INT_CHAR_LEN, "%d", de->uid);
  snprintf(chmod_str, INT_CHAR_LEN, "%d", de->chmod);
  snprintf(is_segmented_str, INT_CHAR_LEN, "%d", de->is_segmented);
  //snprintf(seg_size_str, INT_CHAR_LEN, "%lu", de->segment_size);
  snprintf(file_size_str, INT_CHAR_LEN, "%lu", de->size);
  add_header(&headers, HEADER_TEXT_GID, gid_str);
  add_header(&headers, HEADER_TEXT_UID, uid_str);
  add_header(&headers, HEADER_TEXT_CHMOD, chmod_str);
  add_header(&headers, HEADER_TEXT_PRODUCED_BY, APP_ID);
  //fixme: this is not backward compatible if fields are used
  add_header(&headers, HEADER_TEXT_IS_SEGMENTED, is_segmented_str);
  //add_header(&headers, HEADER_TEXT_SEGMENT_SIZE, seg_size_str);
  //optional field, used to speed up getattr (avoid iteration on segments)
  add_header(&headers, HEADER_TEXT_FILE_SIZE, file_size_str);
}

/*
   write data to file from segmented download
*/
size_t fwrite2(void* ptr, size_t size, size_t nmemb, FILE* filep)
{
  //debugf(DBG_EXT, KCYN "fwrite2: size=%lu",
  //       size * nmemb);
  size_t result = fwrite((const void*)ptr, size, nmemb, filep);
  assert(result == size * nmemb);
  return result;
}

/*
   helper for uploading/downloading file
   detects file end
*/
static size_t rw_callback(size_t (*rw)(void*, size_t, size_t, FILE*),
                          void* ptr,
                          size_t size, size_t nmemb, void* userp)
{
  struct segment_info* info = (struct segment_info*)userp;
  size_t result;
  size_t mem = size * nmemb;
  if (mem < 1 || info->size_left < 1)
    result = 0;
  else
  {
    size_t amt_read = rw(ptr, 1, info->size_left < mem ? info->size_left : mem,
                         info->fp);
    info->size_left -= amt_read;
    info->size_processed += amt_read;
    result = amt_read;
  }
  assert((mem == result) || (info->size_processed == info->size_copy));
  return result;
}

size_t fread2(void* ptr, size_t size, size_t nmemb, FILE* filep)
{
  size_t result = fread(ptr, size, nmemb, filep);
  assert(result == size * nmemb);
  return result;
}
/*
   pass data for uploading multiple segments
*/
static size_t read_callback(void* ptr, size_t size, size_t nmemb, void* userp)
{
  struct segment_info* info = (struct segment_info*)userp;
  debugf(DBG_EXT, KMAG
         "read_callback: progressive=%d size=%lu current=%lu",
         info->de->is_progressive, size * nmemb, info->size_processed);
  return rw_callback(fread2, ptr, size, nmemb, userp);
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
  debugf(DBG_EXTALL,
         KMAG"write_callback_progrs: http_size=%lu rnd=%d", http_size, rnd);
  sleep_ms(rnd);
  struct segment_info* info = (struct segment_info*)userp;
  dir_entry* de;
  if (info->de->is_segmented)
    de = info->de_seg;
  else de = info->de;
  //todo: in case of progressive ops signal we have data to cfs_read
  debugf(DBG_EXT,
         KMAG"write_callback_progrs: http buffer full, fuse_size=%lu, wait empty",
         de->downld_buf.fuse_read_size);
  size_t data_copy_size;
  size_t http_ptr_index = 0;
  const void* src;
  const void* dest;
  int sem_val;
  sem_wait(de->downld_buf.sem_list[SEM_EMPTY]);
  //copy data to fuse buffer until is full OR until no data left to copy in http buf
  while (de->downld_buf.work_buf_size < de->downld_buf.fuse_read_size
         && (http_size - http_ptr_index > 0))
  {
    //data left needed
    data_copy_size = min(de->downld_buf.fuse_read_size -
                         de->downld_buf.work_buf_size,
                         http_size - http_ptr_index);
    src = ptr + http_ptr_index;
    dest = de->downld_buf.readptr + de->downld_buf.work_buf_size;
    memcpy((void*)dest, src, data_copy_size);
    de->downld_buf.work_buf_size += data_copy_size;
    http_ptr_index += data_copy_size;
    debugf(DBG_EXT, KCYN
           "write_callback_progrs: data_copy_size=%lu ptr=%lu src=%lu dest=%lu wrksize=%lu lefthttp=%lu",
           data_copy_size, ptr, src, dest, de->downld_buf.work_buf_size,
           http_size - http_ptr_index);
    if ((de->downld_buf.work_buf_size == de->downld_buf.fuse_read_size)
        && (http_size != http_ptr_index))
    {
      sem_getvalue(de->downld_buf.sem_list[SEM_FULL], &sem_val);
      //fuse buffer full, http data remains
      debugf(DBG_EXT, KMAG
             "write_callback_progrs: copied, post full, some http data left=%lu sem=%d",
             http_size - http_ptr_index, sem_val);
      sem_post(de->downld_buf.sem_list[SEM_FULL]);
      sem_getvalue(de->downld_buf.sem_list[SEM_EMPTY], &sem_val);
      debugf(DBG_EXT, KMAG
             "write_callback_progrs: wait [1] fuse buffer empty, sem=%d", sem_val);
      sem_wait(de->downld_buf.sem_list[SEM_EMPTY]);
      //after this work_buf_size = 0, set by cfs_read
      debugf(DBG_EXT, KMAG
             "write_callback_progrs: done wait empty [1] work_buf=%lu",
             de->downld_buf.work_buf_size);
    }
    if (data_copy_size == http_size)
    {
      //http buffer fully copied, more http data needed
      debugf(DBG_EXT, KMAG
             "write_callback_progrs: http buffer fully copied");
      break;
    }
    //fuse size can change from time to time in cfs_read (why?)
  }
  //exit here if http buffer was fully copied
  //fuse buffer full
  if (de->downld_buf.work_buf_size == de->downld_buf.fuse_read_size)
  {
    sem_getvalue(de->downld_buf.sem_list[SEM_FULL], &sem_val);
    //fuse buffer is full, http fully copied, signal cfs_read to return it in user space
    debugf(DBG_EXT, KMAG"write_callback_progrs: post full sem=%d",
           sem_val);
    sem_post(de->downld_buf.sem_list[SEM_FULL]);
    sem_getvalue(de->downld_buf.sem_list[SEM_EMPTY], &sem_val);
    debugf(DBG_EXT, KMAG
           "write_callback_progrs: wait [2] fuse buffer to get empty sem=%d", sem_val);
    sem_wait(de->downld_buf.sem_list[SEM_EMPTY]);
    debugf(DBG_EXT, KMAG
           "write_callback_progrs: done wait empty [2] work_buf=%lu",
           de->downld_buf.work_buf_size);
    //post to avoid being stuck on this callback
    sem_post(de->downld_buf.sem_list[SEM_EMPTY]);
  }
  else
  {
    debugf(DBG_EXT, KMAG
           "write_callback_progrs: incomplete fuse_buf, need more http data work_buf=%lu",
           de->downld_buf.work_buf_size);
    //post to avoid being stuck on this callback
    sem_post(de->downld_buf.sem_list[SEM_EMPTY]);
  }
  debugf(DBG_EXT, KMAG"exit: write_callback_progrs result=%lu", result);
  return result;
}

/*
   write downloaded data to file (& fuse memory?)
*/
static size_t write_callback(void* ptr, size_t size, size_t nmemb, void* userp)
{
  struct segment_info* info = (struct segment_info*)userp;
  //show progress
  debugf(DBG_EXTALL, KMAG "write_callback(%s): size=%lu current=%lu",
         info->de->full_name, size * nmemb, info->size_processed);
  //send data to fuse buffer
  if (info->de->is_progressive)
    write_callback_progressive(ptr, size, nmemb, userp);
  //write data to local cache file
  size_t result = rw_callback(fwrite2, ptr, size, nmemb, userp);
  assert(result == size * nmemb);
  if (result == 0 && !info->de->is_progressive)
  {
    debugf(DBG_EXT, KMAG "write_callback: post buf full, res=%lu, size=%lu",
           result, info->size_processed);
  }
  debugf(DBG_EXTALL, KMAG "write_callback(%s): result=%lu", info->de->full_name,
         result);
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
  //chaos test monkey
  if (myp->de && myp->de->upload_buf.feed_from_cache)
    myp->donotstop = true;

  if (option_enable_chaos_test_monkey && myp->de
      && ulnow >= 1000000//random_at_most(myp->de->segment_size)
      && myp->method == 'P' && myp->tries == 1 && (!myp->donotstop))
  {
    //force connection close
    debugf(DBG_TEST,
           "progress_callback_xfer(%s): aborting upload transfer at %lu bytes",
           myp->de ? myp->de->name : "nil", ulnow);
    myp->response = 503;
    return 1;
  }
  if (myp->last_ulnow != ulnow)
  {
    myp->last_ultime = curtime;
    myp->last_ulnow = ulnow;
  }
  if (myp->last_dlnow != dlnow)
  {
    myp->last_dltime = curtime;
    myp->last_dlnow = dlnow;
  }
  if (myp->method == 'P' && (curtime - myp->last_ultime > INTERNET_TIMEOUT_SEC))
  {
    debugf(DBG_NORM, KRED "progress_callback_xfer(%s): stopping stalled upload",
           myp->de ? myp->de->name : "nil");
    myp->response = 408;
    return 1;
  }
  if (myp->method == 'G' && (curtime  - myp->last_dltime > INTERNET_TIMEOUT_SEC))
  {
    debugf(DBG_NORM, KRED "progress_callback_xfer(%s): stopping stalled download",
           myp->de ? myp->de->name : "nil");
    myp->response = 408;
    return 1;
  }
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
    debugf(DBG_EXT, "(%s) TOTAL TIME: %.0f sec Down=%.0f Kbps UP=%.0f Kbps",
           (myp->de ? myp->de->name : "nil"), curtime, dspeed / 1024, uspeed / 1024);
    debugf(DBG_EXT, "(%s) UP: %lld of %lld DOWN: %lld/%lld Completion %.1f %%",
           (myp->de ? myp->de->name : "nil"), ulnow, ultotal, dlnow, dltotal, percent);
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
    debugf(DBG_NORM, KRED"writefunc_callback: realloc() failed");
    return 0;
  }
  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;
  return realsize;
}

// provides progressive data on upload for PUT/POST
static size_t progressive_upload_callback(void* ptr, size_t size, size_t nmemb,
    void* userp)
{
  dir_entry* de = (dir_entry*)userp;
  assert(de);
  assert(de->upload_buf.sem_list[SEM_FULL]);
  size_t http_buf_size = size * nmemb;
  struct progressive_data_buf* upload_buf = &de->upload_buf;
  assert(upload_buf);
  int sem_val1, sem_val2;
  sem_getvalue(de->upload_buf.sem_list[SEM_FULL], &sem_val1);
  sem_getvalue(de->upload_buf.sem_list[SEM_FULL], &sem_val2);
  debugf(DBG_EXTALL,
         "prog_upld_callb(%s): entering size=%lu semfull=%d semempty=%d",
         de->name, size * nmemb, sem_val1, sem_val2);
  if (http_buf_size < 1)
  {
    debugf(DBG_EXT, "prog_upld_callb: " KYEL "exit, size*nmemb < 1");
    return 0;
  }
  size_t max_size_to_upload;
  int sem_val_empty, sem_val_full;
  //wait to get fuse buffer data
  //fixme: sometimes freezes here, on HTTP 503 or after data feed from cache
  sem_wait(de->upload_buf.sem_list[SEM_FULL]);
  //ensure we upload no more than fuse buf available
  max_size_to_upload = min(http_buf_size, de->upload_buf.work_buf_size);
  //ensure we upload up to max segment size
  max_size_to_upload = min(max_size_to_upload,
                           de->segment_size - de->upload_buf.size_processed);
  debugf(DBG_EXTALL,
         "prog_upld_callb(%s): full, sizeproc=%lu workbuf=%lu upsize=%lu ptr=%p",
         de->name, upload_buf->size_processed, upload_buf->work_buf_size,
         max_size_to_upload, upload_buf->readptr);
  if (max_size_to_upload > 0)
  {
    //todo: check if this mem copy can be optimised
    //http://sourceforge.net/p/fuse/mailman/message/29119987/
    //copy to http upload buffer
    memcpy(ptr, upload_buf->readptr, max_size_to_upload);
    //compute segment md5sum only is this is a segment,
    //as parent md5 is done in cfs_write
    if (de->parent)
      assert(update_job_md5(de->job, upload_buf->readptr, max_size_to_upload));
    //compute whole file md5sum. check if de = segment or main file
    assert(update_job_md5(de->parent ? de->parent->job2 : de->job2,
                          upload_buf->readptr, max_size_to_upload));
    upload_buf->readptr += max_size_to_upload;
    upload_buf->work_buf_size -= max_size_to_upload;
    upload_buf->size_processed += max_size_to_upload;
    debugf(DBG_EXTALL,
           "prog_upld_callb(%s): sent http data size=%lu workb=%lu",
           de->name, max_size_to_upload, de->upload_buf.work_buf_size);
    sem_post(de->upload_buf.sem_list[SEM_EMPTY]);
    return max_size_to_upload;
  }
  //all data uploaded and write completed, exit
  debugf(DBG_EXT, KMAG
         "prog_upld_callb(%s): upload_ok uplen=%lu szproc=%lu workb=%lu",
         de->name, max_size_to_upload, upload_buf->size_processed,
         de->upload_buf.work_buf_size);
  return 0;
}

/*
   called when connection is closed, both on success or error
*/
/*
   int progressive_closesocket_callback(void* clientp, curl_socket_t item)
   {
   debugf(DBG_EXT, KMAG "progressive_closesocket_callback: closing");

   dir_entry* de = (dir_entry*)clientp;
   assert(de);

   //signal cfs_write and cfs_flush we're done
   if (de->upload_buf.sem_list[SEM_EMPTY])
   {
    sem_post(de->upload_buf.sem_list[SEM_EMPTY]);
    //sleep_ms(100);
    sem_post(de->upload_buf.sem_list[SEM_EMPTY]);
    //sleep_ms(100);
   }
   debugf(DBG_EXT, KMAG "progressive_closesocket_callback: closed %s",
         de->name);
   }
*/

/*
   if de_seg != null assumes this sends a segment request
*/
static int send_request_size(const char* method, const char* encoded_path,
                             void* fp, xmlParserCtxtPtr xmlctx,
                             curl_slist* extra_headers, off_t file_size,
                             int is_segment, dir_entry* de, dir_entry* de_seg)
{
  debugf(DBG_NORM,
         "send_request_size(%s) size=%lu is_seg=%d (%s) de=%p seg_de=%p %s:%s",
         method, file_size, is_segment, encoded_path, de, de_seg,
         (de ? de->name : "nil"), (de_seg ? de_seg->name : "nil"));
  debugf(DBG_EXT,
         "send_request_size: md5sums de=%s de_seg=%s",
         (de ? de->md5sum : "nil"), (de_seg ? de_seg->md5sum : "nil"));
  char url[MAX_URL_SIZE];
  char header_data[MAX_HEADER_SIZE];
  char* slash;
  long response = -1;
  int tries = 0;
  double total_time;
  bool is_download = false;
  bool is_upload = false;
  double size_downloaded = 0;
  double size_uploaded = 0;
  struct segment_info* info = NULL;
  //needed to keep the response data, for debug purposes
  struct MemoryStruct chunk;
  assert(storage_url[0]);
  dir_entry* de_tmp = de_seg ? de_seg : de;
  char* path, *orig_path;
  const char* print_path;
  if (de_seg != NULL)
  {
    path = curl_escape(de_seg->full_name, 0);
    print_path = de_seg->full_name;
  }
  else if (de != NULL)
  {
    path = curl_escape(de->full_name, 0);
    print_path = de->full_name;
  }
  else
  {
    path = (char*)encoded_path;
    print_path = encoded_path;
  }
  orig_path = path; //copy to be freed ok as path ptr will change
  decode_path(path);
  //remove "/" prefix
  while (*path == '/')
    path++;
  snprintf(url, sizeof(url), "%s/%s", storage_url, path);
  //for progress reporting
  //http://curl.haxx.se/libcurl/c/progressfunc.html
  struct curl_progress prog;
  prog.lastruntime = 0;
  prog.tries = 0;
  prog.de = de_seg ? de_seg : de;
  prog.donotstop = false;
  prog.last_ulnow = 0;
  prog.last_dlnow = 0;
  // retry on HTTP failures
  for (tries = 0; tries < REQUEST_RETRIES; tries++)
  {
    debugf(DBG_EXT, "send_request_size(%s): try #%d/%d", print_path, tries,
           REQUEST_RETRIES);
    chunk.memory = malloc(1);  /* will be grown as needed by the realloc above */
    chunk.size = 0;    /* no data at this point */
    CURL* curl = get_connection(path);
    if (rhel5_mode)
      curl_easy_setopt(curl, CURLOPT_CAINFO, RHEL5_CERTIFICATE_FILE);
    curl_slist* headers = NULL;
    assert(curl_easy_setopt(curl, CURLOPT_URL, url) == CURLE_OK);
    assert(curl_easy_setopt(curl, CURLOPT_HEADER, 0L) == CURLE_OK);
    assert(curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L) == CURLE_OK);
    //reversed logic, 0 to enable progress
    assert(curl_easy_setopt(curl, CURLOPT_NOPROGRESS,
                            option_curl_progress_state ? 0L : 1L) == CURLE_OK);
    assert(curl_easy_setopt(curl, CURLOPT_USERAGENT, USER_AGENT) == CURLE_OK);
    assert(curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER,
                            verify_ssl ? 1L : 0L) == CURLE_OK);
    assert(curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, verify_ssl) == CURLE_OK);
    assert(curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 20L) == CURLE_OK);
    assert(curl_easy_setopt(curl, CURLOPT_VERBOSE,
                            option_curl_verbose ? 1L : 0L) == CURLE_OK);
    assert(curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L) == CURLE_OK);
    assert(curl_easy_setopt(curl, CURLOPT_TCP_KEEPIDLE, 60L) == CURLE_OK);
    assert(curl_easy_setopt(curl, CURLOPT_TCP_KEEPINTVL, 60L) == CURLE_OK);
    //assert(curl_easy_setopt(curl, CURLOPT_TCP_NODELAY, 1) == CURLE_OK);
    //disable sigpipe errors, http://curl.haxx.se/mail/lib-2013-03/0123.html
    //assert(curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L) == CURLE_OK);
    //if previous error was 0 (usually on SSL timeouts), try a fresh connect
    /* if (response == 0)
       assert(curl_easy_setopt(curl, CURLOPT_FRESH_CONNECT, 1) == CURLE_OK);
       else
       assert(curl_easy_setopt(curl, CURLOPT_FRESH_CONNECT, 0) == CURLE_OK);
    */
    add_header(&headers, "X-Auth-Token", storage_token);
    // add headers to save utimens attribs only on upload
    if (!strcasecmp(method, HTTP_PUT) //|| !strcasecmp(method, "MKDIR")
        || !strcasecmp(method, HTTP_POST))
    {
      //debugf(DBG_EXTALL, "send_request_size: set utimens for file %s",
      //       orig_path);
      //on rename de is null
      if (de)
      {
        //debugf(DBG_EXTALL,
        //       "send_request_size: utime is path=%s ctime=%li.%li mtime=%li.%li atime=%li.%li",
        //       orig_path,
        //       de->ctime.tv_sec, de->ctime.tv_nsec, de->mtime.tv_sec, de->mtime.tv_nsec,
        //       de->atime.tv_sec, de->atime.tv_nsec);
        set_direntry_headers(de, headers);
      }
    }
    //else
    //  debugf(DBG_EXTALL, "send_request_size: not setting utimes (%s)",
    //         orig_path);
    if (!strcasecmp(method, "MKDIR"))
    {
      assert(curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L) == CURLE_OK);
      assert(curl_easy_setopt(curl, CURLOPT_INFILESIZE, 0L) == CURLE_OK);
      add_header(&headers, "Content-Type", "application/directory");
    }
    else if (!strcasecmp(method, HTTP_POST))
    {
      //used to update file meta
      debugf(DBG_EXT, "send_request_size: POST (%s)", orig_path);
      assert(curl_easy_setopt(curl, CURLOPT_POST, 1L) == CURLE_OK);
      assert(curl_easy_setopt(curl, CURLOPT_INFILESIZE, 0L) == CURLE_OK);
      //does not work in ubuntu
//#ifdef CURLOPT_EXPECT_100_TIMEOUT_MS
      assert(curl_easy_setopt(curl, CURLOPT_EXPECT_100_TIMEOUT_MS,
                              10000L) == CURLE_OK);
//#else
//      debugf(DBG_ERR, KRED "curl CURLOPT_EXPECT_100_TIMEOUT_MS not found");
//#endif
      //curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, &header_dispatch);
      //add_header(&headers, "Transfer-Encoding", "chunked");
      //add_header(&headers, "Expect", "");
    }
    else if (!strcasecmp(method, "MKLINK") && fp)
    {
      rewind(fp);
      assert(curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L) == CURLE_OK);
      assert(curl_easy_setopt(curl, CURLOPT_INFILESIZE, file_size) == CURLE_OK);
      assert(curl_easy_setopt(curl, CURLOPT_READDATA, fp) == CURLE_OK);
      add_header(&headers, "Content-Type", "application/link");
    }
    else if (!strcasecmp(method, HTTP_PUT))
    {
      is_upload = true;
      //todo: read response headers and update file meta (etag & last-modified)
      //http://blog.chmouel.com/2012/02/06/anatomy-of-a-swift-put-query-to-object-server/
      debugf(DBG_EXT, "send_request_size: enter PUT (%s) size=%lu de=%p",
             orig_path, file_size, de);
      //don't do progressive on file creation, when size=0 (why?)
      //http://curl.haxx.se/libcurl/c/post-callback.html
      if (option_enable_progressive_upload && file_size > 0)
      {
        assert(de);
        //do i need this as de_seg is null for first seg file?
        //if (de->is_segmented)
        //  assert(de_seg);
        assert(curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L) == CURLE_OK);
        debugf(DBG_EXT, "send_request_size: progressive PUT (%s)", orig_path);
        assert(curl_easy_setopt(curl, CURLOPT_READFUNCTION,
                                progressive_upload_callback) == CURLE_OK);
        if (de_seg)
        {
          assert(curl_easy_setopt(curl, CURLOPT_READDATA, (void*)de_seg) == CURLE_OK);
          curl_easy_setopt(curl, CURLOPT_HEADERDATA, (void*)de_seg);
          curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, &header_get_segment_meta);
        }
        else if (de)
        {
          assert(curl_easy_setopt(curl, CURLOPT_READDATA, (void*)de) == CURLE_OK);
          curl_easy_setopt(curl, CURLOPT_HEADERDATA, (void*)de);
          curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, &header_get_meta_dispatch);
        }
      }
      else//not progressive
      {
        curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
        if (fp)
        {
          assert(curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE,
                                  file_size) == CURLE_OK);
          debugf(DBG_EXT, "send_request_size: standard PUT (%s)",
                 orig_path);
          assert(curl_easy_setopt(curl, CURLOPT_READDATA,
                                  fp) == CURLE_OK); //actually infoseg
          assert(curl_easy_setopt(curl, CURLOPT_READFUNCTION,
                                  read_callback) == CURLE_OK);
        }
        else//no fp
        {
          debugf(DBG_EXT, "send_request_size: 0 size PUT, update meta (%s)",
                 orig_path);
          assert(curl_easy_setopt(curl, CURLOPT_INFILESIZE, 0L) == CURLE_OK);
        }
      }
      if (is_segment)
      {
        //fixme: progressive upload not working if file is segmented. conflict on read_callback?
        debugf(DBG_EXT, "send_request_size(%s): PUT is segmented, "
               KYEL "readcallback used", orig_path);
        assert(curl_easy_setopt(curl, CURLOPT_READFUNCTION,
                                read_callback) == CURLE_OK);
      }
      //get the response for debug purposes.
      //send all data to this function
      assert(curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
                              writefunc_callback) == CURLE_OK);
      assert(curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&chunk) == CURLE_OK);

      //interrupt a slow download as this could make the next attempt faster
      //due to hubic throtling. but do this only for half of the tries
      if (option_min_speed_limit_progressive > 0 && tries <= (REQUEST_RETRIES / 2))
      {
        curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT,
                         option_min_speed_limit_progressive);
        curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, option_min_speed_timeout);
      }
    }
    else if (!strcasecmp(method, HTTP_GET))
    {
      curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
      //reset local cache md5sum on file retrieval
      //avoid reseting de on segments download
      if (de_seg)
        free_de_before_get(de_seg);
      else if (de)
        free_de_before_get(de);
      if (xmlctx)
      {
        debugf(DBG_EXT, "send_request_size: GET XML (%s)", print_path);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, xmlctx);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &xml_dispatch);
        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, &header_get_container_meta);
        if (de_seg)
          curl_easy_setopt(curl, CURLOPT_HEADERDATA, (void*)info->de_seg);
        else if (de)
          curl_easy_setopt(curl, CURLOPT_HEADERDATA, (void*)info->de);
        else curl_easy_setopt(curl, CURLOPT_HEADERDATA, NULL);
      }
      else if (fp)//is_segment)
      {
        is_download = true;
        info = (struct segment_info*)fp;
        if (is_segment)
        {
          debugf(DBG_EXT,
                 "send_request_size: GET SEGMENT (%s) fp=%p part=%d proc=%lu",
                 orig_path, fp, info->part, info->size_processed);
          curl_easy_setopt(curl, CURLOPT_HEADERDATA, (void*)info->de_seg);
        }
        else
        {
          debugf(DBG_EXT,
                 "send_request_size: GET FILE (%s) fp=%p proc=%lu de=%p",
                 orig_path, fp, info->size_processed, de);
          curl_easy_setopt(curl, CURLOPT_HEADERDATA, (void*)info->de);
        }
        /**/
        //download via callback
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, info);
        //interrupt a slow download as this could make the next attempt faster
        //due to hubic throtling. but do this only for half of the tries
        if (option_min_speed_limit_progressive > 0
            && tries <= (REQUEST_RETRIES / 2))
        {
          curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT,
                           option_min_speed_limit_progressive);
          curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, option_min_speed_timeout);
        }
        //assume we need to append to an existing file (download interrupted)
        if (info->size_processed > 0)
        {
          curl_easy_setopt(curl, CURLOPT_RESUME_FROM_LARGE, info->size_processed);
          debugf(DBG_EXT, "send_request_size(%s): "
                 KYEL " resuming from %lu", orig_path, info->size_processed);
        }
        if (de_seg)
          curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, &header_get_segment_meta);
        else if (de)
          curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, &header_get_meta_dispatch);
      }
      else
      {
        //asumming retrieval of headers only
        if (de_seg)
          free_de_before_head(de_seg);
        else if (de)
          free_de_before_head(de);
        debugf(DBG_EXT, "send_request_size: GET HEADERS (%s)", print_path);
        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, &header_get_meta_dispatch);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, (void*)de);
        curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
      }
    }
    else if (!strcasecmp(method, HTTP_DELETE))
    {
      debugf(DBG_EXT, "send_request_size: DELETE (%s)", print_path);
      curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
    }
    else
    {
      debugf(DBG_EXT, "send_request_size: catch_all (%s)");
      // HEAD request (e.g. for statfs)
      curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
      curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, &header_dispatch);
    }
    //common code for all operations
    if (option_curl_progress_state)
    {
      //for progress reporting
      //http://curl.haxx.se/libcurl/c/progressfunc.html
      prog.curl = curl;
      prog.method = method[0];
      curl_easy_setopt(curl, CURLOPT_PROGRESSFUNCTION, progress_callback);
      /* pass the struct pointer into the progress function */
      curl_easy_setopt(curl, CURLOPT_PROGRESSDATA, &prog);
    }
    /* add the headers from extra_headers if any */
    curl_slist* extra;
    for (extra = extra_headers; extra; extra = extra->next)
    {
      debugf(DBG_EXT, "adding extra header: %s", extra->data);
      headers = curl_slist_append(headers, extra->data);
    }
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    debugf(DBG_EXTALL, "status: send_request_size(%s) started HTTP(%s)",
           orig_path, url);
    signal(SIGPIPE, sigpipe_callback_handler);
    prog.tries++;
    prog.response = -1;//for debug
    debug_http(method, path);// url);
    curl_easy_perform(curl);
    char* effective_url;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response);
    curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &effective_url);
    curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &total_time);
    curl_easy_getinfo(curl, CURLINFO_SIZE_DOWNLOAD, &size_downloaded);
    curl_easy_getinfo(curl, CURLINFO_SIZE_UPLOAD, &size_uploaded);
    debugf(DBG_EXTALL,
           "status: send_request_size(%s) completed HTTP REQ:%s total_time=%.1f seconds",
           orig_path, effective_url, total_time);
    curl_slist_free_all(headers);
    curl_easy_reset(curl);
    return_connection(curl);
    //used for debug/error codes simulation
    if (prog.response != -1)
    {
      debugf(DBG_NORM, KYEL
             "status: send_request_size(%s) force debug response=%d",
             orig_path, prog.response);
      response = prog.response;
    }
    //check if internet is down
    if (response == 408)
    {
      debugf(DBG_NORM, KYEL
             "send_request_size(%s): waiting for internet to resume, retry forever",
             print_path);
      sleep_ms(1000);
      //retry forever until internet is back
      tries--;
      if (is_upload)
      {
        //fixme: unblock potential sem_wait deadlocks
        //notify cfs_flush that a data feed from cache is needed
        de_tmp->upload_buf.feed_from_cache = true;
      }
    }
    //something went really wrong
    if (response == 0)
    {
      debugf(DBG_NORM, KYEL "send_request_size(%s:%s) got response=0, retry forever",
             print_path, method);
      sleep_ms(1000);
      tries--;
    }
    if (response != 404 && (response >= 400 || response < 200))
    {
      //Now, our chunk.memory points to a memory block that is chunk.size
      //bytes big and contains the remote file.
      debugf(DBG_NORM, KRED
             "send_request_size: error, resp=%d , size=%lu, [HTTP %d] (%s)(%s)",
             response, (long)chunk.size, response, method, print_path);
      debugf(DBG_NORM, "send_request_size: error message=[%s]", chunk.memory);
    }
    free(chunk.memory);
    //detect if download was incomplete/interrupted
    if (is_download && info
        && info->size_copy > 0  && info->size_copy != info->size_processed
        && (de && info->size_processed != de->size)
        && (de_seg && info->size_processed != de_seg->size))
    {
      debugf(DBG_NORM, KYEL
             "send_request_size: download interrupted, expect size=%lu got size=%.0f",
             info->size_copy, size_downloaded);
      response = 417;//too slow, signal error and hope for faster download
    }
    if (is_upload)
    {
      //signal request completion (replaces callback option)
      //only if there was data uploaded
      //otherwise retry as no data is lost
      if (file_size > 0 && (de_tmp && de_tmp->upload_buf.size_processed > 0))
      {
        //do not retry as data on upload will be lost
        debugf(DBG_EXT, "send_request_size(%s:%s): upload exit",
               print_path, de_tmp->name);
        break;
      }

      //in case above break is not executed on 503 error
      if (response == 503)
      {
        //do not retry as data on upload will be lost
        debugf(DBG_EXT, KRED "send_request_size(%s): upload exit @503", print_path);
        break;
      }
    }
    if ((response >= 200 && response < 400) || (!strcasecmp(method, "DELETE")
        && response == 409))
    {
      debugf(DBG_NORM,
             "status: send_req_size(%s) speed=%.1f sec res=%d dwn=%.0f upld=%.0f"
             KCYN "(%s) " KGRN "[HTTP OK]", print_path, total_time, response,
             size_downloaded, size_uploaded, method);
      break;
    }
    if (response == 401 && !cloudfs_connect())   // re-authenticate on 401s
    {
      debugf(DBG_NORM, KYEL"status: send_req_size(%s) (%s) [HTTP REAUTH]",
             print_path, method);
      break;
    }
    //handle cases when file is not found, no point in retrying, should exit
    if (response == 404)
    {
      debugf(DBG_NORM,
             "send_req_size: not found error for (%s)(%s), ignored "
             KYEL "[HTTP 404]", method, print_path);
      break;
    }
    else
    {
      debugf(DBG_NORM,
             "send_request_size: httpcode=%d (%s)(%s), retrying "
             KRED "[HTTP ERR]", response, method, print_path);
      if (response != 417)//skip pause on slow speed errors
        //sleep(8 << tries); // backoff
        sleep(1);
    }
    if (xmlctx)
      xmlCtxtResetPush(xmlctx, NULL, 0, NULL, NULL);
  }//end for
  if (encoded_path == NULL)
    curl_free(orig_path);
  debugf(DBG_NORM, "exit: send_request_size(%s)" KCYN
         "(%s) response=%d total_time=%.1f seconds",
         print_path, method, response, total_time);
  return response;
}

//if path is encoded cache entry will not be found, need to pass unencoded as well
//todo: implement use of dir_entry instead of path for performance reasons.
int send_request(char* method, const char* path, FILE* fp,
                 xmlParserCtxtPtr xmlctx, curl_slist* extra_headers,
                 dir_entry* de, dir_entry* de_seg)
{
  off_t flen = 0;
  if (fp)
  {
    // if we don't flush the size will probably be zero
    fflush(fp);
    flen = cloudfs_file_size(fileno(fp));
  }
  return send_request_size(method, path, fp, xmlctx, extra_headers, flen, 0, de,
                           de_seg);
}


/*
   updates file entry with segment list & details
*/
bool update_segments(dir_entry* de, int* segment_count)
{
  assert(de);
  if (!de->manifest_cloud)
  {
    de->is_segmented = false;
    debugf(DBG_EXT, "update_segments(%s): not segmented ", de->name);
    return true;
  }
  else
    de->is_segmented = true;
  debugf(DBG_EXT, "update_segments(%s): man=%s ", de->name, de->manifest_cloud);
  dir_entry* seg_dir;
  char* manifest_path;
  //get a list with all segment files composing the parent large file
  //dig through subfolders until a file is found, assumed to be a segment
  manifest_path = de->manifest_cloud;
  do
  {
    if (!cloudfs_list_directory(manifest_path, &seg_dir))
    {
      debugf(DBG_NORM, KRED "exit 1: update_segments(%s)", de->name);
      return false;
    }
    if (seg_dir && !seg_dir->full_name)
      manifest_path = seg_dir->full_name;//manifest will be reused
  }
  while (seg_dir && seg_dir->isdir);
  bool check_ok;
  int iterations = 0;
  int seg_count;
  //check folder content, iterate through files
  do
  {
    debugf(DBG_EXT, "update_segments(%s): check segments try #%d",
           de->name, iterations);
    check_ok = true;
    seg_count = 0;
    (*segment_count) = 0;
    if (seg_dir && !seg_dir->isdir)
    {
      //most reliable way to get true size is to add all segments
      long total_size = 0;
      dir_entry* tmp_de = seg_dir;
      int de_segment, index = 0;
      while (tmp_de)
      {
        assert(!tmp_de->isdir);//folders are not welcomed
        de_segment = atoi(tmp_de->name);
        if (de_segment != index)
        {
          debugf(DBG_NORM, KRED
                 "update_segments(%s): missing segment %d, retry #%d",
                 de->name, index, iterations);
          cloudfs_free_dir_list(seg_dir);
          sleep_ms(1000 * iterations);
          //reload folder content
          if (!cloudfs_list_directory(manifest_path, &seg_dir))
            abort();
          check_ok = false;
          break;
        }
        total_size += tmp_de->size;
        tmp_de = tmp_de->next;
        seg_count++;
        index++;
      }
      (*segment_count) = seg_count;
      if (check_ok)
      {
        if (de->lazy_segment_load && (de->size != 0) && (de->size != total_size))
        {
          debugf(DBG_ERR, KYEL
                 "update_segments(%s): inconsistent size, meta=%lu, segs=%lu",
                 de->name, de->size, total_size);
          //abort();
        }
        de->size = total_size;
        de->lazy_segment_load = false;//size was read so mark it
        //if we only have one segment mark general file segment size as per conf
        //file because it must be larger than actual segment size in the cloud
        //to avoid crash in cfs_read
        if (de->segment_size == 0)
        {
          //segsize equal first segment size
          //except when one seg exists then equals default seg_size
          de->segment_size = seg_count == 1 ?
                             max(segment_size, seg_dir->size) : seg_dir->size;
        }
        else
        {
          //check if segment (size) is corrupted
          if (!(de->segment_size == seg_dir->size || de->size == seg_dir->size))
          {
            debugf(DBG_EXT, KYEL "update_segments(%s): corrupted file/size",
                   de->name);
            return false;
          }
        }
        debugf(DBG_EXT, "update_segments(%s): found %d segments",
               de->name, seg_count);
      }
    }
    iterations++;
  }
  while (!check_ok && iterations <= REQUEST_RETRIES);
  if (!check_ok)
  {
    //incomplete segments, might show later
    debugf(DBG_NORM, KRED "update_segments(%s): missing segments, count=%d",
           de->name, *segment_count);
    return false;
  }
  else
  {
    de->is_segmented = true;
    if (de->segment_size == 0)
      de->segment_size = segment_size;
    de->segment_remaining = de->size % de->segment_size;
    de->segment_full_count = de->size / de->segment_size;
    de->segment_count = de->segment_full_count + (de->segment_remaining > 0);
    if (seg_count != de->segment_count)
    {
      debugf(DBG_NORM, KRED
             "update_segments(%s): diff no. segments than expected %d!=%d",
             de->name, seg_count, de->segment_count);
      //incomplete no. of segments found in cloud
      return false;
    }
    //assert(seg_count == de->segment_count);
    //save segments dir list into parent file entry
    //fixme: potentially unsafe as it get's overwritten and data is lost
    if (de)
    {
      if (!de->segments)
      {
        debugf(DBG_EXT, KMAG
               "format_segments: adding segment list to (%s)", de->full_name);
        de->segments = seg_dir;
      }
      else
      {
        //todo: free if is old and no op is active for this segment
        dir_entry* new_seg = seg_dir;
        dir_entry* old_seg;
        int de_segment;
        debugf(DBG_EXT, KMAG
               "format_segments: checking seglist changes (%s)", de->full_name);
        while (new_seg)
        {
          de_segment = atoi(new_seg->name);
          old_seg = get_segment(de, de_segment);
          //check if segments are identical
          //if not replace de with new segment list
          if (!old_seg || !old_seg->md5sum
              || strcasecmp(old_seg->md5sum, new_seg->md5sum))
          {
            debugf(DBG_EXT, KMAG
                   "format_segments: modifing segment list for (%s)", de->full_name);
            //todo: what if there are download segmented ops in progress?
            cloudfs_free_dir_list(de->segments);
            de->segments = seg_dir;
            break;
          }
          new_seg = new_seg->next;
        }
      }
    }
  }
  return true;
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
  debugf(DBG_NORM, KYEL "CURL version=%s ssl=%s",
         cvid->version, cvid->ssl_version);
  // CentOS/RHEL 5 get stupid mode, because they have a broken libcurl
  if (cvid->version_num == RHEL5_LIBCURL_VERSION)
  {
    debugf(DBG_NORM, "RHEL5 mode enabled.");
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
  debugf(DBG_EXT, "Destroy mutex");
  pthread_mutex_destroy(&pool_mut);
  int n;
  for (n = 0; n < curl_pool_count; ++n)
  {
    debugf(DBG_EXT, "Cleaning curl conn %d", n);
    curl_easy_cleanup(curl_pool[n]);
  }
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
    debugf(DBG_EXT, "get_file_mimetype(%s): got mime=%s", path, mime);
    return mime;
  }
  debugf(DBG_EXT, KYEL "get_file_mimetype(%s): cannot get mime", path);
  const char* error = "application/octet-stream";
  return error;
}

bool get_file_mimetype_from_path(dir_entry* de, char* mime)
{
  bool result = true;
  if (strstr(de->name, ".mpg"))
    snprintf(mime, MAX_PATH_SIZE, "%s", "video/mpeg");
  else if (strstr(de->name, ".jpg"))
    snprintf(mime, MAX_PATH_SIZE, "%s", "image/jpeg");
  else if (strstr(de->name, ".mp4"))
    snprintf(mime, MAX_PATH_SIZE, "%s", "video/mp4");
  else if (strstr(de->name, ".avi"))
    snprintf(mime, MAX_PATH_SIZE, "%s", "video/x-msvideo");
  else if (strstr(de->name, ".mkv"))
    snprintf(mime, MAX_PATH_SIZE, "%s", "video/x-matroska");
  else
  {
    snprintf(mime, MAX_PATH_SIZE, "%s", "application/octet-stream");
    result = false;
  }
  debugf(DBG_EXT, "get_file_mimetype_from_path(%s): mime=%s", de->name, mime);
  return result;
}

/*
   moves main file to segment 0 as file is segmented
*/
void int_convert_first_segment_th(dir_entry* de)
{
  debugf(DBG_EXT, KMAG "int_convert_first_segment(%s): converting as segment 0",
         de->name);
  dir_entry* de_seg = get_create_segment(de, 0);
  init_semaphores(&de_seg->upload_buf, de_seg, "upload");
  assert(de_seg->full_name);
  int loops = 0;
  //wait until first seg is fully uploaded
  while (is_semaphore_open(&de->upload_buf))
  {
    if (loops % 20 == 0)
      debugf(DBG_EXT, KMAG "int_convert_first_segment(%s): wait completion",
             de->name);
    sleep_ms(200);
    loops++;
  }
  bool res = cloudfs_copy_object(de, de_seg->full_name, true);
  assert(res);
  //signal cfs_flush we're done
  unblock_close_all_semaphores(&de_seg->upload_buf);
  //copy md5sum to first segment for final etag md5sum compute
  assert(!de_seg->md5sum);
  de_seg->md5sum = strdup(de->md5sum);
  debugf(DBG_EXT, KMAG "int_convert_first_segment(%s): converted to %s",
         de->name, de_seg->full_name);
  pthread_exit(NULL);
}

/*
   feeds data into http buffer from cache file, similar with cfs_write
*/
bool int_cfs_write_cache_data_feed(dir_entry* de)
{
  debugf(DBG_EXT, KBLU "int_cfs_write_cache_data_feed(%s): starting, fp=%p",
         de->name, de->upload_buf.local_cache_file);
  int res = fflush(de->upload_buf.local_cache_file);
  if (res == 0)
    debugf(DBG_EXT, KBLU "int_cfs_write_cache_data_feed(%s): flushed ok",
           de->name);
  else
    debugf(DBG_EXT, KRED "int_cfs_write_cache_data_feed(%s): flushed error=%d",
           de->name, res);
  off_t seg_size_disk = get_file_size(de->upload_buf.local_cache_file);
  debugf(DBG_EXT, KBLU "int_cfs_write_cache_data_feed(%s) cache_size=%lu",
         de->full_name, seg_size_disk);
  //rewind to provide data for http upload from local cache
  assert(fseek(de->upload_buf.local_cache_file, 0, SEEK_SET) == 0);
  char* cache_buf = malloc(BUFFER_READ_SIZE);
  off_t read_len;
  off_t ptr_offset = 0;
  do
  {
    read_len = fread(cache_buf, 1, BUFFER_READ_SIZE,
                     de->upload_buf.local_cache_file);
    debugf(DBG_EXTALL, KMAG
           "int_cfs_write_cache(%s): read file size=%lu",
           de->name, read_len);
    if (read_len > 0)
    {
      de->upload_buf.work_buf_size = read_len;
      while (de->upload_buf.work_buf_size > 0)
      {
        debugf(DBG_EXTALL, KMAG
               "int_cfs_write_cache(%s): looping workbufsize=%lu",
               de->name, de->upload_buf.work_buf_size);
        //index in buffer to resume upload in a new segment
        ptr_offset = read_len - de->upload_buf.work_buf_size;
        de->upload_buf.readptr = cache_buf + ptr_offset;
        //signal there is data available in buffer for upload
        unblock_semaphore(&de->upload_buf, SEM_FULL);
        //wait until previous buffer data is uploaded
        //freezes here after re-uploading a missing segment
        if (de->upload_buf.sem_list[SEM_EMPTY])
          sem_wait(de->upload_buf.sem_list[SEM_EMPTY]);
        debugf(DBG_EXTALL, KMAG
               "int_cfs_write_cache(%s): wait done, empty proc=%lu worksize=%lu",
               de->name, de->upload_buf.size_processed,
               de->upload_buf.work_buf_size);
      }
    }
    else
      debugf(DBG_EXT, KMAG
             "int_cfs_write_cache(%s): cache read done", de->name);
  }
  while (read_len > 0);
  debugf(DBG_EXT, KMAG
         "int_cfs_write_cache(%s): exit cache feed proc=%lu",
         de->name, de->upload_buf.size_processed);
  free(cache_buf);
}

/*
   progressive segment upload to cloud
   job->de_seg is null for first file
*/
void internal_upload_segment_progressive(void* arg)
{
  struct thread_job* job = arg;
  dir_entry* de_tmp = job->de_seg ? job->de_seg : job->de;
  dir_entry* de = job->de;
  debugf(DBG_EXT, "int_upload_seg_prog(%s): seg=%s md5=%s part=%d",
         de->name, de_tmp->full_name, de->md5sum, de_tmp->segment_part);
  char* dbg_de_name = strdup(de->name);
  char* dbg_de_seg_name = strdup(de_tmp->name);
  bool cache_file_exist;
  int response, i;
  bool op_ok = true;
  bool md5err = false;
  save_job_md5(de->job2);//saves a snapshot in case error resume is needed
  save_job_md5(de->job);//save as first segment md5 is fuse one
  //multiple attempts for md5sum failures
  for (i = 0; i < 1 + REQUEST_RETRIES; i++)
  {
    if (md5err || !op_ok)
    {
      restore_job_md5(de->job2);
      //wait until cache data is read and ready to feed into http
      debugf(DBG_EXT, "int_upload_seg_prog(%s:%s): waiting for http resume",
             de->name, de_tmp->name);
      //unblock potential wait for seg completion in cfs_flush
      sem_post(de_tmp->upload_buf.sem_list[SEM_DONE]);
      //fixme: sometimes it will freeze here, see cfs_flush note
      //wait until data feed from cache is done
      sem_wait(de_tmp->upload_buf.sem_list[SEM_FULL]);
    }
    if (!md5err && job->de_seg)//already initialised below in case of md5err
      assert(init_job_md5(job));
    //mark file size = 1 to signal we have some data coming in
    response = send_request_size(HTTP_PUT, NULL, NULL, NULL, NULL, 1, 0, de,
                                 job->de_seg);//keep job->de_seg as might be NULL
    op_ok = valid_http_response(response);

    //only check md5 for 2nd segment onwards
    //FIXME: needs a fix to check also first segment, use fuse_md5 (job2)
    if (job->de_seg)
    {
      assert(complete_job_md5(job));
      assert(job->md5str);
    }
    //check if md5 computed locally matches cloud md5
    //de_seg->md5sum is null on failed upload
    if (job->de_seg || !op_ok)
    {
      if (!de_tmp->md5sum || strcasecmp(de_tmp->md5sum, job->md5str) || !op_ok)
      {
        //most likely upload was interrupted by server/network, need to retry
        debugf(DBG_EXT, KRED
               "int_upload_seg_prog(%s): md5sum ERR de_seg=%s try=%d sizeproc=%lu",
               de->name, de_tmp->name, i, de_tmp->upload_buf.size_processed);
        if (job->de_seg)
          assert(init_job_md5(job));
        de_tmp->upload_buf.feed_from_cache = true;
        md5err = true;
        debugf(DBG_EXT,
               "int_upload_seg_prog(%s): signal buf empty sizeproc=%lu",
               de_tmp->name, de_tmp->upload_buf.size_processed);
        //unblock cfs_write to go into cache data feed
        unblock_semaphore(&de_tmp->upload_buf, SEM_EMPTY);
        //sem_post(de_tmp->upload_buf.sem_list[SEM_EMPTY]);
        op_ok = false;
      }
      else
      {
        debugf(DBG_EXT, KMAG
               "int_upload_seg_prog(%s): de_seg=%s try=%d "KGRN"md5sum/size OK",
               de_tmp->name, de_tmp->full_name, i);
        //in case segment meta download failed set md5sum for later check in cfs_flush
        if (!de_tmp->md5sum)
          de_tmp->md5sum = strdup(job->md5str);
        md5err = false;
        break;
      }
    }
    if (op_ok)
      break;
    else
      debugf(DBG_EXT, KMAG
             "int_upload_seg_prog(%s): de_seg=%s try=%d, retrying upload",
             de_tmp->name, de_tmp->full_name, i);
  }

  if (!op_ok)
  {
    //decrement seg count as upload was not ok
    de->segment_count--;
    debugf(DBG_NORM, KRED
           "int_upload_seg_prog(%s:%s): upload failed", de->name, de_tmp->full_name);
    //todo: signal error to running threads
    abort();
  }
  //if this is the last segment, upload the zero size parent file
  //and remove older versions. move file from upload cache to access cache
  if (de_tmp->segment_part == de->segment_count - 1)
  {
    //wait for main file to copy complete as it holds first segment data
    dir_entry* de_first = get_create_segment(de, 0);
    int loops = 0;
    //wait until first seg is fully uploaded so I can create real (0 sz) manifest
    while (is_semaphore_open(&de_first->upload_buf))
    {
      if (loops % 20 == 0)
        debugf(DBG_EXT, KMAG "int_upload_seg_prog(%s): wait FIRST seg completion",
               de->name);
      sleep_ms(200);
      loops++;
    }
    debugf(DBG_EXT, KMAG
           "int_upload_seg_prog(%s:%s): create manifest, part=%d count=%d",
           de->name, de_tmp->name, de_tmp->segment_part, de->segment_count);
    curl_slist* headers = NULL;
    char filemimetype[MAX_PATH_SIZE] = "";
    get_file_mimetype_from_path(de, filemimetype);
    add_header(&headers, HEADER_TEXT_MANIFEST, de->manifest_time);
    add_header(&headers, HEADER_TEXT_CONTENT_LEN, "0");
    add_header(&headers, HEADER_TEXT_CONTENT_TYPE, filemimetype);
    response = send_request_size(HTTP_PUT, NULL, NULL, NULL, headers, 0, 0, de,
                                 NULL);
    //now file is updated on cloud
    curl_slist_free_all(headers);
    //remove older file / segment versions
    char manifest_root[MAX_URL_SIZE];
    snprintf(manifest_root, MAX_URL_SIZE, "/%s/%s", de->manifest_seg, de->name);
    char new_manifest_root[MAX_URL_SIZE];
    snprintf(new_manifest_root, MAX_URL_SIZE, "/%s", de->manifest_time);
    if (de->manifest_cloud)
    {
      debugf(DBG_EXT, KMAG
             "internal_upload_segment_prog(%s): clean old manifest", de->name);
      //delete old segments from previous/initial manifest root
      cleanup_older_segments_th(de->manifest_cloud, new_manifest_root);
    }
    //delete older versions from current manifest (need on overwrites)
    if (strcasecmp(manifest_root, de->manifest_cloud))
      //new_manifest_root))//only if different
    {
      //abort();//check if compare is working
      debugf(DBG_EXT, KMAG
             "internal_upload_segment_prog(%s): clean new manifest versions",
             job->de->name);
      cleanup_older_segments_th(manifest_root, new_manifest_root);
    }
    //check if all segments are visible in cloud
    //as there are cases when last segment appears late
    dir_entry* de_tmp2 = init_dir_entry();
    snprintf(manifest_root, MAX_URL_SIZE, "/%s", de->manifest_time);
    de_tmp2->manifest_cloud = strdup(manifest_root);
    de_tmp2->name = strdup(job->de->name);
    int segment_count;
    if (!update_segments(de_tmp2, &segment_count))
    {
      debugf(DBG_EXT, KYEL
             "internal_upload_segment_prog(%s): incomplete segs", de->name);
    }
    if (de_tmp2->segment_count != de->segment_count)
    {
      debugf(DBG_EXT, KRED
             "int_upload_seg_prog(%s): some segs unvisible (%d<%d)!",
             job->de->name, segment_count, de->segment_count);
      de->has_unvisible_segments = true;
    }
    else
      de->has_unvisible_segments = false;
    cloudfs_free_dir_list(de_tmp2);
    //signal cfs_flush we're done uploading main file so it can exit
    unblock_semaphore(&de_tmp->upload_buf, SEM_DONE);
  }
  //signal cfs_write (and cfs_flush?) we're done
  unblock_close_all_semaphores(&de_tmp->upload_buf);

  debugf(DBG_EXT, "exit: internal_upload_segment_progressive");
  //free only if is true segment, keep first job for complete file md5sum
  if (job->de_seg)
    de_tmp->job = NULL;
  close_file(&de_tmp->upload_buf.local_cache_file);
  //unlock to allow another upload segment to retry a failed transfer
  pthread_mutex_unlock(&de_tmp->upload_buf.mutex);
  free_thread_job(job);
  free(dbg_de_name);
  free(dbg_de_seg_name);
  pthread_exit(NULL);
}

/*
   uploads a new segment folder in cloud
   NOTE!: it alters de fields
*/
bool cloudfs_create_segment(dir_entry* de_seg, dir_entry* de)
{
  dir_entry* de_tmp;
  de_tmp = de_seg ? de_seg : de;
  assert(de_tmp);
  assert(de);
  debugf(DBG_EXT, "cloudfs_create_segment(%s:%s)", de_tmp->name, de->name);
  if (!de_seg)// || de_seg->segment_part == 0)
  {
    de->segment_count = 1;//we have at least 1 segment
    de->is_segmented = false;//for now we don't know if must be segmented
    de->segment_size = segment_size;
    de->segment_remaining = segment_size;
  }
  //check if segment is already pre-launched
  if (!de_seg || !de_seg->job)
  {
    //launch async upload for this segment
    init_semaphores(&de_tmp->upload_buf, de_tmp, "upload");
    struct thread_job* job;
    char job_name[MAX_PATH_SIZE] = "segment_upload:";
    job = init_thread_job(strdup(strcat(job_name, de_tmp->name)));
    job->de = de;
    job->de_seg = de_seg;
    if (de_seg)
      job->de_seg->job = job; //cyclic ref. for md5 sum update in curl callbacks
    pthread_create(&job->thread, NULL,
                   (void*)internal_upload_segment_progressive, job);
  }
  else
  {
    debugf(DBG_EXT, "cloudfs_create_segment(%s:%s): skip, already launched",
           de_tmp->name, de->name);
    abort();
  }
  /*
     //pre-launch next segment to avoid interruptions in upload
     //this segment might not be needed so remove it if needed in cfs_flush
     dir_entry* de_next = get_create_segment(de, de_tmp + 1);
     assert(de_next);
     //launch async upload for this segment
     init_semaphores(&de_next->upload_buf, de_next, "upload");
     struct thread_job* job;
     char job_name[MAX_PATH_SIZE] = "segment_upload_next:";
     job = init_thread_job(strdup(strcat(job_name, de_next->name)));
     job->de = de;
     job->de_seg = de_next;
     job->de_seg->job = job; //cyclic ref. for md5 sum update in curl callbacks
     pthread_create(&job->thread, NULL, (void*)internal_upload_segment_progressive,
                 job);
  */
  debugf(DBG_EXT,
         "exit 0: cloudfs_create_segment(%s:%s) upload started ok file %s",
         de_tmp->full_name, de_tmp->name, de->name);
  return true;
}

//todo: must be syncronised as racing occurs
int download_ahead_segment_thread(void* arg)
{
  struct thread_job* job = arg;
  int segindex;
  dir_entry* de_seg;
  bool in_cache;
  long seg_read_ahead_count;
  if (option_read_ahead == -1)
    seg_read_ahead_count = job->de->segment_count - job->segment_part;
  else //ceil or floor does not compile/link properly
    seg_read_ahead_count = (option_read_ahead / job->de->segment_size)
                           + (option_read_ahead % job->de->segment_size == 0 ? 0 : 1);
  FILE* fp_segment = NULL;
  for (segindex = job->segment_part;
       (segindex < job->de->segment_count
        && segindex < job->segment_part + seg_read_ahead_count); segindex++)
  {
    de_seg = get_segment(job->de, segindex);
    assert(de_seg);
    debugf(DBG_EXT, KCYN
           "download_ahead_segment_th(%s:%s): from segindex=%d count=%d",
           job->de->name, (de_seg ? de_seg->name : ""), segindex,
           job->segment_part + seg_read_ahead_count);
    if (de_seg)
    {
      in_cache = open_segment_cache_md5(job->de, de_seg, &fp_segment, HTTP_GET);
      assert(fp_segment);
      if (!in_cache)
        cloudfs_download_segment(de_seg, job->de, fp_segment, 0);
      fclose(fp_segment);
      fp_segment = NULL;
    }
  }
  debugf(DBG_EXT, KCYN
         "download_ahead_segment_th(%s): exit segindex=%d ahead_count=%lu",
         job->de->name, segindex, seg_read_ahead_count);
  job->de->downld_buf.ahead_thread_count--;
  free_thread_job(job);
  pthread_exit(NULL);
}

/*
   downloading ahead segments.
   if sync_first = true, get first segment sync and rest async.
*/
int download_ahead_segment(dir_entry* de_seg, dir_entry* de, FILE* fp,
                           bool sync_first)
{
  debugf(DBG_EXT, KCYN "download_ahead_segment(%s): segindex=%d",
         de->name, de_seg->segment_part);
  de->downld_buf.ahead_thread_count++;
  int index = 0;
  if (sync_first)
  {
    //get current segment sync.
    cloudfs_download_segment(de_seg, de, fp, 0);
    index = 1;
  }
  //get the rest async.
  char job_name[MAX_PATH_SIZE] = "segment_download:";
  struct thread_job* job = init_thread_job(strdup(strcat(job_name,
                           de_seg->name)));
  job->de = de;
  job->segment_part = de_seg->segment_part + index;
  pthread_create(&job->thread, NULL,
                 (void*)download_ahead_segment_thread, job);
  return true;
}

/*
   download a segment synch and return immediately
   size = 0 for segments read ahead and saved to local cache files
   download completion is signaled via semaphores
*/
int cloudfs_download_segment(dir_entry* de_seg, dir_entry* de, FILE* fp,
                             size_t size)
{
  debugf(DBG_EXT, KMAG
         "cloudfs_download_segment: starting download %s part=%lu",
         de->name, de_seg->segment_part);
  if (!de_seg->downld_buf.mutex_initialised)
  {
    pthread_mutex_init(&de_seg->downld_buf.mutex, &segment_mutex_attr);
    de_seg->downld_buf.mutex_initialised = true;
  }
  pthread_mutex_lock(&de_seg->downld_buf.mutex);
  debugf(DBG_EXT, KMAG "cloudfs_download_segment: passed lock %s part=%lu",
         de->name, de_seg->segment_part);
  //after lock file might be in cache already
  if (check_segment_cache_md5(de, de_seg, fp))
  {
    debugf(DBG_EXT, KMAG
           "cloudfs_download_segment: cache ok after lock %s part=%lu",
           de->name, de_seg->segment_part);
    pthread_mutex_unlock(&de_seg->downld_buf.mutex);
    return true;
  }
  else
  {
    debugf(DBG_EXT, KMAG
           "cloudfs_download_segment: cache NOT ok after lock %s part=%lu",
           de->name, de_seg->segment_part);
  }
  init_semaphores(&de_seg->downld_buf, de_seg, "dwnld");
  de_seg->downld_buf.fuse_read_size = size;
  struct segment_info info;
  info.method = HTTP_GET;
  info.part = de_seg->segment_part;
  info.segment_size = de->segment_size;
  if (de->is_segmented)
    info.size_left = de_seg->segment_part < de->segment_full_count ?
                     de->segment_size : de->segment_remaining;
  else
    info.size_left = de->size;
  //need a copy for resume as info.size_left will be changed during download
  info.size_copy = info.size_left;
  //get existing segment size on disk for resume ops
  //if size is less than full segment size,
  //otherwise assume is corrupted as md5check above failed
  off_t fsize = get_file_size(fp);
  if (fsize  < de_seg->size)
    info.size_processed = fsize;
  else
  {
    //should never happen?
    debugf(DBG_EXT, KRED "cloudfs_download_segment: segment corrupted");
    abort();
  }
  info.seg_base = de_seg->full_name;
  info.de_seg = de_seg;
  info.de = de;
  info.fp = fp;
  info.de->is_progressive = false;
  info.de->is_single_thread = true;
  assert(info.fp);
  assert(fseek(info.fp, info.size_processed, SEEK_SET) == 0);
  setvbuf(info.fp, NULL, _IOFBF, DISK_BUFF_SIZE);
  int response = send_request_size(info.method, NULL, &info, NULL, NULL,
                                   info.size_copy, de->is_segmented, de, de_seg);
  if (!valid_http_response(response))
    debugf(DBG_NORM, KRED
           "cloudfs_download_segment: %s failed resp=%d proc=%lu",
           info.seg_base, response, info.size_processed);
  else
    debugf(DBG_EXT, "cloudfs_download_segment(%s) download ok proc=%lu",
           info.seg_base, info.size_processed);
  fflush(info.fp);
  //compute md5sum after each seg download
  if (de_seg->md5sum_local)
  {
    free(de_seg->md5sum_local);
    de_seg->md5sum_local = NULL;
  }
  assert(fseek(info.fp, 0, SEEK_SET) == 0);
  char md5_file_hash_str[MD5_DIGEST_HEXA_STRING_LEN] = { 0 };
  file_md5(fp, md5_file_hash_str);
  if (md5_file_hash_str && !strcasecmp(md5_file_hash_str, de_seg->md5sum))
  {
    debugf(DBG_EXTALL, "cloudfs_download_seg(%s) md5local=%s",
           de_seg->name, md5_file_hash_str);
    de_seg->md5sum_local = strdup(md5_file_hash_str);
  }
  else
  {
    //todo: delete segment content if fully loaded but corrupted
    if (info.size_processed == de_seg->size)
    {
      debugf(DBG_NORM, KRED
             "cloudfs_download_seg(%s): corrupted segment", de_seg->name);
      int fd = fileno(fp);
      assert(fd != -1);
      assert(ftruncate(fd, 0) == 0);
    }
  }
  unblock_close_all_semaphores(&de_seg->downld_buf);
  pthread_mutex_unlock(&de_seg->downld_buf.mutex);
  debugf(DBG_EXT, KMAG
         "cloudfs_download_segment: done fp=%p part=%d proc=%lu",
         de_seg->downld_buf.local_cache_file, de_seg->segment_part,
         info.size_processed);
  return true;
}

int cloudfs_object_truncate(dir_entry* de, off_t size)
{
  char* encoded = curl_escape(de->full_name, 0);
  int response;
  if (size == 0)
  {
    FILE* fp = fopen("/dev/null", "r");
    response = send_request("PUT", encoded, fp, NULL, NULL, de, NULL);
    fclose(fp);
  }
  else
  {
    //TODO: this is busted
    response = send_request("GET", encoded, NULL, NULL, NULL, de, NULL);
  }
  curl_free(encoded);
  return (response >= 200 && response < 300);
}

/* get metadata from cloud, like time attribs. create new entry if not cached yet.
   if force_segment is true then segments list/meta will be dowloaded
   if foce_meta is true then meta is downloaded (meta is false on lazy load)

   FIXME: with lazy meta file size (and segmented status) can be incorrect
   as they rely on optional fields. fix is to check if optional fields exists?
*/
bool get_file_metadata(dir_entry* de, bool force_segment_update,
                       bool force_meta)
{
  debugf(DBG_EXT, "get_file_meta(%s) isdir=%d isseg=%d file_count=%d",
         de->full_name, de->isdir, de->is_segmented,
         de->parent ? de->parent->object_count : -1);
  //fast dir list mode, if option is enabled (>0) and count > limit
  if (!force_meta && de->parent
      && (option_fast_list_dir_limit != -1
          && (de->parent->object_count > option_fast_list_dir_limit)))
  {
    debugf(DBG_EXT, KYEL "get_file_meta(%s): many files(%d), enable lazy/fast",
           de->name, de->parent->object_count);
    de->lazy_segment_load = true;
    de->metadata_downloaded = true;
    init_entry_lazy(de);
    return true;
  }

  //meta on isdir sometimes returns HTTP404 (segment folders)
  if (option_get_extended_metadata
      &&  (!de->metadata_downloaded || force_meta))// && !de->isdir)
  {
    //clear existing segments cache
    dir_decache_segments(de);
    //retrieve additional file metadata with a quick HEAD query
    int response = send_request("GET", NULL, NULL, NULL, NULL, de, NULL);
    if (valid_http_response(response))
    {
      debugf(DBG_EXT, KCYN"status: get_file_meta(%s) hash=%s",
             de->full_name, de->md5sum);
    }
    else
    {
      debugf(DBG_EXT, KYEL "status: get_file_meta(%s) failed resp=%d",
             de->full_name, response);
      return false;
    }
    de->lazy_meta = false;
  }
  else debugf(DBG_EXT, KCYN
                "get_file_meta(%s) skip head, isdir=%d meta_down=%d",
                de->full_name, de->isdir, de->metadata_downloaded);
  //todo: is this needed?
  //if (!de->isdir)
  //  path_to_stdmeta(de->full_name, de);
  //skip get segments if some segments are not yet visible
  if ((de->size_on_cloud == 0 || de->is_segmented) && !de->isdir
      && /*!de->metadata_downloaded &&*/ !de->has_unvisible_segments)
  {
    //this can be a potential segmented file, try to read segments size
    debugf(DBG_EXT, KMAG"get_file_meta: get segments file=%s",
           de->full_name);
    if (!de->lazy_segment_load || force_segment_update)
    {
      int seg_count;
      if (!update_segments(de, &seg_count))
      {
        //fixme: corrupt file, what to do?
        cloudfs_delete_path(de->manifest_cloud, true, false, NULL);
        return false;
      }
      else
      {
        de->has_unvisible_segments = false;
        //
      }
    }
  }
  else debugf(DBG_EXT, KCYN
                "get_file_meta(%s) skip seg_downld, size_cloud=%lu meta_down=%d",
                de->full_name, de->size_on_cloud, de->metadata_downloaded);
  de->metadata_downloaded = true;
  return true;
}

//get list of folders from cloud
// return 1 for OK, 0 for error
int cloudfs_list_directory(const char* path, dir_entry** dir_list)
{
  debugf(DBG_EXT, "cloudfs_list_directory(%s)", path);
  char container[MAX_PATH_SIZE * 3] = "";
  char object[MAX_PATH_SIZE] = "";
  char last_subdir[MAX_PATH_SIZE] = "";
  int prefix_length = 0;
  int response = 0;
  int retval = 0;
  int entry_count = 0;
  dir_entry* last_dir = NULL;
  dir_entry* de_tmp;
  dir_entry* de_root;
  bool duplicate_entry;
  *dir_list = NULL;
  //http://www.xmlsoft.org/html/libxml-tree.html#xmlNode
  xmlNode* onode = NULL, *anode = NULL, *text_node = NULL;
  xmlParserCtxtPtr xmlctx = xmlCreatePushParserCtxt(NULL, NULL, "", 0, NULL);
  de_root = check_path_info(path);
  if (!strcmp(path, "") || !strcmp(path, "/"))
  {
    path = "";
    strncpy(container, "/?format=xml", sizeof(container));
  }
  else
  {
    //assert(de_root);//should exist as is not root "/" folder
    sscanf(path, "/%[^/]/%[^\n]", container, object);
    char* encoded_container = curl_escape(container, 0);
    char* encoded_object = curl_escape(object, 0);
    // The empty path doesn't get a trailing slash, everything else does
    //fix needed as slash must not be appended if there already
    char* trailing_slash = "";
    prefix_length = strlen(object);
    if (object[0] == 0 || object[prefix_length - 1] == '/')
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
    response = send_request(HTTP_GET, container, NULL, xmlctx, NULL, NULL, NULL);
  }
  if (response >= 200 && response < 300)
    xmlParseChunk(xmlctx, "", 0, 1);
  if (response >= 200 && response < 300 && xmlctx->wellFormed )
  {
    xmlNode* root_element = xmlDocGetRootElement(xmlctx->myDoc);
    for (onode = root_element->children; onode; onode = onode->next)
    {
      debugf(DBG_EXTALL, KYEL "cfs_list: type=%d name=%s",
             onode->type, (const char*)onode->name);
      if (onode->type != XML_ELEMENT_NODE) continue;
      char is_object = !strcasecmp((const char*)onode->name, "object");
      char is_container = !strcasecmp((const char*)onode->name, "container");
      char is_subdir = !strcasecmp((const char*)onode->name, "subdir");
      if (is_object || is_container || is_subdir)
      {
        dir_entry* de = init_dir_entry();
        if (is_object)//usefull for segments
          de->segment_part = entry_count;
        entry_count++;
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
              debugf(DBG_EXTALL, KYEL
                     "cfs_list: anode=[%s] content=[%s]",
                     (const char*)anode->name, content);
            }
            else
            {
              debugf(DBG_EXTALL, KYEL
                     "cfs_list: anode=[%s]", (const char*)anode->name);
            }
          }
          //debugf(DBG_EXT, KCYN
          //       "cloudfs_list_directory(%s): anode [%s]=[%s]", path,
          //       (const char*)anode->name, content);
          if (!strcasecmp((const char*)anode->name, "name"))
          {
            de->name = strdup(content + prefix_length);
            // Remove trailing slash from name
            char* slash = strrchr(de->name, '/');
            if (slash && (0 == *(slash + 1)))
              *slash = 0;
            //concat full name but remove trailing slash from path
            slash = strrchr(path, '/');
            if (slash && (0 == *(slash + 1)))
            {
              if (asprintf(&(de->full_name), "%s%s", path, de->name) < 0)
              {
                assert(!de->full_name);
                de->full_name = NULL;
              }
              //keep this line for else if otherwise auto format will break it
            }
            else if (asprintf(&(de->full_name), "%s/%s", path, de->name) < 0)
            {
              assert(!de->full_name);
              de->full_name = NULL;
            }
            //need a unique file id for semaphores
            de->full_name_hash = strdup(str2md5(de->full_name, strlen(de->full_name)));
          }
          if (!strcasecmp((const char*)anode->name, "bytes"))
          {
            //this will be overwriten with true size if file is segmented
            de->size = strtoll(content, NULL, 10);
            //need the original size to check if file is segmented
            de->size_on_cloud = strtoll(content, NULL, 10);
            if (de->size > segment_size)
              debugf(DBG_NORM, KRED "Issue? seg size (%lu > %lu) too big?",
                     de->size, segment_size);
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
          //if (!strcasecmp((const char*)anode->name, "count"))
          //  de->object_count_recursive = atoi(content);
          if (!strcasecmp((const char*)anode->name, "last_modified"))
          {
            time_t last_modified_t = get_time_from_str_as_gmt(content);
            char local_time_str[64];
            time_t local_time_t = get_time_as_local(last_modified_t, local_time_str,
                                                    sizeof(local_time_str));
            de->last_modified = local_time_t;
            de->ctime.tv_sec = local_time_t;
            de->ctime.tv_nsec = 0;
            //initialise all fields with hubic last modified date
            //in case the file does not have extended attributes set
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
          //removes a dir_entry from cache if is an older version?
          if (!strncasecmp(de->name, last_subdir, sizeof(last_subdir)))
          {
            //not sure when / why this is called, seems to generate many missed delete ops.
            //cloudfs_free_dir_list(de);
            debugf(DBG_EXT, "cloudfs_list_directory: " KYEL
                   "ignore "KNRM"cloudfs_free_dir_list(%s) command", de->name);
            continue;
          }
          strncpy(last_subdir, de->name, sizeof(last_subdir));
        }
        //set parent entry. can be null
        de->parent = de_root;
        //check for duplicates to find a bug
        de_tmp = *dir_list;
        duplicate_entry = false;
        while (de_tmp)
        {
          if (!strcasecmp(de_tmp->full_name, de->full_name))
          {
            debugf(DBG_ERR, KRED "cloudfs_list_dir(%s): ignoring duplicate (%s)",
                   path, de->name);
            duplicate_entry = true;
          }
          de_tmp = de_tmp->next;
        }
        if (!duplicate_entry)
        {
          //fixed, saves elements in default read order
          if (!*dir_list)
            *dir_list = de;
          else
            last_dir->next = de;
          last_dir = de;
          //saves elements in the list in reversed order, not good!
          /*
             de->next = *dir_list;
             dir_list = de;
          */
          //char time_str[TIME_CHARS] = "";
          //get_timespec_as_str(&(de->mtime), time_str, sizeof(time_str));
          debugf(DBG_NORM, KCYN "new dir_entry %s size=%d %s dir=%d lnk=%d md5=%s",
                 de->full_name, de->size, de->content_type, de->isdir, de->islink,
                 de->md5sum);
        }
      }
      else
        debugf(DBG_EXT, "unknown element: %s", onode->name);
    }//end for
    //de_root is null for cloud root and manifest files
    if (de_root)
      de_root->object_count = entry_count;
    retval = 1;
  }
  else if ((!strcmp(path, "") || !strcmp(path, "/")) && *override_storage_url)
  {
    entry_count = 1;
    debugf(DBG_NORM, KRED "Init cache entry container=[%s] !!!???",
           public_container);
    sleep_ms(3000);
    abort();//to find out when this happens
    dir_entry* de = init_dir_entry();
    de->name = strdup(public_container);
    de->parent = de_root;
    de_root->object_count = 1;//todo: check this scenario
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
  debugf(DBG_EXT, "exit: cloudfs_list_directory(%s)", path);
  return retval;
}



/*
  simple threaded delete
*/
void thread_cloudfs_delete_object(dir_entry* de)
{
  cloudfs_delete_object(de);
  pthread_exit(NULL);
}

bool cloudfs_delete_object(dir_entry* de)
{
  debugf(DBG_EXT, "cloudfs_delete_object(%s): dir=%d seg=%d meta_down=%d",
         de->full_name, de->isdir, de->is_segmented, de->metadata_downloaded);
  //get meta for files to obtain manifest data. avoid segments and dirs.
  bool potential_segmented = de->is_segmented || de->size_on_cloud == 0;
  if (potential_segmented && !de->metadata_downloaded && !de->isdir)
    get_file_metadata(de, false, true);
  if (potential_segmented || de->isdir)
  {
    //delete object segments or subfolders
    if (de->manifest_cloud || de->isdir)
    {
      dir_entry* de_content;
      char* prefix_path = de->isdir ? de->full_name : de->manifest_cloud;
      return cloudfs_delete_path(prefix_path, de->isdir, de->is_segmented, de);
    }
  }
  return cloudfs_delete_path(de->full_name, de->isdir, de->is_segmented, de);
}

/*
  simple threaded delete
*/
void cloudfs_delete_object_unlink_async_th(thread_delete_job* job)
{
  debugf(DBG_EXT, "cloudfs_del_obj_async_th(%s): deleting, threadcount=%d",
         job->de->full_name, g_delete_thread_count);
  g_delete_thread_count++;
  char* path = strdup(job->de->full_name);//as de will be NULLed
  cloudfs_delete_object(job->de);
  close_lock_file(path, job->fd);
  g_delete_thread_count--;
  free(job);
  free(path);
  pthread_exit(NULL);
}

/*
  delete using max threads
*/
void cloudfs_delete_object_unlink_async(dir_entry* de, int fd)
{
  debugf(DBG_EXT, "cloudfs_del_obj_unl_async(%s): to delete, threadcount=%d",
         de->name, g_delete_thread_count);
  //fixme: replace with semaphores
  while (g_delete_thread_count >= MAX_DELETE_THREADS)
    sleep_ms(250);
  thread_delete_job* job = malloc(sizeof(struct thread_delete_job));
  job->de = de;
  job->fd = fd;
  pthread_t thread;
  pthread_create(&thread, NULL, (void*)cloudfs_delete_object_unlink_async_th,
                 job);
}

/*
   remove folder and it's subfolders & files recursively
   todo: implement bulk delete:
   https://docs.hpcloud.com/publiccloud/api/swift-api.html
*/
bool cloudfs_delete_path(char* path, bool is_dir, bool is_segmented,
                         dir_entry* de)
{
  //delete object segments or subfolders
  if (is_segmented || is_dir)
  {
    dir_entry* de_content;
    if (cloudfs_list_directory(path, &de_content))
    {
      dir_entry* de_tmp;
      pthread_t* threads = (pthread_t*)malloc(MAX_DELETE_THREADS * sizeof(
          pthread_t));
      int active_threads = 0;
      int th_ret, i;
      de_tmp = de_content;
      while (de_tmp)
      {
        if (active_threads < MAX_DELETE_THREADS)
        {
          pthread_create(&threads[active_threads], NULL,
                         (void*)thread_cloudfs_delete_object, de_tmp);
          active_threads++;
        }
        //wait for threads if pool is full or this is the last object
        if (active_threads == MAX_DELETE_THREADS || !de_tmp->next)
          for (i = 0; i < active_threads; i++)
          {
            if ((th_ret = pthread_join(threads[i], NULL)) != 0)
              debugf(DBG_NORM, KRED
                     "cloudfs_delete_object(%s): Error wait thread %d, stat=%d",
                     path, active_threads, th_ret);
            else
              active_threads = 0;
          }
        de_tmp = de_tmp->next;
      }
      free(threads);
    }
    else
      abort();
  }
  if (de)
  {
    //delete manifest file root
    if (is_segmented)
    {
      char manifest_root[MAX_URL_SIZE];
      snprintf(manifest_root, MAX_URL_SIZE, "/%s/%s",
               de->manifest_seg, de->name);
      send_request(HTTP_DELETE, manifest_root, NULL, NULL, NULL, NULL, NULL);
    }
    //delete segment folder
    if (is_dir)
    {
      char manifest_root[MAX_URL_SIZE];
      snprintf(manifest_root, MAX_URL_SIZE, "%s%s_segments",
               HUBIC_SEGMENT_STORAGE_ROOT, de->full_name);
      send_request(HTTP_DELETE, manifest_root, NULL, NULL, NULL, NULL, NULL);
    }
  }
  //delete main object
  int response = send_request(HTTP_DELETE, path, NULL, NULL, NULL, de, NULL);
  bool ret = valid_http_response(response);
  debugf(DBG_EXT, "status: cloudfs_delete_object(%s) response=%d", path,
         response);
  if (response == 409)
  {
    debugf(DBG_EXT, "status: cloudfs_delete_object(%s) NOT EMPTY", path);
    ret = false;
  }
  if (ret && de) //clear cache if ok
    dir_decache(de->full_name);
  return ret;
}

void thread_cloudfs_copy_object(void* arg)
{
  struct thread_copy_job* job = arg;
  dir_entry* de = job->de_src;
  char* dst_encoded = curl_escape(job->dest, 0);
  char* src_encoded = curl_escape(de->full_name, 0);
  //convert encoded string (slashes are encoded as well) to encoded string with slashes
  decode_path(src_encoded);
  curl_slist* headers = NULL;
  //copy file (or manifest) as destination
  if (de->is_segmented && job->manifest)
  {
    //this is the manifest file so add the manifest field
    add_header(&headers, HEADER_TEXT_MANIFEST, job->manifest);
  }
  //add optional header for file size?
  add_header(&headers, HEADER_COPY_FROM, src_encoded);
  add_header(&headers, HEADER_TEXT_CONTENT_LEN, "0");
  //add_header(&headers, "X-Object-Meta-Filepath", job->dest);
  int response = send_request(HTTP_PUT, dst_encoded, NULL, NULL, headers, NULL,
                              NULL);
  int op_ok = valid_http_response(response);
  curl_free(dst_encoded);
  curl_free(src_encoded);
  curl_slist_free_all(headers);
  debugf(DBG_EXT, "exit: th_cloudfs_copy_object(%s) response=%d",
         de->name, response);
  job->result = op_ok;
  if (job->thread_exit)
    pthread_exit(NULL);
  //free is done in parent
}

/*
   creates an empty file on cloud
*/
bool cloudfs_create_object(dir_entry* de)
{
  debugf(DBG_EXT, "cloudfs_create_object(%s): create empty file",
         de->full_name);
  curl_slist* headers = NULL;
  char filemimetype[MAX_PATH_SIZE] = "";
  get_file_mimetype_from_path(de, filemimetype);
  add_header(&headers, HEADER_TEXT_CONTENT_LEN, "0");
  add_header(&headers, HEADER_TEXT_CONTENT_TYPE, filemimetype);
  int response = send_request_size(HTTP_PUT, NULL, NULL, NULL, headers,
                                   0, 0, de, NULL);
  //now file is updated on cloud
  curl_slist_free_all(headers);
  return valid_http_response(response);
}

/* fixme: this op does not preserve src attributes (e.g. will make rsync not work well)
   https://ask.openstack.org/en/question/14307/is-there-a-way-to-moverename-an-object/
   this operation also causes an HTTP 400 error if X-Object-Meta-FilePath value is larger than 256 chars

   if file_only is true, even if de is segmented only copies main file
*/
bool cloudfs_copy_object(dir_entry* de, const char* dst, bool file_only)
{
  debugf(DBG_EXT, "cloudfs_copy_object(%s, %s)", de->name, dst);
  dir_entry* de_versions, *de_tmp;
  dir_entry* new_de = NULL;
  int result = true;
  if (de->is_segmented && !file_only)
  {
    int active_threads = 0;
    pthread_t* threads = (pthread_t*)malloc(MAX_COPY_THREADS * sizeof(pthread_t));
    thread_copy_job* thread_jobs[MAX_COPY_THREADS];
    //copy segments with destination prefix
    assert(de->manifest_cloud);
    int src_seg_count;
    int iterations = 0;
    //todo: optimise this with update_segments
    //get segments from cloud and ensure count matches before copy
    do
    {
      src_seg_count = 0;
      if (cloudfs_list_directory(de->manifest_cloud, &de_versions))
      {
        de_tmp = de_versions;
        while (de_tmp)
        {
          src_seg_count++;
          de_tmp = de_tmp->next;
        }
      }
      else
      {
        //manifest not found
        abort();
      }
      iterations++;
      if (src_seg_count != de->segment_count)
      {
        debugf(DBG_NORM, KRED
               "cloudfs_copy_object(%s): missing src segments expected %d vs %d",
               de->full_name, de->segment_count, src_seg_count);
        if (de_versions)
          cloudfs_free_dir_list(de_versions);
        sleep_ms(1000 * iterations);
      }
    }
    while (src_seg_count != de->segment_count && iterations < REQUEST_RETRIES);
    int th_ret, i;
    new_de = init_dir_entry();
    new_de->is_segmented = true;
    create_entry_meta(dst, new_de);
    create_manifest_meta(new_de);
    char seg_path[MAX_URL_SIZE] = "";
    de_tmp = de_versions;
    for (i = 0; i < MAX_COPY_THREADS; i++)
      thread_jobs[i] = NULL;
    while (de_tmp)
    {
      get_segment_manifest(seg_path, new_de, de_tmp->segment_part);
      //format segment full path
      //snprintf(seg_path, MAX_URL_SIZE, "/%s/%08i", new_de->manifest_time,
      //         de_tmp->segment_part);
      if (active_threads < MAX_COPY_THREADS)
      {
        thread_copy_job* job = init_thread_copy_job();
        job->thread_exit = true;
        assert(!thread_jobs[active_threads]);
        thread_jobs[active_threads] = job;
        job->dest = strdup(seg_path);
        job->de_src = de_tmp;
        job->manifest = strdup(new_de->manifest_time);
        pthread_create(&threads[active_threads], NULL,
                       (void*)thread_cloudfs_copy_object, job);
        active_threads++;
      }
      //wait for threads if pool is full or this is the last object
      if (active_threads == MAX_COPY_THREADS || !de_tmp->next)
      {
        for (i = 0; i < active_threads; i++)
        {
          if ((th_ret = pthread_join(threads[i], NULL)) != 0)
          {
            debugf(DBG_NORM, KRED
                   "cloudfs_copy_object(%s): Error wait thread %d, stat=%d",
                   de->full_name, active_threads, th_ret);
            result = -1;
            abort();
            break;
          }
          else
          {
            debugf(DBG_EXT, KMAG
                   "cloudfs_copy_object(%s): copy done thread %d, stat=%d",
                   de->full_name, i, th_ret);
            if (!(thread_jobs[i]->result))
            {
              debugf(DBG_NORM, KRED
                     "cloudfs_copy_object(%s): Error copy thread %d",
                     de->full_name, i);
              //retry
              abort();
            }
            free_thread_copy_job(thread_jobs[i]);
            thread_jobs[i] = NULL;
          }
        }
        active_threads = 0;
      }
      de_tmp = de_tmp->next;
    }
    assert(src_seg_count > 0 && src_seg_count == de->segment_count);
    if (result)
    {
      //create new dest manifest file
      //note: manifest cannot be set on X-Copy operations?
      curl_slist* headers = NULL;
      char filemimetype[MAX_PATH_SIZE] = "";
      get_file_mimetype_from_path(new_de, filemimetype);
      add_header(&headers, HEADER_TEXT_MANIFEST, new_de->manifest_time);
      add_header(&headers, HEADER_TEXT_CONTENT_LEN, "0");
      add_header(&headers, HEADER_TEXT_CONTENT_TYPE, filemimetype);
      copy_dir_entry(de, new_de, false);
      int response = send_request_size(HTTP_PUT, NULL, NULL, NULL, headers,
                                       0, 0, new_de, NULL);
      //now file is updated on cloud
      curl_slist_free_all(headers);
      if (!valid_http_response(response))
        abort();
      else
      {
        char manifest_root[MAX_URL_SIZE];
        snprintf(manifest_root, MAX_URL_SIZE, "/%s/%s",
                 new_de->manifest_seg, new_de->name);
        //delete older segments from destination, except recent one
        cleanup_older_segments(manifest_root, new_de->manifest_cloud);
        //check if all segments are visible in cloud after copy
        //dir_entry* new_dir_entry;
        int segment_count;
        update_segments(new_de, &segment_count);
        if (segment_count != de->segment_count)
        {
          debugf(DBG_EXT, KRED
                 "cloudfs_copy_object(%s): last segment missing, retry",
                 de->name);
          //still not visible, what to do?
          abort();
        }
        //insert new object in dir_entry list
        append_dir_entry(new_de);
        new_de->metadata_downloaded = false;
        get_file_metadata(new_de, true, true);
      }
    }
    else
    {
      //todo: recover from failed copy, delete garbage?
      dir_decache(new_de->full_name);
    }
    free(threads);
  }
  else//not segmented
  {
    //todo: handle not segmented
    debugf(DBG_EXT, "cloudfs_copy_object: copy non segmented from %s->%s",
           de->full_name, dst);
    thread_copy_job* job = init_thread_copy_job();
    job->thread_exit = false;
    job->dest = strdup(dst);
    job->de_src = de;
    thread_cloudfs_copy_object((void*)job);
    if (job->result && !file_only)//don't get there for simple file copy
    {
      new_de = init_dir_entry();
      new_de->is_segmented = false;
      create_entry_meta(dst, new_de);
      append_dir_entry(new_de);
      new_de->metadata_downloaded = false;
      get_file_metadata(new_de, true, true);
    }
    free_thread_copy_job(job);
    result = job->result;
  }
  debugf(DBG_EXT, "cloudfs_copy_object(%s): exit res=%d", dst, result);
  return result;
}


bool cloudfs_post_object(dir_entry* de)
{
  debugf(DBG_EXT, "cloudfs_post_object(%s) ", de->name);
  char* encoded = curl_escape(de->full_name, 0);
  curl_slist* headers = NULL;
  //add_header(&headers, HEADER_TEXT_CONTENT_LEN, "0");
  if (de->is_segmented)
  {
    char manifest_str[MAX_PATH_SIZE];
    //remove "/" prefix from manifest path
    assert(de->manifest_cloud);
    snprintf(manifest_str, MAX_PATH_SIZE, "%s", de->manifest_cloud + 1);
    add_header(&headers, HEADER_TEXT_MANIFEST, manifest_str);
  }
  int response = send_request_size(HTTP_POST, encoded, NULL, NULL, headers,
                                   0, de->is_segmented, de, NULL);
  curl_free(encoded);
  curl_slist_free_all(headers);
  debugf(DBG_EXT, "exit: cloudfs_post_object(%s) response=%d", de->name,
         response);
  return valid_http_response(response);
}

bool cloudfs_post_object_th(dir_entry* de)
{
  bool res = cloudfs_post_object(de);
  close_lock_file(de->full_name, de->lock_fd);
  assert(res);
  pthread_exit(NULL);
}


/*
   update an existing file metadata on cloud.
   ca be done with COPY (slow) or with POST
   http://developer.openstack.org/api-ref-objectstorage-v1.html#updateObjectMeta
   http://www.17od.com/2012/12/19/ten-useful-openstack-swift-features/
   if sync=true perform meta update on cloud synchro.
*/
bool cloudfs_update_meta(dir_entry* de, bool sync)
{
  debugf(DBG_EXT, "cloudfs_update_meta(%s) ", de->name);
  //copy version
  /*
     int response = cloudfs_copy_object(de->full_name, de->full_name);
     return response;
  */
  //POST version
  //NOTE: this is loosing the segmented meta data. add all fields before post!!!
  pthread_t thread;
  if (sync)
  {
    bool res = cloudfs_post_object(de);
    close_lock_file(de->full_name, de->lock_fd);
    return res;
  }
  else
  {
    pthread_create(&thread, NULL, (void*)cloudfs_post_object_th, de);
    //bool response = cloudfs_post_object(de);
    return true;
  }
}

//optimised with cache
int cloudfs_statfs(const char* path, struct statvfs* stat)
{
  time_t now = get_time_now();
  int lapsed = now - last_stat_read_time;
  if (lapsed > option_cache_statfs_timeout)
  {
    //todo: check why stat head request is always set to /, why not path?
    int response = send_request("HEAD", "/", NULL, NULL, NULL, NULL, NULL);
    *stat = statcache;
    debugf(DBG_EXT,
           "exit: cloudfs_statfs (new recent values, was cached since %d seconds)",
           lapsed);
    last_stat_read_time = now;
    return valid_http_response(response);
  }
  else
  {
    debugf(DBG_EXT,
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
  int response = send_request("MKLINK", dst_encoded, lnk, NULL, NULL, NULL,
                              NULL);
  curl_free(dst_encoded);
  fclose(lnk);
  return (response >= 200 && response < 300);
}

bool cloudfs_create_directory(const char* path)
{
  debugf(DBG_EXT, "cloudfs_create_directory(%s)", path);
  assert(path);
  char* encoded = curl_escape(path, 0);
  int response = send_request("MKDIR", encoded, NULL, NULL, NULL, NULL, NULL);
  curl_free(encoded);
  debugf(DBG_EXT, "cloudfs_create_directory(%s) response=%d",
         path, response);
  return (response >= 200 && response < 300);
}

off_t cloudfs_file_size(int fd)
{
  struct stat buf;
  fstat(fd, &buf);
  return buf.st_size;
}

static struct reconnect_args
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
  debugf(DBG_EXT, "htmlStringGet: starting");
  struct htmlString chunk;
  chunk.text = malloc(sizeof(char));
  chunk.size = 0;
  chunk.text[0] = '\0';//added to avoid valgrind unitialised warning
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &chunk);
  int loops = 0;
  do
  {
    curl_easy_perform(curl);
    debugf(DBG_EXT, "htmlStringGet: perform done, size=%lu", chunk.size);
    loops++;
  }
  while (chunk.size == 0 && loops < REQUEST_RETRIES);
  chunk.text[chunk.size] = '\0';
  debugf(DBG_EXT, "htmlStringGet: done, result=[%s]", chunk.text);
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
    debugf(DBG_NORM, KRED"HUBIC cannot get json field '%s'\n", name);
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
  debugf(DBG_NORM, "Authenticating... (client_id = '%s')", HUBIC_CLIENT_ID);
  storage_token[0] = storage_url[0] = '\0';
  debugf(DBG_NORM, "CURL init...");
  CURL* curl = curl_easy_init();
  debugf(DBG_NORM, "CURL init OK...");
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
  debug_http(HTTP_POST, HUBIC_TOKEN_URL);
  char* json_str = htmlStringGet(curl);
  json_obj = json_tokener_parse(json_str);
  debugf(DBG_NORM, "HUBIC TOKEN_URL result: '%s'\n", json_str);
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
  debugf(DBG_NORM, "HUBIC Access token: %s\n", access_token);
  debugf(DBG_NORM, "HUBIC Token type  : %s\n", token_type);
  debugf(DBG_NORM, "HUBIC Expire in   : %d\n", expire_sec);
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
  debug_http(HTTP_GET, HUBIC_CRED_URL);
  json_str = htmlStringGet(curl);
  json_obj = json_tokener_parse(json_str);
  debugf(DBG_NORM, "CRED_URL result: '%s'\n", json_str);
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
