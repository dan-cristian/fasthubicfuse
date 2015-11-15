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
#include "commonfs.h"
#include "cloudfsapi.h"
#include "config.h"
#include <fuse.h>

#define RHEL5_LIBCURL_VERSION 462597
#define RHEL5_CERTIFICATE_FILE "/etc/pki/tls/certs/ca-bundle.crt"

#define REQUEST_RETRIES 1

#define MAX_FILES 10000

// 64 bit time + nanoseconds
#define TIME_CHARS 32

// size of buffer for writing to disk look at ioblksize.h in coreutils
// and try some values on your own system if you want the best performance
#define DISK_BUFF_SIZE 32768

static char storage_url[MAX_URL_SIZE];
static char storage_token[MAX_HEADER_SIZE];
static pthread_mutex_t pool_mut;
static CURL *curl_pool[1024];
static int curl_pool_count = 0;
extern int debug;
static int verify_ssl = 2;
static bool option_get_extended_metadata = false;
static bool option_curl_verbose = false;
static int rhel5_mode = 0;
static struct statvfs statcache = {
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

#ifdef HAVE_OPENSSL
#include <openssl/crypto.h>
static pthread_mutex_t *ssl_lockarray;
static void lock_callback(int mode, int type, char *file, int line)
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


static size_t xml_dispatch(void *ptr, size_t size, size_t nmemb, void *stream)
{
  xmlParseChunk((xmlParserCtxtPtr)stream, (char *)ptr, size * nmemb, 0);
  return size * nmemb;
}

static CURL *get_connection(const char *path)
{
  pthread_mutex_lock(&pool_mut);
  CURL *curl = curl_pool_count ? curl_pool[--curl_pool_count] : curl_easy_init();
  if (!curl)
  {
    debugf("curl alloc failed");
    abort();
  }
  pthread_mutex_unlock(&pool_mut);
  return curl;
}

static void return_connection(CURL *curl)
{
  pthread_mutex_lock(&pool_mut);
  curl_pool[curl_pool_count++] = curl;
  pthread_mutex_unlock(&pool_mut);
}

static void add_header(curl_slist **headers, const char *name,
                       const char *value)
{
  char x_header[MAX_HEADER_SIZE];
  snprintf(x_header, sizeof(x_header), "%s: %s", name, value);
  *headers = curl_slist_append(*headers, x_header);
}

static size_t header_dispatch(void *ptr, size_t size, size_t nmemb, void *stream)
{
  //debugf("Dispatching response headers");
  char *header = (char *)alloca(size * nmemb + 1);
  char *head = (char *)alloca(size * nmemb + 1);
  char *value = (char *)alloca(size * nmemb + 1);
  memcpy(header, (char *)ptr, size * nmemb);
  header[size * nmemb] = '\0';
  if (sscanf(header, "%[^:]: %[^\r\n]", head, value) == 2)
  {
    if (!strncasecmp(head, "x-auth-token", size * nmemb))
      strncpy(storage_token, value, sizeof(storage_token));
    if (!strncasecmp(head, "x-storage-url", size * nmemb))
      strncpy(storage_url, value, sizeof(storage_url));
    if (!strncasecmp(head, "x-account-meta-quota", size * nmemb))
      statcache.f_blocks = (unsigned long) (strtoull(value, NULL, 10)/statcache.f_frsize);
    if (!strncasecmp(head, "x-account-bytes-used", size * nmemb))
      statcache.f_bfree = statcache.f_bavail = statcache.f_blocks - (unsigned long) (strtoull(value, NULL, 10)/statcache.f_frsize);
    if (!strncasecmp(head, "x-account-object-count", size * nmemb)) {
      unsigned long object_count = strtoul(value, NULL, 10);
      statcache.f_ffree = MAX_FILES - object_count;
      statcache.f_favail = MAX_FILES - object_count;
    }
  }
  return size * nmemb;
}

static void header_set_time_from_str(char *time_str, struct timespec *time_entry){
  char sec_value[TIME_CHARS];
  char nsec_value[TIME_CHARS];
  time_t sec;
  long nsec;
  sscanf(time_str, "%[^.].%[^\n]", sec_value, nsec_value);
  sec = strtoll(sec_value, NULL, 10);//to allow for larger numbers
  //nsec = atol(nsec_value);
	nsec = strtoll(nsec_value, NULL, 10);
  debugf("Received time=%s.%s / %li.%li, existing=%li.%li", sec_value, nsec_value, sec, nsec, time_entry->tv_sec, time_entry->tv_nsec);
  if (sec != time_entry->tv_sec || nsec != time_entry->tv_nsec){
    debugf("Time changed, setting new time=%li.%li, existing was=%li.%li", sec, nsec, time_entry->tv_sec, time_entry->tv_nsec);
    time_entry->tv_sec = atol(sec_value);
    time_entry->tv_nsec = atol(nsec_value);
  }
}

static size_t header_get_utimens_dispatch(void *ptr, size_t size, size_t nmemb, void *userdata)
{
  //debugf("Dispatching utimens response headers");
  char *header = (char *)alloca(size * nmemb + 1);
  char *head = (char *)alloca(size * nmemb + 1);
  char *value = (char *)alloca(size * nmemb + 1);
  memcpy(header, (char *)ptr, size * nmemb);
  header[size * nmemb] = '\0';
  static char storage[MAX_HEADER_SIZE];
  if (sscanf(header, "%[^:]: %[^\r\n]", head, value) == 2)
  {
    //strncpy(storage, header, sizeof(storage));
    //debugf("received utimens header=[%s]", storage);
    strncpy(storage, head, sizeof(storage));
    dir_entry *de = (dir_entry*)userdata;
		if (de != NULL) {
			if (!strncasecmp(head, HEADER_TEXT_ATIME, size * nmemb)) {
				header_set_time_from_str(value, &de->atime);
			}
			if (!strncasecmp(head, HEADER_TEXT_CTIME, size * nmemb)) {
				header_set_time_from_str(value, &de->ctime);
			}
			if (!strncasecmp(head, HEADER_TEXT_MTIME, size * nmemb)) {
				header_set_time_from_str(value, &de->mtime);
			}
		}
		else {
			debugf("Unexpected NULL dir_entry on header(%s), file should be in cache already", storage);
		}
  }
  else {
    //debugf("Received unexpected header line");
  }
  return size * nmemb;
}

static size_t rw_callback(size_t (*rw)(void*, size_t, size_t, FILE*), void *ptr,
        size_t size, size_t nmemb, void *userp)
{
    struct segment_info *info = (struct segment_info *)userp;
    size_t mem = size * nmemb;

    if (mem < 1 || info->size < 1)
      return 0;

    size_t amt_read = rw(ptr, 1, info->size < mem ? info->size : mem, info->fp);
    info->size -= amt_read;

    return amt_read;
}

size_t fwrite2(void *ptr, size_t size, size_t nmemb, FILE *filep)
{
    return fwrite((const void*)ptr, size, nmemb, filep);
}

static size_t read_callback(void *ptr, size_t size, size_t nmemb, void *userp)
{
    return rw_callback(fread, ptr, size, nmemb, userp);
}

static size_t write_callback(void *ptr, size_t size, size_t nmemb, void *userp)
{
   return rw_callback(fwrite2, ptr, size, nmemb, userp);
}

//http://curl.haxx.se/libcurl/c/CURLOPT_XFERINFOFUNCTION.html
int progress_callback_xfer(void *clientp, curl_off_t dltotal, curl_off_t dlnow, curl_off_t ultotal, curl_off_t ulnow){
  struct curl_progress *myp = (struct curl_progress *)clientp;
  CURL *curl = myp->curl;
  double curtime = 0;
  double dspeed = 0, uspeed=0;

  curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &curtime);
  curl_easy_getinfo(curl, CURLINFO_SPEED_DOWNLOAD, &dspeed);
  curl_easy_getinfo(curl, CURLINFO_SPEED_UPLOAD, &uspeed);

  /* under certain circumstances it may be desirable for certain functionality
  to only run every N seconds, in order to do this the transaction time can
  be used */
  //http://curl.haxx.se/cvssource/src/tool_cb_prg.c
  if ((curtime - myp->lastruntime) >= MINIMAL_PROGRESS_FUNCTIONALITY_INTERVAL) {
    myp->lastruntime = curtime;
    curl_off_t total;
    curl_off_t point;
    double frac, percent;
    total = dltotal + ultotal;
    point = dlnow + ulnow;
    frac = (double)point / (double)total;
    percent = frac * 100.0f;
    debugf("TOTAL TIME: %.0f sec Down=%.0f Kbps UP=%.0f Kbps", curtime, dspeed/1024, uspeed/1024);
    debugf("UP: %lld of %lld DOWN: %lld/%lld Completion %.1f %%", ulnow, ultotal, dlnow, dltotal, percent);
  }

  //#define STOP_DOWNLOAD_AFTER_THIS_MANY_BYTES         6000
  //if (dlnow > STOP_DOWNLOAD_AFTER_THIS_MANY_BYTES)
  //  return 1;
  return 0;
}

//http://curl.haxx.se/libcurl/c/CURLOPT_PROGRESSFUNCTION.html
int progress_callback(void *clientp, double dltotal, double dlnow, double ultotal, double ulnow){
  return progress_callback_xfer(clientp, (curl_off_t)dltotal, (curl_off_t)dlnow, (curl_off_t)ultotal, (curl_off_t)ulnow);
}

// de_cached_entry must be NULL when the file is already in global cache
// otherwise point to a new dir_entry that will be added to the cache (usually happens on fir dir load)
static int send_request_size(const char *method, const char *path, void *fp,
                        xmlParserCtxtPtr xmlctx, curl_slist *extra_headers,
                        off_t file_size, int is_segment,
												dir_entry *de_cached_entry)
{
  debugf(KYEL "send_request_size(%s) (%s)", path, method);
  char url[MAX_URL_SIZE];
  char orig_path[MAX_URL_SIZE];
  char header_data[MAX_HEADER_SIZE];

  char *slash;
  long response = -1;
  int tries = 0;

  if (!storage_url[0])
  {
    debugf("send_request with no storage_url?");
    abort();
  }

  while ((slash = strstr(path, "%2F")) || (slash = strstr(path, "%2f")))
  {
    *slash = '/';
    memmove(slash+1, slash+3, strlen(slash+3)+1);
  }
  while (*path == '/')
    path++;
  snprintf(url, sizeof(url), "%s/%s", storage_url, path);
  snprintf(orig_path, sizeof(orig_path), "/%s", path);

  // retry on failures
  for (tries = 0; tries < REQUEST_RETRIES; tries++)
  {
    CURL *curl = get_connection(path);
    if (rhel5_mode)
      curl_easy_setopt(curl, CURLOPT_CAINFO, RHEL5_CERTIFICATE_FILE);
    curl_slist *headers = NULL;
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HEADER, 0);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0);//0=enable progress
    curl_easy_setopt(curl, CURLOPT_USERAGENT, USER_AGENT);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, verify_ssl ? 1 : 0);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, verify_ssl);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10);
		curl_easy_setopt(curl, CURLOPT_VERBOSE, option_curl_verbose ? 1 : 0);
    add_header(&headers, "X-Auth-Token", storage_token);
    /**/
    //debugf("Get file from cache, path=%s, orig=%s, url=%s", path, orig_path, url);dir_entry *de = local_path_info(orig_path);
    //dir_entry *de = local_path_info(orig_path);
		dir_entry *de;
		if (de_cached_entry == NULL) {
			de = check_path_info(orig_path);
		}
		else {
			// updating metadata on a file to be added to cache
			de = de_cached_entry;
		}
		if (!de) {
			//debugf(KRED "No file found in cache for path=%s", orig_path);
		}
    else {
      //debugf("File found in cache, path=%s", de->full_name);
      debugf("Cached utime for path=%s ctime=%li.%li mtime=%li.%li atime=%li.%li", orig_path,
        de->ctime.tv_sec, de->ctime.tv_nsec, de->mtime.tv_sec, de->mtime.tv_nsec, de->atime.tv_sec, de->atime.tv_nsec);
      // add headers to save utimens attribs only on upload
      if ((!strcasecmp(method, "PUT") && fp) || (!strcasecmp(method, "MKDIR"))) {
        debugf("Saving utimens to file %s", orig_path);
        char mtime_str[TIME_CHARS], atime_str[TIME_CHARS], ctime_str[TIME_CHARS];
        char string_float[TIME_CHARS];
        snprintf(string_float, TIME_CHARS, "%lu.%lu", de->mtime.tv_sec, de->mtime.tv_nsec);
        snprintf(mtime_str, TIME_CHARS, "%f", atof(string_float));
        snprintf(string_float, TIME_CHARS, "%lu.%lu", de->atime.tv_sec, de->atime.tv_nsec);
        snprintf(atime_str, TIME_CHARS, "%f", atof(string_float));
        snprintf(string_float, TIME_CHARS, "%lu.%lu", de->ctime.tv_sec, de->ctime.tv_nsec);
        snprintf(ctime_str, TIME_CHARS, "%f", atof(string_float));
        add_header(&headers, HEADER_TEXT_FILEPATH, orig_path);
        add_header(&headers, HEADER_TEXT_MTIME, mtime_str);
        add_header(&headers, HEADER_TEXT_ATIME, atime_str);
        add_header(&headers, HEADER_TEXT_CTIME, ctime_str);
      }
    }
    /**/
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
      //curl_easy_setopt(curl, CURLOPT_INFILESIZE, 0);
      curl_easy_setopt(curl, CURLOPT_INFILESIZE, file_size);
      curl_easy_setopt(curl, CURLOPT_READDATA, fp);
      add_header(&headers, "Content-Type", "application/link");
    }
    else if (!strcasecmp(method, "PUT") && fp)
    {
      curl_easy_setopt(curl, CURLOPT_UPLOAD, 1);
      curl_easy_setopt(curl, CURLOPT_INFILESIZE, file_size);
      curl_easy_setopt(curl, CURLOPT_READDATA, fp);
      if (is_segment)
        curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);
      //enable progress reporting
      //http://curl.haxx.se/libcurl/c/progressfunc.html
      struct curl_progress prog;
      prog.lastruntime = 0;
      prog.curl = curl;
      curl_easy_setopt(curl, CURLOPT_PROGRESSFUNCTION, progress_callback);
      /* pass the struct pointer into the progress function */
      curl_easy_setopt(curl, CURLOPT_PROGRESSDATA, &prog);
    }
    else if (!strcasecmp(method, "GET"))
    {
      if (is_segment)
      {
        debugf("GET file segment path=%s", orig_path);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
      }
      else if (fp)
      {
        debugf("GET file FP path=%s", orig_path);
        rewind(fp); // make sure the file is ready for a-writin'
        fflush(fp);
        if (ftruncate(fileno(fp), 0) < 0)
        {
          debugf("ftruncate failed.  I don't know what to do about that.");
          abort();
        }
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, &header_get_utimens_dispatch);
        // inspired by UThreadCurl.cpp, https://bitbucket.org/pamungkas5/bcbcurl/src
        // and http://www.codeproject.com/Articles/838366/BCBCurl-a-LibCurl-based-download-manager
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, (void *)de);

        struct curl_progress prog;
        prog.lastruntime = 0;
        prog.curl = curl;
        curl_easy_setopt(curl, CURLOPT_PROGRESSFUNCTION, progress_callback);
        curl_easy_setopt(curl, CURLOPT_PROGRESSDATA, &prog);
      }
      else if (xmlctx)
      {
        debugf("GET file XML path=%s", orig_path);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, xmlctx);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &xml_dispatch);
      }
      else {
        //asumming retrieval of headers only
        debugf("Attempt to retrieve only headers");
        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, &header_get_utimens_dispatch);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, (void *)de);
        curl_easy_setopt(curl, CURLOPT_NOBODY, 1);
      }
    }
    else
    {
			// this posts an HEAD request (e.g. for statfs)
      curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
      curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, &header_dispatch);
    }
    /* add the headers from extra_headers if any */
    curl_slist *extra;
    for (extra = extra_headers; extra; extra = extra->next)
    {
      debugf("adding header: %s", extra->data);
      headers = curl_slist_append(headers, extra->data);
    }
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
		debugf("status: send_request_size(%s) " KYEL "started HTTP REQ:%s", orig_path, url);
    curl_easy_perform(curl);
		double total_time;
		char *effective_url;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response);
		curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &effective_url);
		curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &total_time);
		debugf("status: send_request_size(%s) " KYEL "completed HTTP REQ:%s total_time=%.1f seconds", orig_path, effective_url, total_time);
		curl_slist_free_all(headers);
    curl_easy_reset(curl);
    return_connection(curl);
		if ((response >= 200 && response < 400) || (!strcasecmp(method, "DELETE") && response == 409)) {
			debugf("exit 0: send_request_size(%s) (%s) %s[HTTP OK]", path, method, KGRN);
			return response;
		}
    //handle cases when segment is not found
    if (response == 404){
      debugf("Received 404 for %s, most likely segment not found, ignore %s[HTTP OK]", method, KYEL);
    }
    else {
      // now you can add a delay here
			debugf("Received http code=%d %s %s[HTTP ERR]", method, KRED);
      sleep(0 << tries); // backoff
    }
		if (response == 401 && !cloudfs_connect()) { // re-authenticate on 401s 
			debugf("exit 1: send_request_size(%s) (%s) %s[HTTP REAUTH]", path, method, KYEL);
			return response;
		}
    if (xmlctx)
      xmlCtxtResetPush(xmlctx, NULL, 0, NULL, NULL);
  }
	debugf("exit 2: send_request_size(%s) (%s)", path, method);
  return response;
}

static int send_request(char *method, const char *path, FILE *fp,
                        xmlParserCtxtPtr xmlctx, curl_slist *extra_headers, dir_entry *de_cached_entry)
{

    long flen = 0;
    if (fp) {
      // if we don't flush the size will probably be zero
      fflush(fp);
      flen = cloudfs_file_size(fileno(fp));
    }

    return send_request_size(method, path, fp, xmlctx, extra_headers, flen, 0, de_cached_entry);

}

void *upload_segment(void *seginfo)
{
  struct segment_info *info = (struct segment_info *)seginfo;
  
  char seg_path[MAX_URL_SIZE] = { 0 };

  fseek(info->fp, info->part * info->segment_size, SEEK_SET);
  setvbuf(info->fp, NULL, _IOFBF, DISK_BUFF_SIZE);

  snprintf(seg_path, MAX_URL_SIZE, "%s%08i", info->seg_base, info->part);
  char *encoded = curl_escape(seg_path, 0);

  debugf("Uploading segment=%s path=%s", info->method, seg_path);

  int response = send_request_size(info->method, encoded, info, NULL, NULL,
      info->size, 1, NULL);

  if (!(response >= 200 && response < 300))
    fprintf(stderr, "Segment upload %s failed with response %d", seg_path,
         response);

  curl_free(encoded);
  fclose(info->fp);
  pthread_exit(NULL);
}

// segment_size is the globabl config variable and size_of_segment is local
//TODO: return whether the upload/download failed or not
void run_segment_threads(const char *method, int segments, int full_segments, int remaining,
        FILE *fp, char *seg_base, int size_of_segments)
{
    char file_path[PATH_MAX] = { 0 };
    struct segment_info *info = (struct segment_info *)
            malloc(segments * sizeof(struct segment_info));

    pthread_t *threads = (pthread_t *)malloc(segments * sizeof(pthread_t));
#ifdef __linux__
    snprintf(file_path, PATH_MAX, "/proc/self/fd/%d", fileno(fp));
    debugf("On run segment filepath=%s", file_path);
#else
    //TODO: I haven't actually tested this
    if (fcntl(fileno(fp), F_GETPATH, file_path) == -1)
      fprintf(stderr, "couldn't get the path name\n");
#endif

    int i, ret;
    for (i = 0; i < segments; i++) {
      info[i].method = method;
      info[i].fp = fopen(file_path, method[0] == 'G' ? "r+" : "r");
      info[i].part = i;
      info[i].segment_size = size_of_segments;
      info[i].size = i < full_segments ? size_of_segments : remaining;
      info[i].seg_base = seg_base;
      pthread_create(&threads[i], NULL, upload_segment, (void *)&(info[i]));
      //set a thread name for debug purposes
      pthread_setname_np(threads[i], "run_segment");
    }

    for (i = 0; i < segments; i++) {
      if ((ret = pthread_join(threads[i], NULL)) != 0)
        fprintf(stderr, "error waiting for thread %d, status = %d\n", i, ret);
    }
    free(info);
    free(threads);
}

void split_path(const char *path, char *seg_base, char *container,
        char *object)
{
  char *string = strdup(path);
  snprintf(seg_base, MAX_URL_SIZE, "%s", strsep(&string, "/"));
  strncat(container, strsep(&string, "/"),
      MAX_URL_SIZE - strnlen(container, MAX_URL_SIZE));
  char *_object = strsep(&string, "/");
	
  char *remstr;

  while (remstr = strsep(&string, "/")) {
		strncat(container, "/",
          MAX_URL_SIZE - strnlen(container, MAX_URL_SIZE));
      strncat(container, _object,
          MAX_URL_SIZE - strnlen(container, MAX_URL_SIZE));
      _object = remstr;
  }
	//fixme: when removing root folders this will generate a segfault
	if (_object == NULL)
		_object = object;
	else
		strncpy(object, _object, MAX_URL_SIZE);
	free(string);
}

int internal_is_segmented(const char *seg_path, const char *object)
{
  debugf("internal_is_segmented(%s)", seg_path);
  dir_entry *seg_dir;
  if (cloudfs_list_directory(seg_path, &seg_dir)) {
    if (seg_dir && seg_dir->isdir) {
        do {
            if (!strncmp(seg_dir->name, object, MAX_URL_SIZE)) {
							debugf("exit 1: internal_is_segmented(%s)", seg_path);
                return 1;
            }
        } while ((seg_dir = seg_dir->next));
    }
  }
	debugf("exit 0: internal_is_segmented(%s)", seg_path);
  return 0;
}

int is_segmented(const char *path)
{
  char container[MAX_URL_SIZE] = "";
  char object[MAX_URL_SIZE] = "";
  char seg_base[MAX_URL_SIZE] = "";

  split_path(path, seg_base, container, object);

  char seg_path[MAX_URL_SIZE];
  snprintf(seg_path, MAX_URL_SIZE, "%s/%s_segments", seg_base, container);

  return internal_is_segmented(seg_path, object);
}


int format_segments(const char *path, char * seg_base,  long *segments,
        long *full_segments, long *remaining, long *size_of_segments)
{
  debugf("format_segments(%s)", path);
  char container[MAX_URL_SIZE] = "";
  char object[MAX_URL_SIZE] = "";

	debugf(KMAG"split(%s)(%s)", path, seg_base);
  split_path(path, seg_base, container, object);
	debugf(KMAG"endsplit(%s)(%s)", container, object);

  char seg_path[MAX_URL_SIZE];
  snprintf(seg_path, MAX_URL_SIZE, "%s/%s_segments", seg_base, container);

  //todo: try to avoid one additional http request for small files
  int issegmented;
  //dir_entry *de = local_path_info(path);
  dir_entry *de = check_path_info(path);
  if (!de) {
    issegmented = -1;
  }
  else {
    if (de->size >= segment_above)
      issegmented = 1;
    else
      issegmented = 0;
  }
  debugf("File segmented=%d", issegmented);
  //end change

  if (internal_is_segmented(seg_path, object)) {
    char manifest[MAX_URL_SIZE];
    dir_entry *seg_dir;

    snprintf(manifest, MAX_URL_SIZE, "%s/%s", seg_path, object);
		if (!cloudfs_list_directory(manifest, &seg_dir)) {
			debugf("exit 0: format_segments(%s)", path);
			return 0;
		}

    // snprintf seesaw between manifest and seg_path to get
    // the total_size and the segment size as well as the actual objects
    char *timestamp = seg_dir->name;
    snprintf(seg_path, MAX_URL_SIZE, "%s/%s", manifest, timestamp);
		if (!cloudfs_list_directory(seg_path, &seg_dir)) {
			debugf("exit 1: format_segments(%s)", path);
			return 0;
		}

    char *str_size = seg_dir->name;
    snprintf(manifest, MAX_URL_SIZE, "%s/%s", seg_path, str_size);
		if (!cloudfs_list_directory(manifest, &seg_dir)) {
			debugf("exit 2: format_segments(%s)", path);
			return 0;
		}

    char *str_segment = seg_dir->name;
    snprintf(seg_path, MAX_URL_SIZE, "%s/%s", manifest, str_segment);
		if (!cloudfs_list_directory(seg_path, &seg_dir)) {
			debugf("exit 3: format_segments(%s)", path);
			return 0;
		}

    long total_size = strtoll(str_size, NULL, 10);
    *size_of_segments = strtoll(str_segment, NULL, 10);

    *remaining = total_size % *size_of_segments;
    *full_segments = total_size / *size_of_segments;
    *segments = *full_segments + (*remaining > 0);

    snprintf(manifest, MAX_URL_SIZE, "%s_segments/%s/%s/%s/%s/",
        container, object, timestamp, str_size, str_segment);

    char tmp[MAX_URL_SIZE];
    strncpy(tmp, seg_base, MAX_URL_SIZE);
    snprintf(seg_base, MAX_URL_SIZE, "%s/%s", tmp, manifest);

		debugf("exit 4: format_segments(%s)", path);
    return 1;
  }

  else {
		debugf("exit 5: format_segments(%s)", path);
    return 0;
  }
}

/*
 * Public interface
 */

void cloudfs_init()
{
  LIBXML_TEST_VERSION
  xmlXPathInit();
  curl_global_init(CURL_GLOBAL_ALL);
  pthread_mutex_init(&pool_mut, NULL);
  curl_version_info_data *cvid = curl_version_info(CURLVERSION_NOW);

  // CentOS/RHEL 5 get stupid mode, because they have a broken libcurl
  if (cvid->version_num == RHEL5_LIBCURL_VERSION)
  {
    debugf("RHEL5 mode enabled.");
    rhel5_mode = 1;
  }

  if (!strncasecmp(cvid->ssl_version, "openssl", 7))
  {
    #ifdef HAVE_OPENSSL
    int i;
    ssl_lockarray = (pthread_mutex_t *)OPENSSL_malloc(CRYPTO_num_locks() *
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
  debugf("Destroy mutex");
  pthread_mutex_destroy(&pool_mut);
  int n;
  for (n = 0; n < curl_pool_count; ++n) {
    debugf("Cleaning curl conn %d", n);
    curl_easy_cleanup(curl_pool[n]);
  }
}


int file_is_readable(const char *fname)
{
    FILE *file;
    if ( file = fopen( fname, "r" ) )
    {
        fclose( file );
        return 1;
    }
    return 0;
}

const char * get_file_mimetype ( const char *path )
{
    if( file_is_readable( path ) == 1 )
    {
      magic_t magic;
      const char *mime;

      magic = magic_open( MAGIC_MIME_TYPE );
      magic_load( magic, NULL );
      magic_compile( magic, NULL );
      mime = magic_file( magic, path );
      magic_close( magic );

      return mime;
  }

  const char *error = "application/octet-stream";
  return error;
}


int cloudfs_object_read_fp(const char *path, FILE *fp)
{
  debugf("cloudfs_object_read_fp path=%s", path);
  long flen;
  fflush(fp);
  const char *filemimetype = get_file_mimetype( path );

  // determine the size of the file and segment if it is above the threshhold
  fseek(fp, 0, SEEK_END);
  flen = ftell(fp);

  // delete the previously uploaded segments
  if (is_segmented(path)) {
    if (!cloudfs_delete_object(path))
      debugf("Couldn't delete one of the existing files while uploading.");
  }
  
  struct timespec now;
  if (flen >= segment_above) {
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

    run_segment_threads("PUT", segments, full_segments, remaining, fp,
            seg_base, segment_size);

    char *encoded = curl_escape(path, 0);
    curl_slist *headers = NULL;
    add_header(&headers, "x-object-manifest", manifest);
    //utimens changes, not needed anymore
    //add_header(&headers, "x-object-meta-mtime", meta_mtime);
    add_header(&headers, "Content-Length", "0");
    add_header(&headers, "Content-Type", filemimetype);

    int response = send_request_size("PUT", encoded, NULL, NULL, headers, 0, 0, NULL);
    curl_slist_free_all(headers);

    curl_free(encoded);
    debugf("cloudfs_object_read_fp COMPLETED 1 path=%s", path);
    return (response >= 200 && response < 300);
  }
  else{
    // assume enters here when file is composed of only one segment (small files)
    debugf("cloudfs_object_read_fp ELSE path=%s", path);
  }

  rewind(fp);
  char *encoded = curl_escape(path, 0);
  // utimens changes
  //dir_entry *de = local_path_info(path);
  dir_entry *de = path_info(path);
  if (!de)
    debugf("No file found in cache at cloudfs_object_read_fp for path=%s", path);
  else {
    debugf("cloudfs_object_read_fp Mark utimens attribs as changed now for path=%", path);
    clock_gettime(CLOCK_REALTIME, &now);
    de->atime.tv_sec = now.tv_sec;
    de->atime.tv_nsec = now.tv_nsec;
    de->mtime.tv_sec = now.tv_sec;
    de->mtime.tv_nsec = now.tv_nsec;
    de->ctime.tv_sec = now.tv_sec;
    de->ctime.tv_nsec = now.tv_nsec;
  }
  // end changes
  int response = send_request("PUT", encoded, fp, NULL, NULL, NULL);
  curl_free(encoded);
  debugf("cloudfs_object_read_fp COMPLETED 2 path=%s", path);
  return (response >= 200 && response < 300);
}

//write file downloaded from cloud to local file
int cloudfs_object_write_fp(const char *path, FILE *fp)
{
  debugf("cloudfs_object_write_fp(%s)", path);
  char *encoded = curl_escape(path, 0);
  char seg_base[MAX_URL_SIZE] = "";

  long segments;
  long full_segments;
  long remaining;
  long size_of_segments;

  if (format_segments(path, seg_base, &segments, &full_segments, &remaining,
        &size_of_segments)) {

    rewind(fp);
    fflush(fp);

    if (ftruncate(fileno(fp), 0) < 0)
    {
      debugf("ftruncate failed.  I don't know what to do about that.");
      abort();
    }
    //fixme: this might be unnecessary as it looks for segments when you only want to read a small file
    debugf("Checking for segment for file %s", path);
    run_segment_threads("GET", segments, full_segments, remaining, fp,
            seg_base, size_of_segments);
		debugf("exit 0: cloudfs_object_write_fp(%s)", path);
    return 1;
  }

  int response = send_request("GET", encoded, fp, NULL, NULL, NULL);
  curl_free(encoded);
  fflush(fp);
	if ((response >= 200 && response < 300) || ftruncate(fileno(fp), 0)) {
		debugf("exit 1: cloudfs_object_write_fp(%s)", path);
		return 1;
	}
  rewind(fp);
	debugf("exit 2: cloudfs_object_write_fp(%s)", path);
  return 0;
}

int cloudfs_object_truncate(const char *path, off_t size)
{
  char *encoded = curl_escape(path, 0);
  int response;
  if (size == 0)
  {
    FILE *fp = fopen("/dev/null", "r");
    response = send_request("PUT", encoded, fp, NULL, NULL, NULL);
    fclose(fp);
  }
  else
  {//TODO: this is busted
    response = send_request("GET", encoded, NULL, NULL, NULL, NULL);
  }
  curl_free(encoded);
  return (response >= 200 && response < 300);
}

//get metadata from cloud, like time attribs. create new entry if not cached yet.
void get_file_metadata(dir_entry *de){
	if (option_get_extended_metadata) {
		debugf(KCYN "get_file_metadata(%s)", de->full_name);
		//retrieve additional file metadata with a quick HEAD query
		char *encoded = curl_escape(de->full_name, 0);
		int response = send_request("GET", encoded, NULL, NULL, NULL, de);
		curl_free(encoded);
		debugf(KCYN "exit: get_file_metadata(%s)", de->full_name);
	}
	return;
}

//get list of folders from cloud
// return 1 for OK, 0 for error
int cloudfs_list_directory(const char *path, dir_entry **dir_list)
{
  debugf("cloudfs_list_directory(%s)", path);
  char container[MAX_PATH_SIZE * 3] = "";
  char object[MAX_PATH_SIZE] = "";
  char last_subdir[MAX_PATH_SIZE] = "";
  int prefix_length = 0;
  int response = 0;
  int retval = 0;
  int entry_count = 0;

  *dir_list = NULL;
  xmlNode *onode = NULL, *anode = NULL, *text_node = NULL;
  xmlParserCtxtPtr xmlctx = xmlCreatePushParserCtxt(NULL, NULL, "", 0, NULL);
  if (!strcmp(path, "") || !strcmp(path, "/"))
  {
    path = "";
    strncpy(container, "/?format=xml", sizeof(container));
  }
  else
  {
    sscanf(path, "/%[^/]/%[^\n]", container, object);
    char *encoded_container = curl_escape(container, 0);
    char *encoded_object = curl_escape(object, 0);

    // The empty path doesn't get a trailing slash, everything else does
    char *trailing_slash;
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
  else{
    // this generates 404 err on non segmented files (small files)
    response = send_request("GET", container, NULL, xmlctx, NULL, NULL);
  }

  if (response >= 200 && response < 300)
    xmlParseChunk(xmlctx, "", 0, 1);
  if (response >= 200 && response < 300 && xmlctx->wellFormed )
  {
    xmlNode *root_element = xmlDocGetRootElement(xmlctx->myDoc);
    for (onode = root_element->children; onode; onode = onode->next)
    {
      if (onode->type != XML_ELEMENT_NODE) continue;

      char is_object = !strcasecmp((const char *)onode->name, "object");
      char is_container = !strcasecmp((const char *)onode->name, "container");
      char is_subdir = !strcasecmp((const char *)onode->name, "subdir");

      if (is_object || is_container || is_subdir)
      {
        entry_count++;
        //debugf("Create empty cache entry cloudfs_list_directory for path=%s", path);
        dir_entry *de = (dir_entry *)malloc(sizeof(dir_entry));
        de->next = NULL;
        de->size = 0;
        de->last_modified = time(NULL);
        // utimens changes, initialise additional fields as empty
        de->mtime.tv_sec = time(NULL);
        de->atime.tv_sec = time(NULL);
        de->ctime.tv_sec = time(NULL);
        de->mtime.tv_nsec = 0;
        de->atime.tv_nsec = 0;
        de->ctime.tv_nsec = 0;
        de->md5sum = NULL;
        // change end
        
        //http://developer.openstack.org/api-ref-objectstorage-v1.html
        if (is_container || is_subdir)
          de->content_type = strdup("application/directory");
        for (anode = onode->children; anode; anode = anode->next)
        {
          char *content = "<?!?>";
          for (text_node = anode->children; text_node; text_node = text_node->next){
            if (text_node->type == XML_TEXT_NODE){
              content = (char *)text_node->content;
              //debugf("List dir anode=%s content=%s", (const char *)anode->name, content);
            }
            else {
              //debugf("List dir anode=%s", (const char *)anode->name);
            }
          }
          if (!strcasecmp((const char *)anode->name, "name"))
          {
            de->name = strdup(content + prefix_length);

            // Remove trailing slash
            char *slash = strrchr(de->name, '/');
            if (slash && (0 == *(slash + 1)))
              *slash = 0;

            if (asprintf(&(de->full_name), "%s/%s", path, de->name) < 0){
              de->full_name = NULL;
            }
            
          }
          //debugf("List DIR anode=%s", de->name);
          if (!strcasecmp((const char *)anode->name, "bytes"))
            de->size = strtoll(content, NULL, 10);
          if (!strcasecmp((const char *)anode->name, "content_type"))
          {
            de->content_type = strdup(content);
            char *semicolon = strchr(de->content_type, ';');
            if (semicolon)
              *semicolon = '\0';
          }
          if (!strcasecmp((const char *)anode->name, "hash"))
          {
            de->md5sum = strdup(content);
          }
          if (!strcasecmp((const char *)anode->name, "last_modified"))
          {
            time_t last_modified_t = get_time_from_str_as_gmt(content);
            //debugf("Got cloudfs_list_directory path=%s remote_time=%li.0 [%s]", de->name, last_modified_t, content);
            // utimens addition, set file change time on folder list, convert GMT time received from hubic as local
            char local_time_str[64];
            time_t local_time_t = get_time_as_local(last_modified_t, local_time_str, sizeof(local_time_str));
            //debugf("Set cloudfs_list_directory path=%s local_time=%li.0 [%s]", de->name, local_time_t, local_time_str);
            de->last_modified = local_time_t;
            de->mtime.tv_sec = local_time_t;
            // TODO check if I can retrieve nano seconds
            de->mtime.tv_nsec = 0;
            
          }
        }
        de->isdir = de->content_type &&
            ((strstr(de->content_type, "application/folder") != NULL) ||
             (strstr(de->content_type, "application/directory") != NULL));
        de->islink = de->content_type &&
            ((strstr(de->content_type, "application/link") != NULL));
        if (de->isdir)
        {
          if (!strncasecmp(de->name, last_subdir, sizeof(last_subdir)))
          {
            cloudfs_free_dir_list(de);
            continue;
          }
          strncpy(last_subdir, de->name, sizeof(last_subdir));
        }
        de->next = *dir_list;
        *dir_list = de;
        debugf("Added new dir_entry name=%s path=%s", de->name, de->full_name);
        //attempt to read extended attributes on each dir entry
        get_file_metadata(de);
      }
      else {
        debugf("unknown element: %s", onode->name);
      }
    }
    retval = 1;
  }
  else if ((!strcmp(path, "") || !strcmp(path, "/")) && *override_storage_url) {
    entry_count = 1;
    debugf("Init cache entry container=[%s]", public_container);
    dir_entry *de = (dir_entry *)malloc(sizeof(dir_entry));
    de->name = strdup(public_container);
    struct tm last_modified;
    de->md5sum = NULL;
    // TODO check what this default time means?
    strptime("1388434648.01238", "%FT%T", &last_modified);
    de->last_modified = mktime(&last_modified);
    de->content_type = strdup("application/directory");
    if (asprintf(&(de->full_name), "%s/%s", path, de->name) < 0)
      de->full_name = NULL;
    de->isdir = 1;
    de->islink = 0;
    de->size = 4096;
    de->next = *dir_list;
    *dir_list = de;
    retval = 1;
  }

  // not very usefull
  //debugf("entry count: %d", entry_count);

  xmlFreeDoc(xmlctx->myDoc);
  xmlFreeParserCtxt(xmlctx);
  debugf("exit: cloudfs_list_directory(%s)", path);
  return retval;
}


int cloudfs_delete_object(const char *path)
{
	debugf("cloudfs_delete_object(%s)", path);
  char seg_base[MAX_URL_SIZE] = "";

  long segments;
  long full_segments;
  long remaining;
  long size_of_segments;

  if (format_segments(path, seg_base, &segments, &full_segments, &remaining,
        &size_of_segments)) {
    int response;
    int i;
    char seg_path[MAX_URL_SIZE] = "";
    for (i = 0; i < segments; i++) {
      snprintf(seg_path, MAX_URL_SIZE, "%s%08i", seg_base, i);
      char *encoded = curl_escape(seg_path, 0);
      response = send_request("DELETE", encoded, NULL, NULL, NULL, NULL);
			if (response < 200 || response >= 300) {
				debugf("exit 1: cloudfs_delete_object(%s) response=%d", path, response);
				return 0;
			}
    }
  }

  char *encoded = curl_escape(path, 0);
  int response = send_request("DELETE", encoded, NULL, NULL, NULL, NULL);
  curl_free(encoded);
  int ret = (response >= 200 && response < 300);
	debugf("status: cloudfs_delete_object(%s) response=%d", path, response);
	if (response == 409) {
		debugf("status: cloudfs_delete_object(%s) NOT EMPTY", path);
		ret = -1;
	}
  return ret;
}

int cloudfs_copy_object(const char *src, const char *dst)
{
  char *dst_encoded = curl_escape(dst, 0);
  curl_slist *headers = NULL;
  add_header(&headers, "X-Copy-From", src);
  add_header(&headers, "Content-Length", "0");
  int response = send_request("PUT", dst_encoded, NULL, NULL, headers, NULL);
  curl_free(dst_encoded);
  curl_slist_free_all(headers);
  return (response >= 200 && response < 300);
}

//optimise this
int cloudfs_statfs(const char *path, struct statvfs *stat)
{
	time_t now = get_time_now();
	int lapsed = now - last_stat_read_time;
	if (lapsed > 10) {
		int response = send_request("HEAD", "/", NULL, NULL, NULL, NULL);
		*stat = statcache;
		debugf("exit: cloudfs_statfs (new recent values, was cached since %d seconds)", lapsed);
		last_stat_read_time = now;
		return (response >= 200 && response < 300);
	}
	else {
		debugf("exit: cloudfs_statfs (old values, cached since %d seconds)", lapsed);
	}
}

int cloudfs_create_symlink(const char *src, const char *dst)
{
  char *dst_encoded = curl_escape(dst, 0);

  FILE *lnk = tmpfile();

  fwrite(src, 1, strlen(src), lnk);
  fwrite("\0", 1, 1, lnk);
  int response = send_request("MKLINK", dst_encoded, lnk, NULL, NULL, NULL);
  curl_free(dst_encoded);
  fclose(lnk);
  return (response >= 200 && response < 300);
}

int cloudfs_create_directory(const char *path)
{
	debugf("cloudfs_create_directory(%s)", path);
  char *encoded = curl_escape(path, 0);
  int response = send_request("MKDIR", encoded, NULL, NULL, NULL, NULL);
  curl_free(encoded);
	debugf("cloudfs_create_directory(%s) response=%d", path, response);
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

static struct {
  char client_id    [MAX_HEADER_SIZE];
  char client_secret[MAX_HEADER_SIZE];
  char refresh_token[MAX_HEADER_SIZE];
} reconnect_args;

void cloudfs_set_credentials(char *client_id, char *client_secret, char *refresh_token)
{
  strncpy(reconnect_args.client_id    , client_id    , sizeof(reconnect_args.client_id    ));
  strncpy(reconnect_args.client_secret, client_secret, sizeof(reconnect_args.client_secret));
  strncpy(reconnect_args.refresh_token, refresh_token, sizeof(reconnect_args.refresh_token));
}

struct htmlString {
	char *text;
	size_t size;
};

static size_t writefunc_string(void *contents, size_t size, size_t nmemb, void *data)
{
	struct htmlString *mem = (struct htmlString *) data;
	size_t realsize = size * nmemb;
	mem->text = realloc(mem->text, mem->size + realsize + 1);
	if (mem->text == NULL) { /* out of memory! */
		perror(__FILE__);
		exit(EXIT_FAILURE);
	}

	memcpy(&(mem->text[mem->size]), contents, realsize);
	mem->size += realsize;
	return realsize;
}

char* htmlStringGet(CURL *curl)
{
	struct htmlString chunk;
	chunk.text = malloc(sizeof(char));
	chunk.size = 0;
	chunk.text[0] = '\0';//added to avoid valgrind unitialised warning

	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &chunk);
	do {
		curl_easy_perform(curl);
	} while (chunk.size == 0);

	chunk.text[chunk.size] = '\0';
	return chunk.text;
}

/* thanks to http://devenix.wordpress.com */
char *unbase64(unsigned char *input, int length)
{
	BIO *b64, *bmem;

	char *buffer = (char *)malloc(length);
	memset(buffer, 0, length);

	b64 = BIO_new(BIO_f_base64());
	bmem = BIO_new_mem_buf(input, length);
	bmem = BIO_push(b64, bmem);
	BIO_set_flags(bmem, BIO_FLAGS_BASE64_NO_NL);

	BIO_read(bmem, buffer, length);

	BIO_free_all(bmem);

	return buffer;
}

int safe_json_string(json_object *jobj, char *buffer, char *name)
{
  int result = 0;

  if (jobj)
    {
      json_object *o;
      int found;
      found = json_object_object_get_ex(jobj, name, &o);
      if (found)
        {
          strcpy (buffer, json_object_get_string(o));
          result = 1;
        }
    }

  if (!result)
    debugf("HUBIC cannot get json field '%s'\n", name);

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
  struct json_object *json_obj;

  pthread_mutex_lock(&pool_mut);

  debugf("Authenticating... (client_id = '%s')", HUBIC_CLIENT_ID);

  storage_token[0] = storage_url[0] = '\0';

  CURL *curl = curl_easy_init();

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

  sprintf(payload, "refresh_token=%s&grant_type=refresh_token", HUBIC_REFRESH_TOKEN);

  curl_easy_setopt(curl, CURLOPT_URL, HUBIC_TOKEN_URL);
  curl_easy_setopt(curl, CURLOPT_POST, 1L);
  curl_easy_setopt(curl, CURLOPT_HEADER, 0);

  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, strlen(payload));

  curl_easy_setopt(curl, CURLOPT_USERNAME, HUBIC_CLIENT_ID);
  curl_easy_setopt(curl, CURLOPT_PASSWORD, HUBIC_CLIENT_SECRET);
  curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);

  char *json_str = htmlStringGet(curl);
  json_obj = json_tokener_parse(json_str);
  debugf ("HUBIC TOKEN_URL result: '%s'\n", json_str);
  free(json_str);

  char access_token[HUBIC_OPTIONS_SIZE];
  char token_type[HUBIC_OPTIONS_SIZE];
  int expire_sec;
  int found;
  json_object *o;

  if (!safe_json_string(json_obj, access_token, "access_token"))
    return 0;
  if (!safe_json_string(json_obj, token_type, "token_type"))
    return 0;

  found = json_object_object_get_ex(json_obj, "expires_in", &o);

  expire_sec = json_object_get_int(o);
  debugf ("HUBIC Access token: %s\n", access_token);
  debugf ("HUBIC Token type  : %s\n", token_type);
  debugf ("HUBIC Expire in   : %d\n", expire_sec);

  /* Step 4 : request OpenStack storage URL */

  curl_easy_setopt(curl, CURLOPT_URL, HUBIC_CRED_URL);
  curl_easy_setopt(curl, CURLOPT_POST, 0L);
  curl_easy_setopt(curl, CURLOPT_HEADER, 0);
  curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_NONE);

  /* create the Bearer authentication header */
  curl_slist *headers = NULL;
  sprintf (payload, "Bearer %s", access_token);
  add_header(&headers, "Authorization", payload);
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

  char token[HUBIC_OPTIONS_SIZE];
  char endpoint[HUBIC_OPTIONS_SIZE];
  char expires[HUBIC_OPTIONS_SIZE];

  json_str = htmlStringGet(curl);
  json_obj = json_tokener_parse(json_str);
  debugf ("CRED_URL result: '%s'\n", json_str);
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

  return (response >= 200 && response < 300 && storage_token[0] && storage_url[0]);
}
