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
#include <semaphore.h>
#include <pwd.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stddef.h>
#include <openssl/md5.h>
#include <assert.h>
#include "commonfs.h"
#include "cloudfsapi.h"
#include "config.h"

/*
  http://docs.openstack.org/developer/swift/api/object_api_v1_overview.html
*/
extern char* temp_dir;
extern pthread_mutex_t dcachemut;
extern pthread_mutex_t dcacheuploadmut;
extern pthread_mutexattr_t mutex_attr;
extern pthread_mutexattr_t segment_mutex_attr;
extern int debug;
extern int cache_timeout;
extern int verify_ssl;
extern bool option_get_extended_metadata;
extern bool option_curl_verbose;
extern int option_cache_statfs_timeout;
extern int option_debug_level;
extern bool option_curl_progress_state;
extern bool option_enable_chown;
extern bool option_enable_chmod;
extern bool option_enable_progressive_upload;
extern bool option_enable_progressive_download;
extern long option_min_speed_limit_progressive;
extern long option_min_speed_timeout;
extern long option_read_ahead;
extern bool option_enable_syslog;
extern bool option_enable_chaos_test_monkey;
extern bool option_disable_atime_check;
extern pthread_t control_thread;

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
  .disable_atime_check = "false"
};

bool initialise_options(struct fuse_args args)
{
  char settings_filename[MAX_PATH_SIZE] = "";
  FILE* settings ;
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
    return false;
  }
  return true;
}

/*
  with lazy meta file size (and segmented status) can be incorrect
*/
static int cfs_getattr(const char* path, struct stat* stbuf)
{
  debugf(DBG_NORM, KBLU "cfs_getattr(%s)", path);
  if (debug > 0)
  {
    if (strstr(path, "/debug-decache"))
    {
      debugf(DBG_NORM, KRED "DEBUG COMMAND: Cache Reset (%s)", path);
      char seg_base[MAX_URL_SIZE];
      char container[MAX_URL_SIZE];
      char object[MAX_URL_SIZE];
      split_path(path, seg_base, container, object);
      dir_decache(container);
      //struct fuse_args args;
      //initialise_options(args);
      //print_options();
      return -ENOENT;
    }
  }
  //return standard values for root folder
  if (!strcmp(path, "/"))
  {
    stbuf->st_uid = geteuid();
    stbuf->st_gid = getegid();
    stbuf->st_mode = S_IFDIR | 0777;//0755;
    stbuf->st_nlink = 2;
    debug_list_cache_content();
    debugf(DBG_NORM, KBLU "exit 0: cfs_getattr(%s)", path);
    return 0;
  }
  //get file. if not in cache will be added
  dir_entry* de = path_info(path);
  update_cache_access(de);
  if (!de)
  {
    debug_list_cache_content();
    debugf(DBG_NORM, KBLU"exit 1: cfs_getattr(%s) file not found "
           KYEL "not-in-cache/cloud", path);
    return -ENOENT;
  }
  //lazzy download of file metadata, only when really needed
  if (option_get_extended_metadata && !de->metadata_downloaded)
  {
    get_file_metadata(de, false, false);
    //file might be corrupted after getting metadata - ???
    de = check_path_info(path);
    if (!de)
    {
      debugf(DBG_NORM, KBLU"exit 2: cfs_getattr(%s)"
             KYEL " file corrupted", path);
      return -ENOENT;
    }
    //file is marked with lazy_seg_load=true if file_size meta exist
    if (!de->lazy_segment_load && !de->isdir && !de->lazy_meta)
    {
      //this means file does not have FILE_SIZE meta, not uploaded via this app
      //so add this meta for future speed improvements
      debugf(DBG_NORM, "cfs_getattr(%s):" KYEL
             " update meta to latest fields (add size)", de->name);
      int fd = open_lock_file(path, FUSE_FLAG_O_WRONLY, "getattr-size");
      if (fd == -1)
        return -EBUSY;
      de->lock_fd = fd;
      cloudfs_update_meta(de, true);
    }
  }
  if (option_enable_chown && de->uid != -1 && de->gid != -1)
  {
    stbuf->st_uid = de->uid;
    stbuf->st_gid = de->gid;
  }
  else
  {
    stbuf->st_uid = geteuid();
    stbuf->st_gid = getegid();
  }
  // change needed due to utimens
  stbuf->st_atime = de->atime.tv_sec;
  stbuf->st_atim.tv_nsec = de->atime.tv_nsec;
  stbuf->st_mtime = de->mtime.tv_sec;
  stbuf->st_mtim.tv_nsec = de->mtime.tv_nsec;
  stbuf->st_ctime = de->ctime.tv_sec;
  stbuf->st_ctim.tv_nsec = de->ctime.tv_nsec;
  char time_str[TIME_CHARS] = "";
  get_timespec_as_str(&(de->atime), time_str, sizeof(time_str));
  debugf(DBG_EXTALL, KCYN"cfs_getattr: atime=[%s]", time_str);
  get_timespec_as_str(&(de->mtime), time_str, sizeof(time_str));
  debugf(DBG_EXTALL, KCYN"cfs_getattr: mtime=[%s]", time_str);
  get_timespec_as_str(&(de->ctime), time_str, sizeof(time_str));
  debugf(DBG_EXTALL, KCYN"cfs_getattr: ctime=[%s]", time_str);
  int default_mode_dir, default_mode_file;
  if (option_enable_chmod & de->chmod != -1)
  {
    default_mode_dir = de->chmod;
    default_mode_file = de->chmod;
  }
  else
  {
    default_mode_dir = 0755;
    default_mode_file = 0777;// 0666;
  }
  if (de->isdir)
  {
    stbuf->st_size = 0;
    stbuf->st_mode = S_IFDIR | default_mode_dir;
    stbuf->st_nlink = 2;
  }
  else if (de->islink)
  {
    stbuf->st_size = 1;
    stbuf->st_mode = S_IFLNK | default_mode_dir;
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
    stbuf->st_mode = S_IFREG | default_mode_file;
    stbuf->st_nlink = 1;
  }
  debugf(DBG_NORM, KBLU "exit 2: cfs_getattr(%s) size=%lu", path,
         de->size);
  return 0;
}

static int cfs_fgetattr(const char* path, struct stat* stbuf,
                        struct fuse_file_info* info)
{
  debugf(DBG_NORM, KBLU "cfs_fgetattr(%s): calling getattr", path);
  int result = cfs_getattr(path, stbuf);
  debugf(DBG_NORM, KBLU "cfs_fgetattr(%s): exit getattr", path);
  return result;
}

static int cfs_readdir(const char* path, void* buf, fuse_fill_dir_t filldir,
                       off_t offset, struct fuse_file_info* info)
{
  debugf(DBG_NORM, KBLU "cfs_readdir(%s)", path);
  dir_entry* de, *de_root;
  //fixme: if this called while an upload is in progress and cache expires,
  //will remove the cache entries and crash as previous segments are deleted
  if (!caching_list_directory(path, &de))
  {
    debug_list_cache_content();
    debugf(DBG_NORM, KRED "exit 0: cfs_readdir(%s)", path);
    return -ENOLINK;
  }
  filldir(buf, ".", NULL, 0);
  filldir(buf, "..", NULL, 0);
  for (; de; de = de->next)
    filldir(buf, de->name, NULL, 0);
  debug_list_cache_content();
  de_root = check_path_info(path);
  //assert(de_root);
  debugf(DBG_NORM, KBLU "exit 1: cfs_readdir(%s): obj_count=%d",
         path, de_root ? de_root->object_count : -1);
  return 0;
}

static int cfs_mkdir(const char* path, mode_t mode)
{
  debugf(DBG_NORM, KBLU "cfs_mkdir(%s)", path);
  int response = cloudfs_create_directory(path);
  if (response)
  {
    update_dir_cache(path, 0, 1, 0);
    debug_list_cache_content();
    debugf(DBG_NORM, KBLU "exit 0: cfs_mkdir(%s)", path);
    return 0;
  }
  debugf(DBG_NORM, KRED "exit 1: cfs_mkdir(%s) response=%d", path,
         response);
  return -ENOENT;
}

static int cfs_create(const char* path, mode_t mode,
                      struct fuse_file_info* info)
{
  debugf(DBG_NORM, KBLU "cfs_create(%s)", path);
  int fd = open_lock_file(path, info->flags, "create");
  if (fd == -1)
    return -EBUSY;
  info->fh = (uintptr_t)fd;
  //create a copy in upload cache to record creation time meta fields
  update_dir_cache_upload(path, 0, 0, 0);
  //create also a copy in access cache to signal create OK
  update_dir_cache(path, 0, 0, 0);
  info->direct_io = 1;
  dir_entry* de = check_path_info_upload(path);
  assert(de);

  //create_dir_entry(de, path, mode);
  de->chmod = mode;

  //create empty file
  int result = cloudfs_create_object(de);
  close_lock_file(path, fd);
  if (!result)
  {
    debugf(DBG_NORM, KRED"exit: cfs_create(%s), create failed", path);
    return -EIO;
  }
  debugf(DBG_NORM, KBLU "exit: cfs_create(%s), success", path);
  return 0;
}

/*
   open (download) file from cloud
   todo: implement etag optimisation, download only
   if content changed, http://www.17od.com/2012/12/19/ten-useful-openstack-swift-features/
   avoid being called when op is in progress
*/
static int cfs_open(const char* path, struct fuse_file_info* info)
{
  debugf(DBG_NORM, KBLU
         "cfs_open(%s) d_io=%d flush=%d non_seek=%d write_pg=%d fh=%p",
         path, info->direct_io, info->flush, info->nonseekable, info->writepage,
         info->fh);
  bool file_cache_ok = false;
  dir_entry* de = path_info(path);
  update_cache_access(de);
  if (!de)
    return -ENOENT;
  //create/open file in cache so we can manage concurrent operations on same file
  int fd = open_lock_file(path, info->flags, "open");
  if (fd == -1)
  {
    debugf(DBG_ERR, KRED "exit: cfs_open(%s) lock failed", path);
    return -EBUSY;
  }
  //download metadata if needed.sometimes getattr is not called.
  //if (option_get_extended_metadata &&
  //    (!de->metadata_downloaded || de->lazy_segment_load))
  bool res = get_file_metadata(de, true, true);

  info->fh = (uintptr_t)fd;
  info->direct_io = 1;
  //non seek must be set to 0 to enable
  // video players work via samba (as they perform a seek to file end)
  info->nonseekable = 0;
  debugf(DBG_NORM, KBLU "exit: cfs_open(%s)", path);
  return 0;
}

/*
  download file from cloud
  http://docs.openstack.org/developer/swift/api/large_objects.html
*/
static int cfs_read(const char* path, char* buf, size_t size, off_t offset,
                    struct fuse_file_info* info)
{
  int result = -1;
  off_t offset_seg;
  int sem_val, err;
  //int rnd = random_at_most(50);
  //if (offset % 100000 == 0)//avoid clutter
  debugf(DBG_EXT, KBLU
         "cfs_read(%s) buffsize=%lu offset=%lu ", path, size, offset);
  //sleep_ms(rnd);
  if (offset == 0)
  {
    //mark as exclusive read lock instead of soft read
    assert(update_lock_file(path, info->fh, "r", "r!"));
  }
  int iters = 0;
  bool in_cache = false;

  dir_entry* de = check_path_info(path);
  update_cache_access(de);

  if (de && de->is_segmented)
  {
    int read_ahead_count = (option_read_ahead / de->segment_size) + 1;
    int segment_index = offset / de->segment_size;
    dir_entry* de_seg, *de_seg_next;
    while (result <= 0)
    {
      de_seg = get_segment(de, segment_index);
      //could not find expected segment
      if (!de_seg)
      {
        debugf(DBG_ERR, KRED
               "cfs_read(%s): segment %d not in cloud", path, segment_index);
        return -ENODATA;
      }
      //offset in segment is different than full file offset
      offset_seg = offset - (segment_index * de->segment_size);
      debugf(DBG_EXTALL, KMAG
             "cfs_read: while seg path=%s off=%lu segment=%d seg_name=%s md5=%s",
             de->name, offset, segment_index, de_seg->name, de_seg->md5sum);
      if (de_seg)
      {
        bool in_cache;
        FILE* fp_segment = NULL;
        in_cache = open_segment_cache_md5(de, de_seg, &fp_segment, HTTP_GET);
        if (!in_cache)
        {
          debugf(DBG_EXT, KMAG "cfs_read(%s): seg %d " KYEL "not in cache",
                 de_seg->name, segment_index);
          download_ahead_segment(de_seg, de, fp_segment, true);
          if (de_seg->downld_buf.mutex_initialised)
          {
            debugf(DBG_EXT, KBLU
                   "cfs_read: 1-wait lock seg=%s", de_seg->name);
            pthread_mutex_lock(&de_seg->downld_buf.mutex);
            debugf(DBG_EXT, KBLU
                   "cfs_read: 1-wait data seg=%s", de_seg->name);
            if (de_seg->downld_buf.sem_list[SEM_FULL])
              sem_wait(de_seg->downld_buf.sem_list[SEM_FULL]);
            pthread_mutex_unlock(&de_seg->downld_buf.mutex);
          }
          else
          {
            debugf(DBG_EXT, KBLU
                   "cfs_read: 2-wait data seg=%s", de_seg->name);
            if (de_seg->downld_buf.sem_list[SEM_FULL])
              sem_wait(de_seg->downld_buf.sem_list[SEM_FULL]);
          }
          debugf(DBG_EXT, KBLU
                 "cfs_read: got full data seg=%s", de_seg->name);
          fclose(fp_segment);
          fp_segment = NULL;
          in_cache = open_segment_cache_md5(de, de_seg, &fp_segment, HTTP_GET);
          if (!in_cache)
            debugf(DBG_EXT, KYEL
                   "cfs_read: read ahead failed seg=%s", de_seg->name);
          else
            debugf(DBG_EXT, "cfs_read: read ahead OK seg=%s", de_seg->name);
        }

        if (in_cache)
        {
          int fno = fileno(fp_segment);
          if (fno != -1)//safety check
          {
            result = pread(fno, buf, size, offset_seg);
            err = errno;
            if (offset % 100000 == 0)
              debugf(DBG_EXT, KBLU
                     "cfs_read(%s) fno=%d fp=%p part=%d off=%lu res=%lu",
                     de_seg->name, fno, fp_segment, segment_index, offset_seg, result);
            close(fno);
            fclose(fp_segment);
            //download if segment ahead not in cache and no other download runs
            de_seg_next = get_segment(de, segment_index + read_ahead_count);
            if (de->downld_buf.ahead_thread_count == 0 && de_seg_next &&
                (de_seg_next->md5sum_local == NULL
                 || (strcasecmp(de_seg_next->md5sum_local, de_seg_next->md5sum))))
              download_ahead_segment(de_seg_next, de, fp_segment, false);

            if (result > 0)
              return result;
            else
            {
              debugf(DBG_EXT, KMAG "cfs_read(%s): done serving segment %d",
                     path, segment_index);
              //force download (or read from cache) of a new segment
              segment_index++;
              //exit if all segments are downloaded
              if (segment_index == de->segment_count)
                break;
            }
          }
          else //fno == -1
          {
            debugf(DBG_NORM, KRED "cfs_read(%s): error seg_fp(%p) fileno=-1",
                   path, fp_segment);//de_seg->downld_buf.local_cache_file);
            fclose(fp_segment);//de_seg->downld_buf.local_cache_file);
            //de_seg->downld_buf.local_cache_file = NULL;
            return -1;
          }
        }
        //was open after read_ahead
        fclose(fp_segment);

        if (false)//de->is_progressive)
        {
          //sleep_ms(rnd);
          if (de->downld_buf.fuse_read_size != 0
              && de->downld_buf.fuse_read_size != size)
          {
            //todo: fuse buffer size is changing from time to time (mostly on ops via samba), why?
            debugf(DBG_EXT, KRED
                   "cfs_read: fuse size changed since last cfs_read, old=%lu new=%lu",
                   de->downld_buf.fuse_read_size, size);
            //sleep_ms(100);
          }
          //reset data size provided by http
          de->downld_buf.work_buf_size = 0;
          //inform the expected fuse buffer size to be filled in by http
          de->downld_buf.fuse_read_size = size;
          de->downld_buf.readptr = buf;
          sem_getvalue(de->downld_buf.sem_list[SEM_EMPTY], &sem_val);
          //signal we need data, buffer is empty, triggers http data copy to buf
          debugf(DBG_EXT, KBLU
                 "cfs_read: post empty data, buf_size=%lu sem=%d",
                 size, sem_val);
          sem_post(de->downld_buf.sem_list[SEM_EMPTY]);
          sem_getvalue(de->downld_buf.sem_list[SEM_FULL], &sem_val);
          debugf(DBG_EXT, KBLU "cfs_read: wait full data sem=%d",
                 sem_val);
          //wait until data buffer is full
          sem_wait(de->downld_buf.sem_list[SEM_FULL]);
          debugf(DBG_EXT, KBLU "cfs_read: got full data size=%lu",
                 de->downld_buf.work_buf_size);
          debugf(DBG_EXT, KBLU "cfs_read: exit ret_code=%lu",
                 de->downld_buf.work_buf_size);
          return de->downld_buf.work_buf_size;
        }
      }
      iters++;
    }//end while
    return result;
  }

  //non-segmented files
  if (de && !de->is_segmented)
  {
    debugf(DBG_NORM, "cfs_read(%s): read non segmented file", path);
    bool in_cache;
    FILE* fp_file = NULL;
    while (result <= 0)
    {
      in_cache = open_file_cache_md5(de, &fp_file, HTTP_GET);
      if (!in_cache)
      {
        cloudfs_download_segment(de, de, fp_file, de->size);
        fclose(fp_file);
        fp_file = NULL;
        in_cache = open_file_cache_md5(de, &fp_file, HTTP_GET);
        if (!in_cache)
        {
          debugf(DBG_EXT, KRED
                 "cfs_read(%s): download failed, cache not ok, file=%s", path, de->name);
          abort();
        }
        else
          debugf(DBG_EXT, "cfs_read: download OK file=%s", de->name);
      }

      if (in_cache)
      {
        int fno = fileno(fp_file);
        if (fno != -1)//safety check
        {
          result = pread(fno, buf, size, offset);
          err = errno;
          debugf(DBG_EXT, KBLU "cfs_read(%s) fno=%d fp=%p err=%s",
                 de->name, fno, fp_file, strerror(err));
          close(fno);
          fclose(fp_file);
          fp_file = NULL;
          return result;
        }
        else abort();
      }
      else
      {
        debugf(DBG_NORM, KRED "cfs_read(%s): unable to download", de->name);
        return -ENOENT;
      }
    }//end while
    return result;
  }
}

//todo: flush will upload a file again even if just file attributes are changed.
//optimisation needed to detect if content is changed
//and to only save meta when just attribs are modified.
static int cfs_flush(const char* path, struct fuse_file_info* info)
{
  debugf(DBG_NORM, KBLU
         "cfs_flush(%s) d_io=%d flush=%d non_seek=%d write_pg=%d fh=%p",
         path, info->direct_io, info->flush, info->nonseekable, info->writepage,
         info->fh);
  int result = 0;
  //exit on null paths
  if (!path)
  {
    debugf(DBG_NORM, KRED "cfs_flush: received NULL path");
    return 0;
  }
  int errsv = 0;
  dir_entry* de = check_path_info(path);
  update_cache_access(de);
  dir_entry* de_upload = check_path_info_upload(path);
  if (!de_upload)
    assert(de);

  if (de_upload)
  {
    debugf(DBG_EXT, KMAG "cfs_flush(%s): signal upload done, size=%lu",
           path, de_upload->size);
    //on cfs_create empty file segment count is 0, no need to enter here
    if (de_upload->is_segmented && de_upload->segment_count > 0)
    {
      dir_entry* de_seg = get_segment(de_upload, de_upload->segment_count - 1);
      assert(de_seg);
      //will be blocked until http upload trully terminates
      debugf(DBG_EXT, KMAG "cfs_flush(%s): seg_count=%d", de_upload->name,
             de_upload->segment_count);
      //unblock the last segment wait in http callback
      if (de_seg->upload_buf.sem_list[SEM_FULL])
      {
        debugf(DBG_EXT, KMAG "cfs_flush(%s): wait upload completion, last=%s",
               de_upload->name, de_seg->name);
        //notify data feed is done
        sem_post(de_seg->upload_buf.sem_list[SEM_FULL]);
        //wait until upload and cleanup of previous versions fully completes
        //otherwise errors will be thrown by rsync (due to early rename)
        //fixme: sometimes we get freeze
        sem_wait(de_seg->upload_buf.sem_list[SEM_DONE]);
        //check if all previous segment uploads are done (except last)
        //sometimes prev uploads are still in progress
        int seg_index;
        dir_entry* de_seg_tmp;
        //calculate md5sum
        char job_name[MAX_PATH_SIZE] = "flush_md5_etags:";
        struct thread_job* job = init_thread_job(strdup(strcat(job_name,
                                 de_upload->name)));
        init_job_md5(job);
        bool pending;//segments still pending upload
        int loops = 0;
        do
        {
          pending = false;
          for (seg_index = 0; seg_index < de_upload->segment_count;
               seg_index++)
          {
            de_seg_tmp = get_segment(de_upload, seg_index);
            assert(de_seg_tmp);
            if (de_seg_tmp->upload_buf.sem_list[SEM_DONE])
            {
              if (loops % 20 == 0)
                debugf(DBG_EXT, KMAG "cfs_flush(%s): wait for pending upload %s",
                       de->name, de_seg_tmp->name);
              //upload might be blocked in sem_wait @ upload_prog
              //after cfs_write completed, so feed data from here
              if (de_seg_tmp->upload_buf.feed_from_cache)
              {
                debugf(DBG_EXT, KRED
                       "cfs_flush(%s): wait blocked in cache %s, retrying upload",
                       de->name, de_seg_tmp->name);
                //feed data to http thread
                int_cfs_write_cache_data_feed(de_seg_tmp);
                de_seg_tmp->upload_buf.feed_from_cache = false;
              }
              pending = true;
            }
            else
              debugf(DBG_EXT, KMAG "cfs_flush(%s): upload done %s md5=%s",
                     de_upload->name, de_seg_tmp->name, de_seg_tmp->md5sum);
          }
          if (pending)
            sleep_ms(200);
          loops++;
        }
        while (pending && loops < 120);

        //signal free of last semaphore is safe now
        //free_semaphores(&de_seg->upload_buf, SEM_DONE);

        //if operation completed ok calculate file cumulative segment etag
        if (!pending)
        {
          debugf(DBG_EXT, KMAG "cfs_flush(%s): compute md5sum etags", de_upload->name);
          for (seg_index = 0; seg_index < de_upload->segment_count; seg_index++)
          {
            de_seg_tmp = get_segment(de_upload, seg_index);
            assert(de_seg_tmp);
            //update md5sum for the whole file using etags
            update_job_md5(job, de_seg_tmp->md5sum, strlen(de_seg_tmp->md5sum));
          }
          //complete md5sum compute for this file using cumulative segment etags
          complete_job_md5(job);
          if (de_upload->md5sum_local)
            free(de_upload->md5sum_local);
          de_upload->md5sum_local = strdup(job->md5str);
          free_thread_job(job);
        }
        //complete md5sum using fuse provided content
        complete_job_md5(de_upload->job);
        //complete md5sum using http uploaded content
        complete_job_md5(de_upload->job2);

        if (pending)
        {
          debugf(DBG_EXT, KRED
                 "cfs_flush(%s): pending segments for too long, aborting", de_upload->name);
          abort();
          result = -EIO;
        }

        if (strcasecmp(de_upload->job->md5str, de_upload->job2->md5str))
        {
          //md5sums are different, upload is corrupt
          debugf(DBG_EXT, KRED
                 "cfs_flush(%s): md5sum not match between fuse(%s) and http(%s)",
                 de_upload->name, de_upload->job->md5str, de_upload->job2->md5str);
          result = -EILSEQ;
          abort();
        }
        else
          debugf(DBG_EXT, KGRN "cfs_flush(%s): content md5sum OK (%s)",
                 de_upload->name, de_upload->job->md5str);

        //fixme: sometimes last segment is not yet visible on cloud
        //copy dir_entry for to have segment list complete
        if (de_upload->has_unvisible_segments)
          copy_dir_entry(de_upload, de, true);

        //mark file meta as obsolete to force a reload (for md5sums mostly)
        //if has unvisible segments update_segments in get_file_meta will skip
        de->metadata_downloaded = false;
        bool meta_ok = get_file_metadata(de, true, true);
        if (!meta_ok || strcasecmp(de->md5sum, de_upload->md5sum_local))
        {
          if (!strcasecmp(de->md5sum, de_upload->segments->md5sum_local))
          {
            debugf(DBG_EXT, KRED
                   "cfs_flush(%s): etags not match, EARLY?, cloud(%s) local(%s)",
                   de_upload->name, de->md5sum, de_upload->md5sum_local);
          }
          else
          {
            //md5sums are different, upload is corrupt
            debugf(DBG_EXT, KRED
                   "cfs_flush(%s): etags md5sum not match, cloud(%s) local(%s)",
                   de_upload->name, de->md5sum, de_upload->md5sum_local);
          }
          result = -EILSEQ;
          abort();
        }
        else
          debugf(DBG_EXT, KGRN "cfs_flush(%s): segment md5sum OK (%s)",
                 de_upload->name, de_upload->md5sum_local);
        //free md5sum holders
        free_thread_job(de_upload->job);
        free_thread_job(de_upload->job2);
      }
      //close-flushes last cache file. previous are closed in cfs_write
      assert(de_seg->upload_buf.local_cache_file);
      fclose(de_seg->upload_buf.local_cache_file);
      close_lock_file(de_upload->full_name, info->fh);
    }
    else if (!de_upload->is_segmented)
    {
      char* fuse_md5 = NULL;
      if (de_upload->job)
      {
        //complete md5sum using fuse provided content
        complete_job_md5(de_upload->job);
        fuse_md5 = strdup(de_upload->job->md5str);
      }
      //signal completion of read/write operation
      //signal last data available in buffer for upload
      if (de_upload->upload_buf.sem_list[SEM_FULL])
        sem_post(de_upload->upload_buf.sem_list[SEM_FULL]);
      int loops = 0;
      while (de_upload->upload_buf.sem_list[SEM_DONE])
      {
        if (loops % 20 == 0)
          debugf(DBG_EXT, KMAG "cfs_flush(%s): wait non-segmented pending upload",
                 de_upload->name);
        sleep_ms(200);
        if (de_upload->upload_buf.feed_from_cache)
        {
          //;
          int_cfs_write_cache_data_feed(de_upload);
          de_upload->upload_buf.feed_from_cache = false;
          //signal to force http upload completion
          if (de->upload_buf.sem_list[SEM_FULL])
            sem_post(de->upload_buf.sem_list[SEM_FULL]);
        }
        loops++;
      }

      if (fuse_md5 && strcasecmp(fuse_md5, de_upload->md5sum))
      {
        //md5sums are different, upload is corrupt
        debugf(DBG_EXT, KRED
               "cfs_flush(%s): bad md5sum between fuse(%s), cloud(%s)",
               de_upload->name, fuse_md5, de_upload->md5sum);
        result = -EILSEQ;
        abort();
      }
      else
        debugf(DBG_EXT, KGRN "cfs_flush(%s): non_seg content md5sum OK (%s)",
               de_upload->name, fuse_md5);
      //update meta de
      copy_dir_entry(de_upload, de, true);
      free(fuse_md5);
      //free md5sum holders
      if (de_upload->job)
        free_thread_job(de_upload->job);
      //might be already closed via first segment in cfs_write
      if (de_upload->upload_buf.local_cache_file)
      {
        fclose(de_upload->upload_buf.local_cache_file);
        de_upload->upload_buf.local_cache_file = NULL;
      }
      close_lock_file(de_upload->full_name, info->fh);
    }
    else
      debugf(DBG_EXT, "cfs_flush(%s): no need to wait!?", de->name);
    //delete cached folder
    unlink_cache_segments(de_upload);
    dir_decache_upload(de_upload->full_name);
  }
  else//not upload
  {
    //unlink_cache_segments(de);
    debugf(DBG_EXT, KMAG
           "cfs_flush(%s): non-upload done, size=%lu", path, de->size);
  }
  errsv = 0;
  close_lock_file(de->full_name, info->fh);
  debugf(DBG_NORM, KBLU "exit 1: cfs_flush(%s) result=%d:%s", path, errsv,
         strerror(errsv));
  return result;
}

static int cfs_release(const char* path, struct fuse_file_info* info)
{
  debugf(DBG_NORM, KBLU
         "cfs_release(%s) d_io=%d flush=%d non_seek=%d write_pg=%d fh=%p",
         path, info->direct_io, info->flush, info->nonseekable, info->writepage,
         info->fh);
  dir_entry* de = check_path_info(path);
  update_cache_access(de);
  //duplicate as cfs_flush not always called
  if (close_lock_file(de->full_name, info->fh))
    unlink_cache_segments(de);
  debugf(DBG_NORM, KBLU "exit: cfs_release(%s)", path);
  return 0;
}

static int cfs_rmdir(const char* path)
{
  debugf(DBG_NORM, KBLU "cfs_rmdir(%s)", path);
  dir_entry* de = check_path_info(path);
  int success = cloudfs_delete_object(de);
  if (success == -1)
  {
    debugf(DBG_NORM, KBLU "exit 0: cfs_rmdir(%s)", path);
    return -ENOTEMPTY;
  }
  if (success)
  {
    dir_decache(path);
    debugf(DBG_NORM, KBLU "exit 1: cfs_rmdir(%s)", path);
    return 0;
  }
  debugf(DBG_NORM, KBLU "exit 2: cfs_rmdir(%s)", path);
  return -ENOENT;
}

static int cfs_ftruncate(const char* path, off_t size,
                         struct fuse_file_info* info)
{
  debugf(DBG_NORM, KBLU "cfs_ftruncate(%s): size=%lu, ignored", path, size);

  dir_entry* de = check_path_info_upload(path);
  if (!de)
    de = check_path_info(path);
  if (de && de->size != size)
    debugf(DBG_ERR, KRED "cfs_ftruncate(%s): file size (%lu) != truncate (%lu)",
           path, de->size, size);
  /*openfile* of = (openfile*)(uintptr_t)info->fh;
    if (ftruncate(of->fd, size))
    return -errno;
    lseek(of->fd, 0, SEEK_SET);
    update_dir_cache(path, size, 0, 0);
  */
  debugf(DBG_NORM, KBLU "exit: cfs_ftruncate(%s)", path);
  return 0;
}

/*
  upload file to cloud
  http://docs.openstack.org/developer/swift/api/large_objects.html

  todo: implement versioning?
  https://docs.hpcloud.com/publiccloud/api/swift-api.html

  error codes
  http://www-numi.fnal.gov/offline_software/srt_public_context/WebDocs/Errors/unix_system_errors.html
*/
static int cfs_write(const char* path, const char* buf, size_t length,
                     off_t offset, struct fuse_file_info* info)
{
  if (offset == 0)  //avoid clutter
  {
    debugf(DBG_EXT, KBLU
           "cfs_write(%s) blen=%lu off=%lu", path, length, offset);
  }
  else
    debugf(DBG_EXTALL, KBLU
           "cfs_write(%s) blen=%lu off=%lu", path, length, offset);
  int result, errsv;
  char debugstr[256];
  dir_entry* de_orig = check_path_info(path);
  dir_entry* de = check_path_info_upload(path);
  struct thread_job* job_fuse_md5 = NULL;
  if (!de)
  {
    //update only once otherwise memory leaks
    //should be updated on cfs_create
    update_dir_cache_upload(path, offset, 0, 0);
    de = check_path_info_upload(path);
    create_dir_entry(de, path);
    de->chmod = 0666;
  }
  assert(de);
  if (offset == 0)
  {
    assert(de->size == 0);
    //job for fuse content check
    char job_name[MAX_PATH_SIZE] = "fuse_md5:";
    job_fuse_md5 = init_thread_job(strdup(strcat(job_name, de->name)));
    de->job = job_fuse_md5;
    init_job_md5(job_fuse_md5);
    //job for uploaded data content check
    char job_name_http[MAX_PATH_SIZE] = "http_md5:";
    struct thread_job* job_http_md5 = init_thread_job(strdup(strcat(job_name_http,
                                      de->name)));
    init_job_md5(job_http_md5);
    de->job2 = job_http_md5;

    //if overwriting existing file check if is segmented and
    //remove older segment files
    if (de_orig && de_orig->is_segmented)
    {
      debugf(DBG_EXT, KMAG "cfs_write(%s): deleting old segments", de->name);
      cloudfs_delete_path(de_orig->manifest_cloud, true, false, NULL);
    }
  }
  if (de->job)
    update_job_md5(de->job, buf, length);
  else
  {
    debugf(DBG_ERR, KRED
           "cfs_write(%s) unexpected empty job off=%lu", path, offset);
    abort();
  }
  //force seg_size as this dir_entry might be already initialised?
  de->segment_size = segment_size;
  de->segment_remaining = segment_size; //we don't know remaining size

  //assert(de->is_segmented);
  dir_entry* de_seg, *de_tmp;
  int seg_index = 0;
  int sem_val_full, sem_val_empty;
  off_t ptr_offset = 0;
  off_t seg_size_processed = offset;
  off_t seg_size_to_upload;
  off_t seg_size_uploaded;
  off_t fuse_size_uploaded = 0;

  int last_seg_index = -1;
  int loops = 0;
  dir_entry* prev_seg = NULL;
  while (seg_size_processed < offset + length)
  {
    //creates the segment to be uploaded as dir_entry
    //and sets minimum required fields
    seg_index = seg_size_processed / segment_size;
    if (seg_index != last_seg_index)
    {
      //just switched to a new segment, or got new fuse data (cfs_write called)
      if (seg_index > 0)
      {
        prev_seg = get_segment(de, seg_index - 1);
        //we know this is segmented so if 2nd segment, set prev to main de

        if (!prev_seg && seg_index == 1)
          prev_seg = de;
        assert(prev_seg);
        if (prev_seg->upload_buf.sem_list[SEM_FULL]
            && !prev_seg->upload_buf.signaled_completion)
        {
          //unblock previous segment from data wait
          sem_post(prev_seg->upload_buf.sem_list[SEM_FULL]);
          prev_seg->upload_buf.signaled_completion = true;
          debugf(DBG_EXT, KMAG"cfs_write(%s): signal prev segment %s complete",
                 de->name, prev_seg->name);
          //entry only once
          if (seg_index == 1 && de->is_segmented == false)
          {
            de->is_segmented = true;//change to segmented, before convert
            //add first segment as we now know file is segmented
            create_manifest_meta(de);
            //check if first seg exists, if not create
            assert(get_create_segment(de, 0));
            //rename first segment, as thread to avoid block
            pthread_t thread;
            pthread_create(&thread, NULL, (void*)int_convert_first_segment_th, de);
          }
        }
        if (last_seg_index != -1)
        {
          //close prev cache file as segment changed. last is closed in cfs_flush
          assert(prev_seg->upload_buf.local_cache_file);
          fclose(prev_seg->upload_buf.local_cache_file);
          prev_seg->upload_buf.local_cache_file = NULL;
        }
      }
      //for first segment upload to parent file, until we know if is segmented
      if (seg_index == 0)
      {
        de_tmp = de;
        de_seg = NULL;
      }
      else
      {
        //get existing segment or create a new one if not exists
        de_seg = get_create_segment(de, seg_index);
        assert(get_segment(de, seg_index));
        assert(de->manifest_seg);
        de_tmp = de_seg;
      }

      de_tmp->upload_buf.fuse_buf_size = length;
      //this is called once per segment
      if (!de_tmp->upload_buf.mutex_initialised)
      {
        pthread_mutex_init(&de_tmp->upload_buf.mutex, &segment_mutex_attr);
        de_tmp->upload_buf.mutex_initialised = true;
        //prepare to save segment data in cache if we need to retry upload
        FILE* fp_segment = NULL;
        //remove segment cache file to ensure clean data is written in cache
        delete_segment_cache(de, de_seg);
        //create local cache segment file
        open_segment_in_cache(de, de_seg, &fp_segment, HTTP_PUT);
        assert(fp_segment);
        de_tmp->upload_buf.local_cache_file = fp_segment;
      }
      //set data len to be processed in this segment
      //carefull not to go over total segment size
      de_tmp->upload_buf.work_buf_size =
        min(de_tmp->segment_size - de_tmp->upload_buf.size_processed,
            length - fuse_size_uploaded);
    }
    seg_size_to_upload = de_tmp->upload_buf.work_buf_size;
    //loop until entire buffer was uploaded
    debugf(DBG_EXTALL, KMAG "cfs_write(%s:%s): looping worksize=%lu proc=%lu",
           de->name, de_tmp->name, seg_size_to_upload,
           de_tmp->upload_buf.size_processed);
    //index in buffer to resume upload in a new segment
    //(when buffer did not fit in the current segment)
    ptr_offset = de->size - offset;
    de_tmp->upload_buf.readptr = buf + ptr_offset;

    //start a new segment upload thread when segment upload is at start
    //or at last segment byte (why?)
    if ((de_tmp->upload_buf.size_processed == 0)
        || (de_tmp->upload_buf.size_processed == de_tmp->segment_size))
    {
      //if previous upload failed before uploading any data (401 httperr)
      //need to wait until thread does cleanup to retry upload
      pthread_mutex_lock(&de_tmp->upload_buf.mutex);
      //increment to sinal there is more data and avoid sudden completion
      de->segment_count++;
      while (prev_seg && prev_seg->size != prev_seg->segment_size)
      {
        debugf(DBG_EXT, KYEL
               "cfs_write(%s): prev seg(%s) still uploading, %lu/%lu",
               de_tmp->name, prev_seg->name, prev_seg->size,
               prev_seg->segment_size);
      }
      bool op_ok = cloudfs_create_segment(de_seg, de);
      assert(op_ok);
    }

    //signal there is data available in buffer for upload
    if (de_tmp->upload_buf.sem_list[SEM_FULL])
      sem_post(de_tmp->upload_buf.sem_list[SEM_FULL]);
    //wait until previous buffer data is uploaded via curl callback
    sem_wait(de_tmp->upload_buf.sem_list[SEM_EMPTY]);
    seg_size_uploaded = seg_size_to_upload - de_tmp->upload_buf.work_buf_size;
    //write data to segment cache file in case upload retry is needed
    //but no more than segment size
    size_t write_len = fwrite(buf + ptr_offset, 1, seg_size_uploaded,
                              de_tmp->upload_buf.local_cache_file);
    errsv = errno;
    if (write_len != seg_size_uploaded)
    {
      //probably disk is full
      debugf(DBG_EXT, KRED "cfs_write(%s): cache write error=%s",
             path, strerror(errsv));
      dir_decache(de->full_name);
      return -ENOSPC;
    }
    //add what was uploaded
    seg_size_processed += seg_size_uploaded;
    fuse_size_uploaded += seg_size_uploaded;
    //keep increase the file & segment size as we upload more data
    de->size += seg_size_uploaded;
    if (de_seg)
      de_tmp->size += seg_size_uploaded;

    debugf(DBG_EXTALL,
           KMAG "cfs_write(%s:%s): wait done de_seg=%lu de=%lu szproc=%lu",
           de->name, de_tmp->name, de_tmp->size, de->size,
           de_tmp->upload_buf.size_processed);
    //check if data must be feed from cache in case of upload error (retry)
    if (de_tmp->upload_buf.feed_from_cache)
    {
      debugf(DBG_EXT, KMAG "cfs_write(%s:%s): switch to cache data feed",
             de->name, de_tmp->name);
      size_t save_size_processed = de_tmp->upload_buf.size_processed;
      size_t save_work_buf_size = de_tmp->upload_buf.work_buf_size;
      //reset de_seg upload statistics
      de_tmp->upload_buf.size_processed = 0;
      int_cfs_write_cache_data_feed(de_tmp);
      assert(save_size_processed == de_tmp->upload_buf.size_processed);
      de_tmp->upload_buf.work_buf_size = save_work_buf_size;
      de_tmp->upload_buf.feed_from_cache = false;
      debugf(DBG_EXT, KMAG
             "cfs_write(%s:%s): resume fuse data feed workbuf=%lu",
             de->name, de_tmp->name, de_tmp->upload_buf.work_buf_size);
    }

    debugf(DBG_EXTALL, KMAG
           "cfs_write(%s:%s): buffer empty work=%lu upld=%lu left=%lu fusz=%lu",
           de->name, de_tmp->name, de_tmp->upload_buf.work_buf_size,
           seg_size_uploaded, de_tmp->size - de_tmp->upload_buf.size_processed,
           length - fuse_size_uploaded);
    loops++;
    last_seg_index = seg_index;
  }
  if (offset == 0)
    debugf(DBG_EXT, KMAG "cfs_write(%s): exit, seg_count=%d",
           path, de->segment_count);
  else
    debugf(DBG_EXTALL, KMAG "cfs_write(%s): exit, seg_count=%d",
           path, de->segment_count);
  return length;

}

static int cfs_unlink(const char* path)
{
  debugf(DBG_NORM, KBLU "cfs_unlink(%s)", path);
  int fd = open_lock_file(path, 0, "unlink");
  if (fd == -1)
    return -EBUSY;
  dir_entry* de = check_path_info(path);
  int success = cloudfs_delete_object(de);
  close_lock_file(path, fd);
  if (success == -1)
  {
    debugf(DBG_NORM, KRED "exit 0: cfs_unlink(%s)", path);
    return -EACCES;
  }
  if (success)
  {
    dir_decache(path);
    debugf(DBG_NORM, KBLU "exit 1: cfs_unlink(%s)", path);
    return 0;
  }
  debugf(DBG_NORM, KRED "exit 2: cfs_unlink(%s)", path);
  return -ENOENT;
}

static int cfs_fsync(const char* path, int idunno,
                     struct fuse_file_info* info)
{
  debugf(DBG_NORM, "cfs_fsync(%s)", path);
  return 0;
}

//todo: implement this
static int cfs_truncate(const char* path, off_t size)
{
  debugf(DBG_NORM, KBLU "cfs_truncate(%s): size=%lu", path, size);
  dir_entry* de = check_path_info_upload(path);
  if (!de)
    de = check_path_info(path);
  if (de && de->size != size)
    debugf(DBG_ERR, KRED "cfs_truncate(%s): file size (%lu) != truncate (%lu)",
           path, de->size, size);
  //dir_entry* de = check_path_info(path);
  //dir_entry* de = check_path_info_upload(path);
  //assert(de);
  //de->size = 0;
  //clock_gettime(CLOCK_REALTIME, &de->ctime_local);
  //cloudfs_object_truncate(de, size);
  debugf(DBG_NORM, KBLU "exit: cfs_truncate(%s)", path);
  return 0;
}

//this is called regularly on copy (via mc), is optimised (cached)
static int cfs_statfs(const char* path, struct statvfs* stat)
{
  debugf(DBG_NORM, KBLU "cfs_statfs(%s)", path);
  if (cloudfs_statfs(path, stat))
  {
    debugf(DBG_NORM, KBLU "exit 0: cfs_statfs(%s)", path);
    return 0;
  }
  else
  {
    debugf(DBG_NORM, KRED"exit 1: cfs_statfs(%s) not-found", path);
    return -EIO;
  }
}

static int cfs_chown(const char* path, uid_t uid, gid_t gid)
{
  if (option_enable_chown)
  {
    debugf(DBG_NORM, KBLU "cfs_chown(%s,%d,%d)", path, uid, gid);
    dir_entry* de = check_path_info(path);
    //get extended attributes
    bool res = get_file_metadata(de, true, true);
    if (de)
    {
      if (de->uid != uid || de->gid != gid)
      {
        debugf(DBG_NORM, "cfs_chown(%s): change from uid:gid %d:%d to %d:%d",
               path, de->uid, de->gid, uid, gid);
        de->uid = uid;
        de->gid = gid;
        int fd = open_lock_file(path, FUSE_FLAG_O_WRONLY, "chown");
        if (fd == -1)
          return -EBUSY;
        de->lock_fd = fd;
        int response = cloudfs_update_meta(de, false);
      }
    }
    debugf(DBG_NORM, KBLU "exit: cfs_chown(%s,%d,%d)", path, uid, gid);
  }
  return 0;
}

static int cfs_chmod(const char* path, mode_t mode)
{
  if (option_enable_chmod)
  {
    debugf(DBG_NORM, KBLU"cfs_chmod(%s,%d)", path, mode);
    dir_entry* de = check_path_info(path);
    //get extended attributes
    bool res = get_file_metadata(de, true, true);
    if (de)
    {
      if (de->chmod != mode)
      {
        debugf(DBG_NORM, "cfs_chmod(%s): change mode from %d to %d", path,
               de->chmod, mode);
        de->chmod = mode;
        //lock here, will be unlocked after meta update thread completes
        int fd = open_lock_file(path, FUSE_FLAG_O_WRONLY, "chmod");
        if (fd == -1)
          return -EBUSY;
        de->lock_fd = fd;
        int response = cloudfs_update_meta(de, false);
      }
    }
    debugf(DBG_NORM, KBLU"exit: cfs_chmod(%s,%d)", path, mode);
  }
  return 0;
}

static int cfs_rename(const char* src, const char* dst)
{
  debugf(DBG_NORM, KBLU"cfs_rename(%s, %s)", src, dst);
  int fd_src = open_lock_file(src, FUSE_FLAG_O_RDONLY, "rename-src");
  if (fd_src == -1)
    return -EBUSY;
  int fd_dst = open_lock_file(dst, FUSE_FLAG_O_WRONLY, "rename-dst");
  if (fd_dst == -1)
  {
    close_lock_file(src, fd_src);
    return -EBUSY;
  }
  int result = 0;
  dir_entry* src_de = path_info(src);
  if (!src_de)
  {
    debugf(DBG_NORM, KRED "exit 0: cfs_rename(%s,%s) not-found", src, dst);
    result = -ENOENT;
  }
  else if (src_de->isdir)
  {
    debugf(DBG_NORM, KRED "exit 1: cfs_rename(%s,%s) cannot rename dirs!",
           src, dst);
    result = -EISDIR;
  }
  else
  {
    //ensure segments are loaded
    get_file_metadata(src_de, true, true);
    if (cloudfs_copy_object(src_de, dst, false))
    {
      debugf(DBG_NORM, KBLU "cfs_rename(%s,%s): copy ok, del src", src, dst);
      cloudfs_delete_object(src_de);
      debugf(DBG_NORM, KBLU "cfs_rename(%s,%s): del OK %s", src, dst, src);
    }
    else result = -ENODATA;
  }
  close_lock_file(src, fd_src);
  close_lock_file(dst, fd_dst);
  if (result != 0)
    debugf(DBG_NORM, KRED"exit 3: cfs_rename(%s,%s) io error", src, dst);
  return result;
}

static int cfs_symlink(const char* src, const char* dst)
{
  debugf(DBG_NORM, KBLU"cfs_symlink(%s, %s)", src, dst);
  //dir_entry* de = check_path_info(src);
  if (cloudfs_create_symlink(src, dst))
  {
    update_dir_cache(dst, 1, 0, 1);
    debugf(DBG_NORM, KBLU"exit0: cfs_symlink(%s, %s)", src, dst);
    return 0;
  }
  debugf(DBG_NORM, KRED"exit1: cfs_symlink(%s, %s) io error", src, dst);
  return -EIO;
}

static int cfs_readlink(const char* path, char* buf, size_t size)
{
  debugf(DBG_NORM, KBLU"cfs_readlink(%s)", path);
  dir_entry* de = check_path_info(path);
  //fixme: use temp file specified in config
  FILE* temp_file = tmpfile();
  int ret = 0;
  /*if (!cloudfs_object_write_fp(de, temp_file))
    {
    debugf(DBG_NORM, KRED"exit 1: cfs_readlink(%s) not found", path);
    ret = -ENOENT;
    }
  */
  if (!pread(fileno(temp_file), buf, size, 0))
  {
    debugf(DBG_NORM, KRED"exit 2: cfs_readlink(%s) not found", path);
    ret = -ENOENT;
  }
  fclose(temp_file);
  debugf(DBG_NORM, KBLU"exit 3: cfs_readlink(%s)", path);
  return ret;
}

static void* cfs_init(struct fuse_conn_info* conn)
{
  signal(SIGPIPE, SIG_IGN);
  return NULL;
}


//http://man7.org/linux/man-pages/man2/utimensat.2.html
static int cfs_utimens(const char* path, const struct timespec times[2])
{
  debugf(DBG_NORM, KBLU "cfs_utimens(%s)", path);
  // looking for file entry in cache
  dir_entry* de = path_info(path);
  update_cache_access(de);
  if (!de)
  {
    debugf(DBG_NORM, KRED"exit 0: cfs_utimens(%s) file not in cache", path);
    return -ENOENT;
  }
  //get extended attributes
  bool res = get_file_metadata(de, true, true);

  if (!option_disable_atime_check &&
      (de->atime.tv_sec != times[0].tv_sec || de->atime.tv_nsec != times[0].tv_nsec)
      || de->mtime.tv_sec != times[1].tv_sec
      || de->mtime.tv_nsec != times[1].tv_nsec)
  {
    debugf(DBG_EXT, KCYN
           "cfs_utimens: change %s prev: atime=%li.%li mtime=%li.%li new: atime=%li.%li mtime=%li.%li",
           path, de->atime.tv_sec, de->atime.tv_nsec, de->mtime.tv_sec, de->mtime.tv_nsec,
           times[0].tv_sec, times[0].tv_nsec, times[1].tv_sec, times[1].tv_nsec);
    //lock here, will be unlocked after meta update thread completes
    int fd = open_lock_file(path, FUSE_FLAG_O_WRONLY, "utimens");
    if (fd == -1)
      return -EBUSY;
    de->lock_fd = fd;

    char time_str[TIME_CHARS] = "";
    get_timespec_as_str(&times[1], time_str, sizeof(time_str));
    debugf(DBG_EXT, KCYN"cfs_utimens: set mtime=[%s]", time_str);
    get_timespec_as_str(&times[0], time_str, sizeof(time_str));
    debugf(DBG_EXT, KCYN"cfs_utimens: set atime=[%s]", time_str);
    de->atime = times[0];
    de->mtime = times[1];
    // not sure how to best obtain ctime from fuse source file
    //just record current date.
    clock_gettime(CLOCK_REALTIME, &de->ctime);
    cloudfs_update_meta(de, false);
  }
  else
    debugf(DBG_EXT, KCYN"cfs_utimens: a/m/time not changed");
  debugf(DBG_NORM, KBLU "exit 1: cfs_utimens(%s)", path);
  return 0;
}

//todo: would be great if someone implements these 4 extended attributes methods
int cfs_setxattr(const char* path, const char* name, const char* value,
                 size_t size, int flags)
{
  debugf(DBG_EXT, KBLU "cfs_setxattr(%s): name=%s value=%s",
         path, name, value);
  return 0;
}

int cfs_getxattr(const char* path, const char* name, char* value, size_t size)
{
  debugf(DBG_EXT, KBLU "cfs_getxattr(%s): name=%s value=%s",
         path, name, value);
  return 0;
}

int cfs_removexattr(const char* path, const char* name)
{
  debugf(DBG_EXT, KBLU "cfs_removexattr(%s): name=%s", path, name);
  return 0;
}

int cfs_listxattr(const char* path, char* list, size_t size)
{
  debugf(DBG_EXT, KBLU "cfs_listxattr(%s): name=%s", path);
  return 0;
}

void control_thread_run()
{
  debugf(DBG_NORM, "control_thread_run initialised");
  while (true)
  {
    debugf(DBG_EXT, KGRN "control_thread_run: locks=%d", get_open_locks());
    sleep_ms(10000);
  }
  debugf(DBG_NORM, "control_thread_run exit");
  pthread_exit(NULL);
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
             extra_options.disable_atime_check)
     )
    return 0;
  if (!strcmp(arg, "-f") || !strcmp(arg, "-d") || !strcmp(arg, "debug"))
    debug = 1;
  return 1;
}


int main(int argc, char** argv)
{
  fprintf(stderr, "Starting hubicfuse on homedir %s!\n", get_home_dir());
  signal(SIGINT, interrupt_handler);
  /* Catch Signal Handler SIGPIPE */
  signal(SIGPIPE, sigpipe_callback_handler);

  struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
  if (!initialise_options(args))
    return 1;
  debugf(DBG_ERR, "Starting hubicfuse");
  fuse_opt_parse(&args, &options, NULL, parse_option);
  cloudfs_init();
  if (debug)
    print_options();

  cloudfs_set_credentials(options.client_id, options.client_secret,
                          options.refresh_token);
  if (!cloudfs_connect())
  {
    fprintf(stderr, "Failed to authenticate.\n");
    return 1;
  }
#ifndef HAVE_OPENSSL
//#warning Compiling without libssl, will run single-threaded.
//  fuse_opt_add_arg(&args, "-s");
#endif
//https://www.cs.hmc.edu/~geoff/classes/hmc.cs135.201001/homework/fuse/fuse_doc.html
  struct fuse_operations cfs_oper =
  {
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
    .utimens = cfs_utimens,
//#ifdef HAVE_SETXATTR
    .setxattr = cfs_setxattr,
    .getxattr = cfs_getxattr,
    .listxattr = cfs_listxattr,
    .removexattr = cfs_removexattr,
//#endif
//    .fsyncdir    = cfs_fsyncdir,
//.lock = prefix_lock,
//.bmap = prefix_bmap,
//.ioctl = prefix_ioctl,
//.poll = prefix_poll,

  };
  pthread_mutexattr_init(&mutex_attr);
  pthread_mutexattr_settype(&mutex_attr, PTHREAD_MUTEX_RECURSIVE);
  pthread_mutex_init(&dcachemut, &mutex_attr);
  pthread_mutex_init(&dcacheuploadmut, &mutex_attr);
  pthread_mutexattr_init(&segment_mutex_attr);
  pthread_mutexattr_settype(&segment_mutex_attr, PTHREAD_MUTEX_ERRORCHECK);
  //init control thread
  pthread_create(&control_thread, NULL, (void*)control_thread_run, NULL);
  //create parent segment storage (might exist already)
  cloudfs_create_directory(HUBIC_SEGMENT_STORAGE_ROOT);
  return fuse_main(args.argc, args.argv, &cfs_oper, &options);
}
