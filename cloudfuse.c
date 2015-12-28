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

extern char* temp_dir;
extern pthread_mutex_t dcachemut;
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
extern size_t file_buffer_size;
extern bool option_enable_progressive_upload;
extern bool option_enable_progressive_download;
extern long option_min_speed_limit_progressive;
extern long option_min_speed_timeout;
extern long option_read_ahead;

static int cfs_getattr(const char* path, struct stat* stbuf)
{
  debugf(DBG_LEVEL_NORM, KBLU "cfs_getattr(%s)", path);
  //return standard values for root folder
  if (!strcmp(path, "/"))
  {
    stbuf->st_uid = geteuid();
    stbuf->st_gid = getegid();
    stbuf->st_mode = S_IFDIR | 0755;
    stbuf->st_nlink = 2;
    debug_list_cache_content();
    debugf(DBG_LEVEL_NORM, KBLU "exit 0: cfs_getattr(%s)", path);
    return 0;
  }
  //get file. if not in cache will be downloaded.
  dir_entry* de = path_info(path);
  if (!de)
  {
    debug_list_cache_content();
    debugf(DBG_LEVEL_NORM, KBLU"exit 1: cfs_getattr(%s) file not found "
           KYEL "not-in-cache/cloud", path);
    return -ENOENT;
  }
  //lazzy download of file metadata, only when really needed
  if (option_get_extended_metadata && !de->metadata_downloaded)
    get_file_metadata(de);
  if (option_enable_chown)
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
  debugf(DBG_LEVEL_EXTALL, KCYN"cfs_getattr: atime=[%s]", time_str);
  get_timespec_as_str(&(de->mtime), time_str, sizeof(time_str));
  debugf(DBG_LEVEL_EXTALL, KCYN"cfs_getattr: mtime=[%s]", time_str);
  get_timespec_as_str(&(de->ctime), time_str, sizeof(time_str));
  debugf(DBG_LEVEL_EXTALL, KCYN"cfs_getattr: ctime=[%s]", time_str);
  int default_mode_dir, default_mode_file;
  if (option_enable_chmod)
  {
    default_mode_dir = de->chmod;
    default_mode_file = de->chmod;
  }
  else
  {
    default_mode_dir = 0755;
    default_mode_file = 0666;
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
  debugf(DBG_LEVEL_NORM, KBLU "exit 2: cfs_getattr(%s) size=%lu", path,
         de->size);
  return 0;
}

static int cfs_fgetattr(const char* path, struct stat* stbuf,
                        struct fuse_file_info* info)
{
  debugf(DBG_LEVEL_NORM, KBLU "cfs_fgetattr(%s)", path);

  //openfile* of = (openfile*)(uintptr_t)info->fh;
  //if (of)
  //{
  //get file. if not in cache will be downloaded.
  dir_entry* de = path_info(path);
  if (!de)
  {
    debug_list_cache_content();
    debugf(DBG_LEVEL_NORM, KBLU "exit 1: cfs_fgetattr(%s) "
           KYEL "not-in-cache/cloud", path);
    return -ENOENT;
  }
  int default_mode_file;
  if (option_enable_chmod)
    default_mode_file = de->chmod;
  else
    default_mode_file = 0666;
  stbuf->st_size = de->size;//cloudfs_file_size(of->fd);
  stbuf->st_mode = S_IFREG | default_mode_file;
  stbuf->st_nlink = 1;
  debugf(DBG_LEVEL_NORM, KBLU "exit 0: cfs_fgetattr(%s)", path);
  return 0;
  //}
}

static int cfs_readdir(const char* path, void* buf, fuse_fill_dir_t filldir,
                       off_t offset, struct fuse_file_info* info)
{
  debugf(DBG_LEVEL_NORM, KBLU "cfs_readdir(%s)", path);
  dir_entry* de;
  if (!caching_list_directory(path, &de))
  {
    debug_list_cache_content();
    debugf(DBG_LEVEL_NORM, KRED "exit 0: cfs_readdir(%s)", path);
    return -ENOLINK;
  }
  filldir(buf, ".", NULL, 0);
  filldir(buf, "..", NULL, 0);
  for (; de; de = de->next)
    filldir(buf, de->name, NULL, 0);
  debug_list_cache_content();
  debugf(DBG_LEVEL_NORM, KBLU "exit 1: cfs_readdir(%s)", path);
  return 0;
}

static int cfs_mkdir(const char* path, mode_t mode)
{
  debugf(DBG_LEVEL_NORM, KBLU "cfs_mkdir(%s)", path);
  int response = cloudfs_create_directory(path);
  if (response)
  {
    update_dir_cache(path, 0, 1, 0);
    debug_list_cache_content();
    debugf(DBG_LEVEL_NORM, KBLU "exit 0: cfs_mkdir(%s)", path);
    return 0;
  }
  debugf(DBG_LEVEL_NORM, KRED "exit 1: cfs_mkdir(%s) response=%d", path,
         response);
  return -ENOENT;
}

static int cfs_create(const char* path, mode_t mode,
                      struct fuse_file_info* info)
{
  debugf(DBG_LEVEL_NORM, KBLU "cfs_create(%s)", path);
  FILE* temp_file;
  int errsv;
  char file_path_safe[NAME_MAX] = "";
  /*if (*temp_dir)
    {
    get_safe_cache_file_path(path, file_path_safe, NULL, temp_dir, -1);
    temp_file = fopen(file_path_safe, "w+b");
    errsv = errno;
    if (temp_file == NULL)
    {
      debugf(DBG_LEVEL_NORM, KRED
             "exit 0: cfs_create cannot open temp file %s.error %s\n", file_path_safe,
             strerror(errsv));
      return -EIO;
    }
    }
    else
    {
    temp_file = tmpfile();
    errsv = errno;
    if (temp_file == NULL)
    {
      debugf(DBG_LEVEL_NORM, KRED
             "exit 1: cfs_create cannot open tmp file for path %s.error %s\n", path,
             strerror(errsv));
      return -EIO;
    }
    }
    openfile* of = (openfile*)malloc(sizeof(openfile));
    of->fd = dup(fileno(temp_file));
    fclose(temp_file);
    of->flags = info->flags;
    info->fh = (uintptr_t)of;
  */
  info->fh = -1;
  update_dir_cache(path, 0, 0, 0);
  info->direct_io = 1;
  dir_entry* de = check_path_info(path);
  if (de)
  {
    debugf(DBG_LEVEL_EXT, KCYN"cfs_create(%s): found in cache", path);
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    debugf(DBG_LEVEL_EXT, KCYN"cfs_create(%s) set utimes as now", path);
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
    debugf(DBG_LEVEL_EXT, KCYN"cfs_create: atime=[%s]", time_str);
    get_timespec_as_str(&(de->mtime), time_str, sizeof(time_str));
    debugf(DBG_LEVEL_EXT, KCYN"cfs_create: mtime=[%s]", time_str);
    get_timespec_as_str(&(de->ctime), time_str, sizeof(time_str));
    debugf(DBG_LEVEL_EXT, KCYN"cfs_create: ctime=[%s]", time_str);
    //set chmod & chown
    de->chmod = mode;
    de->uid = geteuid();
    de->gid = getegid();
  }
  else
    debugf(DBG_LEVEL_EXT, KBLU "cfs_create(%s) "KYEL"dir-entry not found", path);
  debugf(DBG_LEVEL_NORM, KBLU "exit 2: cfs_create(%s)=(%s) result=%d:%s", path,
         file_path_safe, errsv, strerror(errsv));
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
  debugf(DBG_LEVEL_NORM, KBLU
         "cfs_open(%s) d_io=%d flush=%d non_seek=%d write_pg=%d fh=%p",
         path, info->direct_io, info->flush, info->nonseekable, info->writepage,
         info->fh);
  FILE* temp_file = NULL;
  int errsv;
  bool file_cache_ok = false;
  dir_entry* de = path_info(path);
  if (!de)
    return -ENOENT;

  /*
    if (*temp_dir)
    {
    char file_path_safe[NAME_MAX];
    get_safe_cache_file_path(path, file_path_safe, NULL, temp_dir, -1);
    debugf(DBG_LEVEL_EXT, "cfs_open: try open custom temp (%s)", file_path_safe);
    if (access(file_path_safe, F_OK) != -1)
    {
      // file exists in local cache
      temp_file = fopen(file_path_safe, "r");
      errsv = errno;
      if (temp_file == NULL)
      {
        debugf(DBG_LEVEL_NORM, KRED
               "exit 0: cfs_open can't open temp_file=[%s] err=%d:%s",
               file_path_safe, errsv, strerror(errsv));
        return -ENOENT;
      }
      else
      {
        debugf(DBG_LEVEL_EXT, "cfs_open: " KGRN "file is in cache(%s)",
               file_path_safe);
        //todo: compute md5sum to ensure file content is OK
        if (de)
        {
          if (!option_enable_progressive_download && de->md5sum_local == NULL)
          {
            //save md5sum to avoid repetead calculations
            char md5_file_hash_str[MD5_DIGEST_HEXA_STRING_LEN] = "\0";
            file_md5(temp_file, md5_file_hash_str);
            de->md5sum_local = strdup(md5_file_hash_str);
          }

          if (de && de->md5sum && de->md5sum_local
              && (!strcasecmp(de->md5sum_local, de->md5sum)))
          {
            debugf(DBG_LEVEL_EXT, "cfs_open: "KGRN"md5sum cache OK");
            file_cache_ok = true;
            //leave file open
          }
          else
          {
            debugf(DBG_LEVEL_EXT, "cfs_open: "KYEL"md5sum cache NOT OK (%s)",
                   file_path_safe);
            debugf(DBG_LEVEL_EXT, "cfs_open: "KYEL"md5sum de_cache=%s, local=%s",
                   de->md5sum, de->md5sum_local);
            fclose(temp_file);
          }
        }
        else
        {
          debugf(DBG_LEVEL_EXT,
                 "cfs_open: file in cache but"KYEL"unable to find cloud md5sum");
          fclose(temp_file);
        }
      }
    }

    if (!file_cache_ok)
    {
      errsv = errno;
      debugf(DBG_LEVEL_EXT, "cfs_open: file not in cache, err=%s", strerror(errsv));
      //FIXME: commented out as this condition will not be meet in some odd cases and program will crash
      //if (!(info->flags & O_WRONLY)) {
      debugf(DBG_LEVEL_EXT, "cfs_open: opening custom temp(%s)",
             file_path_safe);
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
      if (temp_file == NULL)
      {
        debugf(DBG_LEVEL_NORM,
               KRED"exit 1: cfs_open cannot open custom temp=[%s] err=%d:%s",
               file_path_safe, errsv, strerror(errsv));
        return -ENOENT;
      }

      debugf(DBG_LEVEL_NORM, KMAG "cfs_open(%s) temp fp=%p", path, temp_file);

      //skip file download if progressive, done later in cfs_read
      if (!option_enable_progressive_download)
      {
        //standard download (not progressive), get full file in local cache
        if (!cloudfs_object_write_fp(path, temp_file))
        {
          fclose(temp_file);
          debugf(DBG_LEVEL_NORM, KRED
                 "exit 2: cfs_open(%s) cannot download/write custom temp",
                 path);
          return -ENOENT;
        }
      }
    }
    //else file is in cache
    }
    else
    {
    //using system standard temp directory
    temp_file = tmpfile();
    if (temp_file == NULL)
    {
      debugf(DBG_LEVEL_NORM, KRED"exit 3: cfs_open cannot create tmpfile err=%s",
             strerror(errno));
      return -ENOENT;
    }
    if (!(info->flags & O_TRUNC))
    {
      //todo: why is this check on flags needed?
      if (!option_enable_progressive_download &&
          !cloudfs_object_write_fp(path, temp_file) && !(info->flags & O_CREAT))
      {
        fclose(temp_file);
        debugf(DBG_LEVEL_NORM,
               KRED"exit 4: cfs_open(%s) cannot download/write tmpfile", path);
        return -ENOENT;
      }
    }
    }
  */
  /*
    update_dir_cache(path, (de ? de->size : 0), 0, 0);
    openfile* of = (openfile*)malloc(sizeof(openfile));//where is this free'd?
    of->fd = dup(fileno(temp_file));
    if (of->fd == -1)
    {
    //FIXME: potential leak if free not used?
    free(of);
    debugf(DBG_LEVEL_NORM, KRED "exit 5: cfs_open(%s) of->fd", path);
    return -ENOENT;
    }
    debugf(DBG_LEVEL_NORM, KMAG "cfs_open(%s) fp=%p", path, temp_file);

    of->flags = info->flags;
  */
  //info->fh = (uintptr_t)of;
  info->fh = -1;
  info->direct_io = 1;
  //non seek must be set to 0 to enable
  // video players work via samba (as they perform a seek to file end)
  info->nonseekable = 0;

  /*
    //launch download as thread if progressive is enabled and file not in cache
    if (!file_cache_ok && option_enable_progressive_download)
    {
    //if (de->downld_buf.download_started)
    //  debugf(DBG_LEVEL_NORM, "cfs_open(%s): " KYEL
    //         "local file already opened, op. in progress",
    //         path);
    //else
    //{
    de->downld_buf.local_cache_file = fdopen(dup(fileno(temp_file)), "w+b");
    errsv = errno;
    if (de->downld_buf.local_cache_file != NULL)
    {
      de->downld_buf.work_buf_size = 0;
      //put something different that work_buf_size to avoid wait by http
      de->downld_buf.fuse_read_size = 0;
      de->downld_buf.file_is_in_cache = false;
      //save de on current thread stack
      //thread_de_read = de;
    }
    else
    {
      debugf(DBG_LEVEL_NORM, KRED
             "cfs_open(%s): exit 6, failed opening temp_file err=%s",
             path, strerror(errno));
      fclose(temp_file);
      return -ENOENT;
    }
    //}
    }
    else
    {
    debugf(DBG_LEVEL_NORM, KMAG"exit 7: cfs_open(%s) "KGRN"FILE in CACHE", path);
    //signal file should be in cache at cfs_read
    de->downld_buf.file_is_in_cache = true;
    }
    fclose(temp_file);
  */
  debugf(DBG_LEVEL_NORM, KBLU "exit 8: cfs_open(%s)", path);
  return 0;
  //return ((openfile*)(uintptr_t)info->fh)->fd;
}

static int cfs_read(const char* path, char* buf, size_t size, off_t offset,
                    struct fuse_file_info* info)
{
  int result = -1;
  off_t offset_seg;
  int sem_val, err;
  int rnd = random_at_most(50);
  if (offset == 0)//avoid clutter, list only once
    debugf(DBG_LEVEL_EXT, KBLU
           "cfs_read(%s) buffsize=%lu offset=%lu ", path, size, offset);
  //sleep_ms(rnd);
  int iters = 0;
  file_buffer_size = size;
  debug_print_descriptor(info);
  bool in_cache = false;
  dir_entry* de = check_path_info(path);

  if (de && de->is_segmented)
  {
    int read_ahead_count = (option_read_ahead / de->segment_size) + 1;
    int segment_part = offset / de->segment_size;
    dir_entry* de_seg, *de_seg_next;
    while (result <= 0)
    {
      de_seg = get_segment(de, segment_part);
      assert(de_seg);
      //offset in segment is different than full file offset
      offset_seg = offset - (segment_part * de->segment_size);
      debugf(DBG_LEVEL_EXTALL, KMAG
             "cfs_read: while seg path=%s off=%lu segment=%d seg_name=%s md5=%s",
             de->name, offset, segment_part, de_seg->name, de_seg->md5sum);
      if (de_seg)
      {
        bool in_cache;
        FILE* fp_segment = NULL;
        in_cache = open_segment_cache_md5(de, de_seg, &fp_segment, HTTP_GET);
        if (!in_cache)
        {
          debugf(DBG_LEVEL_EXT, KMAG "cfs_read(%s): seg %d " KYEL "not in cache",
                 de_seg->name, segment_part);
          download_ahead_segment(de_seg, de, fp_segment, true);
          if (de_seg->downld_buf.mutex_initialised)
          {
            debugf(DBG_LEVEL_EXT, KBLU
                   "cfs_read: 1-wait lock seg=%s", de_seg->name);
            pthread_mutex_lock(&de_seg->downld_buf.mutex);
            debugf(DBG_LEVEL_EXT, KBLU
                   "cfs_read: 1-wait data seg=%s", de_seg->name);
            if (de_seg->downld_buf.sem_list[SEM_FULL])
              sem_wait(de_seg->downld_buf.sem_list[SEM_FULL]);
            pthread_mutex_unlock(&de_seg->downld_buf.mutex);
          }
          else
          {
            debugf(DBG_LEVEL_EXT, KBLU
                   "cfs_read: 2-wait data seg=%s", de_seg->name);
            if (de_seg->downld_buf.sem_list[SEM_FULL])
              sem_wait(de_seg->downld_buf.sem_list[SEM_FULL]);
          }
          debugf(DBG_LEVEL_EXT, KBLU
                 "cfs_read: got full data seg=%s", de_seg->name);
          fclose(fp_segment);
          fp_segment = NULL;
          in_cache = open_segment_cache_md5(de, de_seg, &fp_segment, HTTP_GET);
          if (!in_cache)
            debugf(DBG_LEVEL_EXT, KYEL
                   "cfs_read: read ahead failed seg=%s", de_seg->name);
          else
            debugf(DBG_LEVEL_EXT, "cfs_read: read ahead OK seg=%s", de_seg->name);
        }

        if (in_cache)
        {
          int fno = fileno(fp_segment);
          if (fno != -1)//safety check
          {
            result = pread(fno, buf, size, offset_seg);
            err = errno;
            debugf(DBG_LEVEL_EXT, KBLU "cfs_read(%s) fno=%d fp=%p p=%d err=%s",
                   de_seg->name, fno, fp_segment, segment_part, strerror(err));
            close(fno);
            fclose(fp_segment);
            //download if segment ahead not in cache and no other download runs
            de_seg_next = get_segment(de, segment_part + read_ahead_count);
            if (de->downld_buf.ahead_thread_count == 0 && de_seg_next &&
                (de_seg_next->md5sum_local == NULL
                 || (strcasecmp(de_seg_next->md5sum_local, de_seg_next->md5sum))))
              download_ahead_segment(de_seg_next, de, fp_segment, false);

            if (result > 0)
              return result;
            else
            {
              debugf(DBG_LEVEL_EXT, KMAG "cfs_read(%s): done serving segment %d",
                     path, segment_part);
              //force download (or read from cache) of a new segment
              segment_part++;
              //exit if all segments are downloaded
              if (segment_part == de->segment_count)
                break;
            }
          }
          else //fno == -1
          {
            debugf(DBG_LEVEL_NORM, KRED "cfs_read(%s): error seg_fp(%p) fileno=-1",
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
            debugf(DBG_LEVEL_EXT, KRED
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
          debugf(DBG_LEVEL_EXT, KBLU
                 "cfs_read: post empty data, buf_size=%lu sem=%d",
                 size, sem_val);
          sem_post(de->downld_buf.sem_list[SEM_EMPTY]);
          sem_getvalue(de->downld_buf.sem_list[SEM_FULL], &sem_val);
          debugf(DBG_LEVEL_EXT, KBLU "cfs_read: wait full data sem=%d",
                 sem_val);
          //wait until data buffer is full
          sem_wait(de->downld_buf.sem_list[SEM_FULL]);
          debugf(DBG_LEVEL_EXT, KBLU "cfs_read: got full data size=%lu",
                 de->downld_buf.work_buf_size);
          debugf(DBG_LEVEL_EXT, KBLU "cfs_read: exit ret_code=%lu",
                 de->downld_buf.work_buf_size);
          if (de->downld_buf.work_buf_size == 0)
          {
            //cleanup thread, read completed
            //de->downld_buf.download_started = false;
            //thread_de_read = NULL;
          }
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
    debugf(DBG_LEVEL_NORM, "cfs_read(%s): read non segmented file", path);
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
          debugf(DBG_LEVEL_EXT, KYEL
                 "cfs_read: download failed file=%s", de->name);
        else
          debugf(DBG_LEVEL_EXT, "cfs_read: download OK file=%s", de->name);
      }

      if (in_cache)
      {
        int fno = fileno(fp_file);
        if (fno != -1)//safety check
        {
          result = pread(fno, buf, size, offset);
          err = errno;
          debugf(DBG_LEVEL_EXT, KBLU "cfs_read(%s) fno=%d fp=%p err=%s",
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
        debugf(DBG_LEVEL_NORM, KRED "cfs_read(%s): unable to download", de->name);
        return -ENOENT;
      }
    }//end while
    return result;
  }
  /*
    result = pread(((openfile*)(uintptr_t)info->fh)->fd, buf, size, offset);
    debugf(DBG_LEVEL_EXT, "cfs_read(%s): got data from file", path);
    if (offset == 0)
    debugf(DBG_LEVEL_NORM, KBLU "exit: cfs_read(%s) result=%s", path,
    strerror(errno));
    else
    debugf(DBG_LEVEL_NORM, KBLU "exit: cfs_read(%s) result=%s", path,
    strerror(errno));
    return result;
  */
}

//todo: flush will upload a file again even if just file attributes are changed.
//optimisation needed to detect if content is changed
//and to only save meta when just attribs are modified.
static int cfs_flush(const char* path, struct fuse_file_info* info)
{
  debugf(DBG_LEVEL_NORM, KBLU
         "cfs_flush(%s) d_io=%d flush=%d non_seek=%d write_pg=%d fh=%p",
         path, info->direct_io, info->flush, info->nonseekable, info->writepage,
         info->fh);
  debug_print_descriptor(info);
  int errsv = 0;
  dir_entry* de = check_path_info(path);
  assert(de);
  /*
    if (info->fh != -1)
    {
    openfile* of = (openfile*)(uintptr_t)info->fh;
    if (of)
    {
      //this reset file size to 0 for large segmented files
      //off_t file_size = cloudfs_file_size(of->fd);
      //update_dir_cache(path, file_size, 0, 0);
      if (of->flags & O_RDWR || of->flags & O_WRONLY)
      {
        FILE* fp = fdopen(dup(of->fd), "r");
        errsv = errno;
        if (fp != NULL)
        {
          //on progressive ops upload is already done
          if (option_enable_progressive_upload && de->size > 0)
          {
            debugf(DBG_LEVEL_EXT, KMAG"cfs_flush(%s): progressive ops completed, size=%lu",
                   path, de->size);
            //signal completion of read/write operation
            de->upload_buf.write_completed = true;
            //signal last data available in buffer for upload
            sem_post(de->upload_buf.isfull_semaphore);
            sem_wait(de->upload_buf.isempty_semaphore);
            fclose(fp);
            errsv = 0;
          }
          else
          {
            rewind(fp);
            //calculate md5 hash, compare with cloud hash to determine if file content is changed
            char md5_file_hash_str[MD5_DIGEST_HEXA_STRING_LEN] = "\0";
            file_md5(fp, md5_file_hash_str);
            if (de && de->md5sum != NULL && (!strcasecmp(md5_file_hash_str, de->md5sum)))
            {
              //file content is identical, no need to upload entire file, just update metadata
              debugf(DBG_LEVEL_NORM, KBLU
                     "cfs_flush(%s): skip full upload as content did not change", path);
              cloudfs_update_meta(de);
            }
            else
            {
              //upload file from cache to cloud
              rewind(fp);
              debugf(DBG_LEVEL_NORM, KBLU
                     "cfs_flush(%s): perform full upload as content changed (or no file found in cache)",
                     path);
              if (!cloudfs_object_read_fp(path, fp))
              {
                fclose(fp);
                errsv = errno;
                debugf(DBG_LEVEL_NORM, KRED"exit 0: cfs_flush(%s) result=%d:%s", path, errsv,
                       strerror(errsv));
                return -ENOENT;
              }
            }
            fclose(fp);
            errsv = errno;
          }
        }
        else
          debugf(DBG_LEVEL_EXT, KRED "status: cfs_flush, err=%d:%s", errsv,
                 strerror(errsv));
      }
      else
      {
        //todo: what to do here?

      }
    }
    }
  */
  //else //fh == -1
  //{

  if (option_enable_progressive_upload && de->size > 0)
  {
    debugf(DBG_LEVEL_EXT, KMAG"cfs_flush(%s): progressive ops completed, size=%lu",
           path, de->size);
    //signal completion of read/write operation
    //de->upload_buf.write_completed = true;
    //signal last data available in buffer for upload
    if (de->upload_buf.sem_list[SEM_FULL])
      sem_post(de->upload_buf.sem_list[SEM_FULL]);
    //if (de->upload_buf.sem_list[SEM_EMPTY])
    //  sem_wait(de->upload_buf.sem_list[SEM_EMPTY]);
    errsv = 0;
  }

  //if segmented or progressive upload is already done by now, skip it
  if (!de->is_segmented && !option_enable_progressive_upload)
  {
    if (/*file_changed_time(de) || */file_changed_md5(de))
    {
      debugf(DBG_LEVEL_EXT, "cfs_flush(%s): time/content changed", de->name);
      cloudfs_upload_segment(de, de);
    }
    else
      debugf(DBG_LEVEL_EXT, "cfs_flush(%s): time/content not changed", de->name);
  }
  debugf(DBG_LEVEL_NORM, KBLU "exit 1: cfs_flush(%s) result=%d:%s", path, errsv,
         strerror(errsv));
  return 0;
  //}
}

static int cfs_release(const char* path, struct fuse_file_info* info)
{
  debugf(DBG_LEVEL_NORM, KBLU
         "cfs_release(%s) d_io=%d flush=%d non_seek=%d write_pg=%d fh=%p",
         path, info->direct_io, info->flush, info->nonseekable, info->writepage,
         info->fh);
  if (info->fh != -1)
    close(((openfile*)(uintptr_t)info->fh)->fd);
  debugf(DBG_LEVEL_NORM, KBLU "exit: cfs_release(%s)", path);
  return 0;
}

static int cfs_rmdir(const char* path)
{
  debugf(DBG_LEVEL_NORM, KBLU "cfs_rmdir(%s)", path);
  int success = cloudfs_delete_object(path);
  if (success == -1)
  {
    debugf(DBG_LEVEL_NORM, KBLU "exit 0: cfs_rmdir(%s)", path);
    return -ENOTEMPTY;
  }
  if (success)
  {
    dir_decache(path);
    debugf(DBG_LEVEL_NORM, KBLU "exit 1: cfs_rmdir(%s)", path);
    return 0;
  }
  debugf(DBG_LEVEL_NORM, KBLU "exit 2: cfs_rmdir(%s)", path);
  return -ENOENT;
}

static int cfs_ftruncate(const char* path, off_t size,
                         struct fuse_file_info* info)
{
  debugf(DBG_LEVEL_NORM, KBLU "cfs_ftruncate(%s)", path);
  file_buffer_size = size;
  openfile* of = (openfile*)(uintptr_t)info->fh;
  if (ftruncate(of->fd, size))
    return -errno;
  lseek(of->fd, 0, SEEK_SET);
  update_dir_cache(path, size, 0, 0);
  debugf(DBG_LEVEL_NORM, KBLU "exit: cfs_ftruncate(%s)", path);
  return 0;
}

/*
  upload file to cloud
*/
static int cfs_write(const char* path, const char* buf, size_t length,
                     off_t offset, struct fuse_file_info* info)
{
  if (offset == 0)//avoid clutter
    debugf(DBG_LEVEL_EXT, KBLU
           "cfs_write(%s) blen=%lu off=%lu *buf=%lu", path, length, offset, buf);
  else
    debugf(DBG_LEVEL_EXTALL, KBLU
           "cfs_write(%s) blen=%lu off=%lu *buf=%lu", path, length, offset, buf);
  int result, errsv;
  dir_entry* de = check_path_info(path);
  if (!de)
  {
    update_dir_cache(path, offset, 0, 0);
    de = check_path_info(path);
  }
  assert(de);
  /*
    if (de->is_segmented)
    {
    int i;
    dir_entry* de_seg;
    size_t file_size = offset + length;
    long seg_count = file_size / segment_size;
    FILE* fp = NULL;
    int seg_index = offset / segment_size;
    if (file_size % segment_size > 0)
      seg_count++;

    for (i = seg_index)
    {
      de_seg = get_create_segment(de, seg_index);
      //todo: work in progress
      open_segment_in_cache(de, de_seg, &fp, HTTP_PUT);
      int fno = fileno(fp);
      assert(fno != -1);
      result = pwrite(fno, buf, length, offset);
      errsv = errno;
      fclose(fp);
      clock_gettime(CLOCK_REALTIME, &de->ctime_local);
      de_seg->size = offset + result;//length;
    }
    debugf(DBG_LEVEL_EXT, KBLU "exit 1: cfs_write(%s) result=%s", path,
           strerror(errsv));
    return result;
    }

  */
  //if (!de->is_segmented)
  //{
  //todo: prior check of md5sum file content not done here,
  //upload optimisation not functional
  if (!option_enable_progressive_upload)
  {
    //regular upload, copy first in cache, upload at flush, no progress
    FILE* fp = NULL;
    bool in_cache = open_file_in_cache(de, &fp, HTTP_PUT);
    int fno = fileno(fp);
    assert(fno != -1);
    result = pwrite(fno, buf, length, offset);
    de->size = offset + result;
    errsv = errno;
    fclose(fp);
    clock_gettime(CLOCK_REALTIME, &de->ctime_local);
    if (de->md5sum_local)
    {
      free(de->md5sum_local);
      de->md5sum_local = NULL;
    }
    debugf(DBG_LEVEL_EXT, KBLU "exit 0: cfs_write(%s) result=%s", path,
           strerror(errsv));
    return result;
  }
  else
  {
    dir_entry* de_seg;
    int seg_index = 0;
    int sem_val_full, sem_val_empty;
    if (option_enable_progressive_upload)// && de->size > segment_above)
    {
      //creates the segment to be uploaded as dir_entry and sets minimum required fields
      seg_index = offset / segment_size;
      de_seg = get_create_segment(de, seg_index);
      assert(get_segment(de, seg_index));
      //alter offset for segmented uploads
      de_seg->upload_buf.offset = offset - (seg_index * segment_size);
      de_seg->upload_buf.readptr = buf;
      //todo: alter size for segmented to avoid going above segment_size
      de_seg->upload_buf.work_buf_size = length;
    }
    else
    {
      de->upload_buf.offset = offset;
      de->upload_buf.readptr = buf;
      de->upload_buf.work_buf_size = length;
    }
    de->size = offset + length;

    if (offset == 0)
    {
      de->is_segmented = true;
      init_semaphores(&de->upload_buf, de, "upload");
      //progressive for large (segmented files)
      if (option_enable_progressive_upload)// && de->size > segment_above)
      {
        bool op_ok = cloudfs_create_segment(de_seg, de);
        assert(op_ok);
        ;
      }
      else //progressive for non-segmented files
      {
        //start file upload with a new thread
        debugf(DBG_LEVEL_NORM, KBLU "cfs_write(%s) start upload thread buf_len=%lu",
               path, length);
        pthread_create(&de->upload_buf.thread, NULL,
                       (void*)cloudfs_object_upload_progressive, de);
      }
    }
    //signal there is data available in buffer for upload
    sem_post(de->upload_buf.sem_list[SEM_FULL]);//isfull_semaphore);
    //wait until previous buffer data is uploaded
    sem_wait(de->upload_buf.sem_list[SEM_EMPTY]);//isempty_semaphore);
    sem_getvalue(de->upload_buf.sem_list[SEM_FULL], &sem_val_full);
    debugf(DBG_LEVEL_EXTALL, KMAG
           "cfs_write(%s): buffer for upload, sem_val_full=%d", path,
           sem_val_full);
    return length;//?
  }
}

static int cfs_unlink(const char* path)
{
  debugf(DBG_LEVEL_NORM, KBLU "cfs_unlink(%s)", path);
  int success = cloudfs_delete_object(path);
  if (success == -1)
  {
    debugf(DBG_LEVEL_NORM, KRED "exit 0: cfs_unlink(%s)", path);
    return -EACCES;
  }
  if (success)
  {
    dir_decache(path);
    debugf(DBG_LEVEL_NORM, KBLU "exit 1: cfs_unlink(%s)", path);
    return 0;
  }
  debugf(DBG_LEVEL_NORM, KRED "exit 2: cfs_unlink(%s)", path);
  return -ENOENT;
}

static int cfs_fsync(const char* path, int idunno,
                     struct fuse_file_info* info)
{
  debugf(DBG_LEVEL_NORM, "cfs_fsync(%s)", path);
  return 0;
}

static int cfs_truncate(const char* path, off_t size)
{
  debugf(DBG_LEVEL_NORM, "cfs_truncate(%s)", path);
  dir_entry* de = check_path_info(path);
  assert(de);
  clock_gettime(CLOCK_REALTIME, &de->ctime_local);
  cloudfs_object_truncate(path, size);
  debugf(DBG_LEVEL_NORM, "exit: cfs_truncate(%s)", path);
  return 0;
}

//this is called regularly on copy (via mc), is optimised (cached)
static int cfs_statfs(const char* path, struct statvfs* stat)
{
  debugf(DBG_LEVEL_NORM, KBLU "cfs_statfs(%s)", path);
  if (cloudfs_statfs(path, stat))
  {
    debugf(DBG_LEVEL_NORM, KBLU "exit 0: cfs_statfs(%s)", path);
    return 0;
  }
  else
  {
    debugf(DBG_LEVEL_NORM, KRED"exit 1: cfs_statfs(%s) not-found", path);
    return -EIO;
  }
}

static int cfs_chown(const char* path, uid_t uid, gid_t gid)
{
  if (option_enable_chown)
  {
    debugf(DBG_LEVEL_NORM, KBLU "cfs_chown(%s,%d,%d)", path, uid, gid);
    dir_entry* de = check_path_info(path);
    if (de)
    {
      if (de->uid != uid || de->gid != gid)
      {
        debugf(DBG_LEVEL_NORM, "cfs_chown(%s): change from uid:gid %d:%d to %d:%d",
               path, de->uid, de->gid, uid, gid);
        de->uid = uid;
        de->gid = gid;
        //issue a PUT request to update metadata (quick request just to update headers)
        int response = cloudfs_update_meta(de);
      }
    }
    debugf(DBG_LEVEL_NORM, KBLU "exit: cfs_chown(%s,%d,%d)", path, uid, gid);
  }
  return 0;
}

static int cfs_chmod(const char* path, mode_t mode)
{
  if (option_enable_chmod)
  {
    debugf(DBG_LEVEL_NORM, KBLU"cfs_chmod(%s,%d)", path, mode);
    dir_entry* de = check_path_info(path);
    if (de)
    {
      if (de->chmod != mode)
      {
        debugf(DBG_LEVEL_NORM, "cfs_chmod(%s): change mode from %d to %d", path,
               de->chmod, mode);
        de->chmod = mode;
        //todo: issue a PUT request to update metadata (empty request just to update headers?)
        int response = cloudfs_update_meta(de);
      }
    }
    debugf(DBG_LEVEL_NORM, KBLU"exit: cfs_chmod(%s,%d)", path, mode);
  }
  return 0;
}

static int cfs_rename(const char* src, const char* dst)
{
  debugf(DBG_LEVEL_NORM, KBLU"cfs_rename(%s, %s)", src, dst);
  dir_entry* src_de = path_info(src);
  if (!src_de)
  {
    debugf(DBG_LEVEL_NORM, KRED"exit 0: cfs_rename(%s,%s) not-found", src, dst);
    return -ENOENT;
  }
  if (src_de->isdir)
  {
    debugf(DBG_LEVEL_NORM, KRED"exit 1: cfs_rename(%s,%s) cannot rename dirs!",
           src, dst);
    return -EISDIR;
  }
  if (cloudfs_copy_object(src, dst))
  {
    /* FIXME this isn't quite right as doesn't preserve last modified */
    //fix done in cloudfs_copy_object()
    update_dir_cache(dst, src_de->size, 0, 0);
    int result = cfs_unlink(src);
    dir_entry* dst_de = path_info(dst);
    if (!dst_de)
      debugf(DBG_LEVEL_NORM, KRED"cfs_rename(%s,%s) dest-not-found-in-cache", src,
             dst);
    else
    {
      debugf(DBG_LEVEL_NORM, KBLU"cfs_rename(%s,%s) upload ok", src, dst);
      //copy attributes, shortcut, rather than forcing a download from cloud
      copy_dir_entry(src_de, dst_de);
    }
    debugf(DBG_LEVEL_NORM, KBLU"exit 3: cfs_rename(%s,%s)", src, dst);
    return result;
  }
  debugf(DBG_LEVEL_NORM, KRED"exit 4: cfs_rename(%s,%s) io error", src, dst);
  return -EIO;
}

static int cfs_symlink(const char* src, const char* dst)
{
  debugf(DBG_LEVEL_NORM, KBLU"cfs_symlink(%s, %s)", src, dst);
  if (cloudfs_create_symlink(src, dst))
  {
    update_dir_cache(dst, 1, 0, 1);
    debugf(DBG_LEVEL_NORM, KBLU"exit0: cfs_symlink(%s, %s)", src, dst);
    return 0;
  }
  debugf(DBG_LEVEL_NORM, KRED"exit1: cfs_symlink(%s, %s) io error", src, dst);
  return -EIO;
}

static int cfs_readlink(const char* path, char* buf, size_t size)
{
  debugf(DBG_LEVEL_NORM, KBLU"cfs_readlink(%s)", path);
  //fixme: use temp file specified in config
  FILE* temp_file = tmpfile();
  int ret = 0;
  if (!cloudfs_object_write_fp(path, temp_file))
  {
    debugf(DBG_LEVEL_NORM, KRED"exit 1: cfs_readlink(%s) not found", path);
    ret = -ENOENT;
  }
  if (!pread(fileno(temp_file), buf, size, 0))
  {
    debugf(DBG_LEVEL_NORM, KRED"exit 2: cfs_readlink(%s) not found", path);
    ret = -ENOENT;
  }
  fclose(temp_file);
  debugf(DBG_LEVEL_NORM, KBLU"exit 3: cfs_readlink(%s)", path);
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
  debugf(DBG_LEVEL_NORM, KBLU "cfs_utimens(%s)", path);
  // looking for file entry in cache
  dir_entry* path_de = path_info(path);
  if (!path_de)
  {
    debugf(DBG_LEVEL_NORM, KRED"exit 0: cfs_utimens(%s) file not in cache", path);
    return -ENOENT;
  }
  if (path_de->atime.tv_sec != times[0].tv_sec
      || path_de->atime.tv_nsec != times[0].tv_nsec ||
      path_de->mtime.tv_sec != times[1].tv_sec
      || path_de->mtime.tv_nsec != times[1].tv_nsec)
  {
    debugf(DBG_LEVEL_EXT, KCYN
           "cfs_utimens: change %s prev: atime=%li.%li mtime=%li.%li new: atime=%li.%li mtime=%li.%li",
           path,
           path_de->atime.tv_sec, path_de->atime.tv_nsec, path_de->mtime.tv_sec,
           path_de->mtime.tv_nsec,
           times[0].tv_sec, times[0].tv_nsec, times[1].tv_sec, times[1].tv_nsec);
    char time_str[TIME_CHARS] = "";
    get_timespec_as_str(&times[1], time_str, sizeof(time_str));
    debugf(DBG_LEVEL_EXT, KCYN"cfs_utimens: set mtime=[%s]", time_str);
    get_timespec_as_str(&times[0], time_str, sizeof(time_str));
    debugf(DBG_LEVEL_EXT, KCYN"cfs_utimens: set atime=[%s]", time_str);
    path_de->atime = times[0];
    path_de->mtime = times[1];
    // not sure how to best obtain ctime from fuse source file. just record current date.
    clock_gettime(CLOCK_REALTIME, &path_de->ctime);
    //calling a meta cloud update here is not always needed.
    //touch for example opens and closes/flush the file.
    //worth implementing a meta cache functionality to avoid multiple uploads on meta changes
    //when changing timestamps on very large files, touch command will trigger 2 x long and useless file uploads on cfs_flush()
    //cloudfs_update_meta(path_de);
  }
  else
    debugf(DBG_LEVEL_EXT, KCYN"cfs_utimens: a/m/time not changed");
  debugf(DBG_LEVEL_NORM, KBLU "exit 1: cfs_utimens(%s)", path);
  return 0;
}

//todo: would be great if someone implements these 4 extended attributes methods
int cfs_setxattr(const char* path, const char* name, const char* value,
                 size_t size, int flags)
{
  return 0;
}

int cfs_getxattr(const char* path, const char* name, char* value, size_t size)
{
  return 0;
}

int cfs_removexattr(const char* path, const char* name)
{
  return 0;
}

int cfs_listxattr(const char* path, char* list, size_t size)
{
  return 0;
}

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
  .read_ahead = "0"
};

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
      sscanf(arg, " read_ahead = %[^\r\n ]", extra_options.read_ahead)
     )
    return 0;
  if (!strcmp(arg, "-f") || !strcmp(arg, "-d") || !strcmp(arg, "debug"))
    cloudfs_debug(1);
  return 1;
}

//allows memory leaks inspections
void interrupt_handler(int sig)
{
  debugf(DBG_LEVEL_NORM, "Got interrupt signal %d, cleaning memory", sig);
  //TODO: clean memory allocations
  //http://www.cprogramming.com/debugging/valgrind.html
  cloudfs_free();
  //TODO: clear dir cache
  pthread_mutex_destroy(&dcachemut);
  exit(0);
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
    return false;
  }
  return true;
}

int main(int argc, char** argv)
{
  fprintf(stderr, "Starting hubicfuse on homedir %s!\n", get_home_dir());
  signal(SIGINT, interrupt_handler);

  struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
  if (!initialise_options(args))
    return 1;

  fuse_opt_parse(&args, &options, NULL, parse_option);
  cloudfs_init();
  if (debug)
  {
    fprintf(stderr, "verify_ssl = %lu\n", verify_ssl);
    fprintf(stderr, "curl_progress_state = %lu\n", option_curl_progress_state);
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
    fprintf(stderr, "min_speed_limit_progressive = %d\n",
            option_min_speed_limit_progressive);
    fprintf(stderr, "min_speed_timeout = %d\n", option_min_speed_timeout);
    fprintf(stderr, "read_ahead = %d\n", option_read_ahead);
  }
  cloudfs_set_credentials(options.client_id, options.client_secret,
                          options.refresh_token);
  if (!cloudfs_connect())
  {
    fprintf(stderr, "Failed to authenticate.\n");
    return 1;
  }
#ifndef HAVE_OPENSSL
#warning Compiling without libssl, will run single-threaded.
  fuse_opt_add_arg(&args, "-s");
#endif
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
#ifdef HAVE_SETXATTR
    .setxattr = cfs_setxattr,
    .getxattr = cfs_getxattr,
    .listxattr = cfs_listxattr,
    .removexattr = cfs_removexattr,
#endif
  };
  pthread_mutexattr_init(&mutex_attr);
  pthread_mutexattr_settype(&mutex_attr, PTHREAD_MUTEX_RECURSIVE);
  pthread_mutex_init(&dcachemut, &mutex_attr);
  pthread_mutexattr_init(&segment_mutex_attr);
  pthread_mutexattr_settype(&segment_mutex_attr, PTHREAD_MUTEX_ERRORCHECK);
  return fuse_main(args.argc, args.argv, &cfs_oper, &options);
}
