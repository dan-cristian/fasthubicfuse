#ifndef _CLOUDFSAPI_H
#define _CLOUDFSAPI_H
#ifndef _WIN32
#include <curl/curl.h>
#include <curl/easy.h>
#include <fuse.h>
#endif
#include <time.h>
#include "commonfs.h"

#define BUFFER_INITIAL_SIZE 4096
#define MAX_HEADER_SIZE 8192
#define USER_AGENT "CloudFuse"

#define MINIMAL_PROGRESS_FUNCTIONALITY_INTERVAL 5

typedef struct curl_slist curl_slist;

struct curl_progress
{
  double lastruntime;
  CURL* curl;
  char method;
  int tries;
  int response;
  dir_entry* de;
  bool donotstop;
  curl_off_t last_ulnow;
  curl_off_t last_dlnow;
  double last_ultime;
  double last_dltime;
};



void cloudfs_init(void);
void cloudfs_free(void);
void cloudfs_set_credentials(char* client_id, char* client_secret,
                             char* refresh_token);
int cloudfs_connect(void);

struct segment_info
{
  FILE* fp;
  int part;
  long size_left;
  long size_copy;
  long size_processed;
  long segment_size;
  char* seg_base;
  const char* method;
  struct dir_entry* de;
  struct dir_entry* de_seg;
};

extern long segment_size;//segment file size
extern long segment_above;//max size of a file before being segmented



void int_convert_first_segment_th(dir_entry* de);
bool int_cfs_write_cache_data_feed(dir_entry* de);
const char* get_file_mimetype (const char* filename);
int cloudfs_list_directory(const char* path, dir_entry**);
bool cloudfs_delete_object(dir_entry* de);
void cloudfs_delete_object_unlink_async(dir_entry* de, int fd);
bool cloudfs_delete_path(char* path, bool is_dir, bool is_segmented,
                         dir_entry* de);
bool cloudfs_create_object(dir_entry* de);
bool cloudfs_copy_object(dir_entry* de, const char* dst, bool file_only);
int cloudfs_create_symlink(const char* src, const char* dst);
bool cloudfs_create_directory(const char* path);
int cloudfs_object_truncate(dir_entry* de, off_t size);
off_t cloudfs_file_size(int fd);
int cloudfs_statfs(const char* path, struct statvfs* stat);
bool get_file_metadata(dir_entry* de, bool force_segment_update,
                       bool force_meta);
bool cloudfs_update_meta(dir_entry* de, bool sync);
//int cloudfs_object_upload_progressive(dir_entry* de, dir_entry* de_seg);
//void* cloudfs_object_downld_progressive(void* path);
int download_ahead_segment(dir_entry* de_seg, dir_entry* de, FILE* fp,
                           bool sync_first);
int cloudfs_download_segment(dir_entry* de_seg, dir_entry* de, FILE* fp,
                             size_t size);
//int cloudfs_upload_segment(dir_entry* de_seg, dir_entry* de);
bool cloudfs_create_segment(dir_entry* de_seg, dir_entry* de);

#endif
