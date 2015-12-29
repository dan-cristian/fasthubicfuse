#ifndef _CLOUDFSAPI_H
#define _CLOUDFSAPI_H
#include <curl/curl.h>
#include <curl/easy.h>
#include <fuse.h>
#include <time.h>
#include "commonfs.h"

#define BUFFER_INITIAL_SIZE 4096
#define MAX_HEADER_SIZE 8192
#define USER_AGENT "CloudFuse"
#define OPTION_SIZE 1024
#define MINIMAL_PROGRESS_FUNCTIONALITY_INTERVAL 5

typedef struct curl_slist curl_slist;

struct curl_progress
{
  double lastruntime;
  CURL* curl;
};

typedef struct options
{
  char cache_timeout[OPTION_SIZE];
  char verify_ssl[OPTION_SIZE];
  char segment_size[OPTION_SIZE];
  char segment_above[OPTION_SIZE];
  char storage_url[OPTION_SIZE];
  char container[OPTION_SIZE];
  char temp_dir[OPTION_SIZE];
  char client_id[OPTION_SIZE];
  char client_secret[OPTION_SIZE];
  char refresh_token[OPTION_SIZE];
} FuseOptions;

typedef struct extra_options
{
  char get_extended_metadata[OPTION_SIZE];
  char curl_verbose[OPTION_SIZE];
  char cache_statfs_timeout[OPTION_SIZE];
  char debug_level[OPTION_SIZE];
  char curl_progress_state[OPTION_SIZE];
  char enable_chmod[OPTION_SIZE];
  char enable_chown[OPTION_SIZE];
  char enable_progressive_upload[OPTION_SIZE];
  char enable_progressive_download[OPTION_SIZE];
  char min_speed_limit_progressive[OPTION_SIZE];
  char min_speed_timeout[OPTION_SIZE];
  char read_ahead[OPTION_SIZE];
} ExtraFuseOptions;

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

char* override_storage_url;
char* public_container;

int file_is_readable(const char* fname);
const char* get_file_mimetype (const char* filename);

int cloudfs_object_read_fp(dir_entry* de, FILE* fp);
int cloudfs_object_write_fp(dir_entry* de, FILE* fp);
int cloudfs_list_directory(const char* path, dir_entry**);
int cloudfs_delete_object(dir_entry* de);
int cloudfs_copy_object(dir_entry* de, const char* dst);
int cloudfs_create_symlink(dir_entry* de, const char* dst);
int cloudfs_create_directory(const char* label);
int cloudfs_object_truncate(dir_entry* de, off_t size);
off_t cloudfs_file_size(int fd);
int cloudfs_statfs(const char* path, struct statvfs* stat);
void cloudfs_verify_ssl(int dbg);
void cloudfs_option_get_extended_metadata(int option);
void cloudfs_option_curl_verbose(int option);
void get_file_metadata(dir_entry* de);
int cloudfs_update_meta(dir_entry* de);
int cloudfs_object_upload_progressive(dir_entry* de);
void* cloudfs_object_downld_progressive(void* path);
int download_ahead_segment(dir_entry* de_seg, dir_entry* de, FILE* fp,
                           bool sync_first);
int cloudfs_download_segment(dir_entry* de_seg, dir_entry* de, FILE* fp,
                             size_t size);
int cloudfs_upload_segment(dir_entry* de_seg, dir_entry* de);
bool cloudfs_create_segment(dir_entry* de_seg, dir_entry* de);
#endif
