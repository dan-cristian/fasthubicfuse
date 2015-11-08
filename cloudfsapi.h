#ifndef _CLOUDFSAPI_H
#define _CLOUDFSAPI_H

#include <curl/curl.h>
#include <curl/easy.h>
#include <fuse.h>
#include <pthread.h>
#include <time.h>

#define BUFFER_INITIAL_SIZE 4096
#define MAX_HEADER_SIZE 8192
#define MAX_PATH_SIZE (1024 + 256 + 3)
#define MAX_URL_SIZE (MAX_PATH_SIZE * 3)
#define USER_AGENT "CloudFuse"
#define OPTION_SIZE 1024

// utimens support
#define HEADER_TEXT_MTIME "X-Object-Meta-Mtime"
#define HEADER_TEXT_ATIME "X-Object-Meta-Atime"
#define HEADER_TEXT_CTIME "X-Object-Meta-Ctime"
#define HEADER_TEXT_FILEPATH "X-Object-Meta-FilePath"

typedef struct curl_slist curl_slist;

typedef struct dir_entry
{
  char *name;
  char *full_name;
  char *content_type;
  off_t size;
  time_t last_modified;
  // implement utimens
  struct timespec mtime;
  struct timespec ctime;
  struct timespec atime;
  int isdir;
  int islink;
  struct dir_entry *next;
} dir_entry;

typedef struct options {
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


extern int cache_timeout;
typedef struct dir_cache
{
  char *path;
  dir_entry *entries;
  time_t cached;
  struct dir_cache *next, *prev;
} dir_cache;
extern dir_cache *dcache;


void cloudfs_init(void);
void cloudfs_set_credentials(char *client_id, char *client_secret, char *refresh_token);
int cloudfs_connect(void);

struct segment_info
{
    FILE *fp;
    int part;
    long size;
    long segment_size;
    char *seg_base;
    const char *method;
};

long segment_size;
long segment_above;

char *override_storage_url;
char *public_container;

int file_is_readable(const char *fname);
const char * get_file_mimetype ( const char *filename );

int cloudfs_object_read_fp(const char *path, FILE *fp);
int cloudfs_object_write_fp(const char *path, FILE *fp);
int cloudfs_list_directory(const char *path, dir_entry **);
int cloudfs_delete_object(const char *path);
int cloudfs_copy_object(const char *src, const char *dst);
int cloudfs_create_symlink(const char *src, const char *dst);
int cloudfs_create_directory(const char *label);
int cloudfs_object_truncate(const char *path, off_t size);
off_t cloudfs_file_size(int fd);
void cloudfs_debug(int dbg);
void cloudfs_verify_ssl(int dbg);
void cloudfs_free_dir_list(dir_entry *dir_list);
int cloudfs_statfs(const char *path, struct statvfs *stat);

void debugf(char *fmt, ...);
#endif
