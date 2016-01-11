#ifndef _COMMONFS_H
#define _COMMONFS_H
#include <fuse.h>
#include <pthread.h>
#include <semaphore.h>
#include <assert.h>

typedef enum { false, true } bool;
#define MAX_PATH_SIZE (1024 + 256 + 3)
#define THREAD_NAMELEN 16
#define MAX_URL_SIZE (MAX_PATH_SIZE * 3)
// 64 bit time + nanoseconds
#define TIME_CHARS 32
#define DBG_LEVEL_NORM 0
#define DBG_LEVEL_EXT 1
#define DBG_LEVEL_EXTALL 2
#define INT_CHAR_LEN 16
#define MD5_DIGEST_HEXA_STRING_LEN  (2 * MD5_DIGEST_LENGTH + 1)
#define MAX_SEGMENT_THREADS 5
#define APP_ID "FastHubicFuse_v0_1"

// utimens support
#define HEADER_TEXT_MTIME "X-Object-Meta-Mtime"
#define HEADER_TEXT_ATIME "X-Object-Meta-Atime"
#define HEADER_TEXT_CTIME "X-Object-Meta-Ctime"
#define HEADER_TEXT_MTIME_DISPLAY "X-Object-Meta-Mtime-Display"
#define HEADER_TEXT_ATIME_DISPLAY "X-Object-Meta-Atime-Display"
#define HEADER_TEXT_CTIME_DISPLAY "X-Object-Meta-Ctime-Display"
#define HEADER_TEXT_CHMOD "X-Object-Meta-Chmod"
#define HEADER_TEXT_UID "X-Object-Meta-Uid"
#define HEADER_TEXT_GID "X-Object-Meta-Gid"
#define HEADER_TEXT_FILEPATH "X-Object-Meta-FilePath"
#define HEADER_TEXT_MD5HASH "Etag"
#define HEADER_TEXT_IS_SEGMENTED "X-Object-Meta-Is-Segmented"
#define HEADER_TEXT_PRODUCED_BY "X-Object-Meta-Produced-By"
#define HEADER_TEXT_MANIFEST "X-Object-Manifest"
#define HEADER_TEXT_SEGMENT_SIZE "X-Object-Segment-Size"

//used for storing locally cloud cached files in temp folder
#define TEMP_FILE_NAME_FORMAT "%s/cloudfuse%s"
#define HUBIC_DATE_FORMAT "%Y-%m-%d %T."
//root folder on hubic cloud that will store segments uploaded via this app
//default one in hubic is "default_segments", we keep it separately as safety measure
#define HUBIC_SEGMENT_STORAGE_ROOT "default_fuse_segments"
#define TEMP_SEGMENT_DIR_SUFFIX "_segments"
#define TEMP_SEGMENT_FORMAT "_segments/%d"
#define HTTP_GET "GET"
#define HTTP_PUT "PUT"
#define HTTP_POST "POST"
#define HTTP_DELETE "DELETE"

#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMAG  "\x1B[35m"
#define KCYN  "\x1B[36m"
#define KWHT  "\x1B[37m"

#define min(x, y) ({                \
  typeof(x) _min1 = (x);          \
  typeof(y) _min2 = (y);          \
  (void)(&_min1 == &_min2);      \
  _min1 < _min2 ? _min1 : _min2; })

#define SEM_EMPTY 0
#define SEM_FULL 1
#define SEM_DONE 2

typedef struct
{
  int fd;
  int flags;
} openfile;



typedef struct progressive_data_buf
{
  const char* readptr;
  size_t work_buf_size;
  off_t offset;
  size_t size_processed;
  //bool upload_completed;
  //bool write_completed;
  bool file_is_in_cache;
  int ahead_thread_count;
  pthread_t thread;
  pthread_mutex_t mutex;
  bool mutex_initialised;
  sem_t* sem_list[SEM_DONE + 1];
  char* sem_name_list[SEM_DONE + 1];
  size_t fuse_read_size;
  FILE* local_cache_file;
  size_t fuse_buf_size;
} progressive_data_buf;

//linked list with files in a directory
typedef struct dir_entry
{
  char* name;
  char* full_name;
  char* full_name_hash;//md5 hash for uniqueness purposes (e.g. semaphore unique id)
  char* content_type;
  char* manifest_time;
  char* manifest_seg;
  char* manifest_cloud;
  off_t size;//size of the file, might not match the size in cloud if is segmented
  off_t size_on_cloud;//size of the file in cloud, should be 0 for segmented files
  time_t last_modified;
  // additional attributes
  struct timespec mtime;
  struct timespec ctime;
  struct timespec ctime_local;//cached time used for content change check
  struct timespec atime;
  char* md5sum;//md5sum on cloud
  char* md5sum_local;//md5sum of local cached file/segment
  mode_t chmod;
  uid_t uid;
  gid_t gid;
  bool is_segmented;//-1 for undefined
  struct dir_entry* segments;
  long segment_count;//number of segments for this file
  long segment_full_count;//number of full segments for this file
  long segment_part;//segment number if this represents a segment
  size_t segment_size;
  size_t segment_remaining;
  time_t accessed_in_cache;//todo: cache support based on access time
  bool metadata_downloaded;
  struct progressive_data_buf upload_buf;
  struct progressive_data_buf downld_buf;
  bool is_progressive;
  bool is_single_thread;
  // end change
  int isdir;
  int islink;
  struct dir_entry* next;
} dir_entry;

typedef struct thread_job
{
  dir_entry* de;
  dir_entry* de_seg;
  int segment_part;
  off_t segment_offset;
  //FILE* fp;
  pthread_t thread;
  void* self_reference;
  bool is_single_thread;
} thread_job;

// linked list with cached folder names
typedef struct dir_cache
{
  char* path;
  dir_entry* entries;
  time_t cached;
  //todo: added cache support based on access time
  time_t accessed_in_cache;
  bool was_deleted;
  //end change
  struct dir_cache* next, *prev;
} dir_cache;

time_t my_timegm(struct tm* tm);
time_t get_time_from_str_as_gmt(char* time_str);
time_t get_time_as_local(time_t time_t_val, char time_str[],
                         int char_buf_size);
int get_time_as_string(time_t time_t_val, long nsec, char* time_str,
                       int time_str_len);
time_t get_time_now();
int get_timespec_as_str(const struct timespec* times, char* time_str,
                        int time_str_len);
char* str2md5(const char* str, int length);
int file_md5(FILE* file_handle, char* md5_file_str);
int file_md5_by_name(const char* file_name_str, char* md5_file_str);
void removeSubstr(char* string, char* sub);
void debug_print_descriptor(struct fuse_file_info* info);
bool valid_http_response(int response);
void decode_path(char* path);
void split_path(const char* path, char* seg_base, char* container,
                char* object);
void get_manifest_path(dir_entry* de, char* manifest_path);
int get_safe_cache_file_path(const char* path, char* file_path_safe,
                             char* parent_dir_path_safe, const char* temp_dir,
                             const int segment_part);
int init_semaphores(struct progressive_data_buf* data_buf, dir_entry* de,
                    char* prefix);
int free_semaphores(struct progressive_data_buf* data_buf, int sem_index);
long random_at_most(long max);
dir_entry* init_dir_entry();
void free_de_before_get(dir_entry* de);
void free_de_before_head(dir_entry* de);
void copy_dir_entry(dir_entry* src, dir_entry* dst);
dir_cache* new_cache(const char* path);
void dir_for(const char* path, char* dir);
void debug_print_file_name(FILE* fp);
void debug_list_cache_content();
void update_dir_cache(const char* path, off_t size, int isdir, int islink);
dir_entry* path_info(const char* path);
dir_entry* check_path_info(const char* path);
dir_entry* check_parent_folder_for_file(const char* path);
dir_entry* get_segment(dir_entry* de, int segment_index);
dir_entry* get_create_segment(dir_entry* de, int segment_index);
void dir_decache(const char* path);
void cloudfs_free_dir_list(dir_entry* dir_list);
extern int cloudfs_list_directory(const char* path, dir_entry**);
int caching_list_directory(const char* path, dir_entry** list);
bool open_segment_in_cache(dir_entry* de, dir_entry* de_seg,
                           FILE** fp_segment, const char* method);
bool open_segment_cache_md5(dir_entry* de, dir_entry* de_seg,
                            FILE** fp_segment, const char* method);
bool open_file_in_cache(dir_entry* de, FILE** fp, const char* method);
bool open_file_cache_md5(dir_entry* de, FILE** fp, const char* method);
bool check_segment_cache_md5(dir_entry* de, dir_entry* de_seg, FILE* fp);
void sleep_ms(int milliseconds);
char* get_home_dir();
bool file_changed_time(dir_entry* de);
bool file_changed_md5(dir_entry* de);
int update_direntry_md5sum(char* md5sum_str, FILE* fp);
void interrupt_handler(int sig);
void clear_full_cache();
void print_options();
void debugf(int level, char* fmt, ...);

#endif
