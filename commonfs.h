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
#define DBG_TEST -2
#define DBG_ERR -1
#define DBG_NORM 0
#define DBG_EXT 1
#define DBG_EXTALL 2
#define INT_CHAR_LEN 16
#define MD5_DIGEST_HEXA_STRING_LEN  (2 * MD5_DIGEST_LENGTH + 1)
#define MAX_SEGMENT_THREADS 5
#define MAX_DELETE_THREADS 30
#define MAX_COPY_THREADS 10
#define REQUEST_RETRIES 5
#define BUFFER_READ_SIZE 128 * 1024
#define INTERNET_TIMEOUT_SEC 180
#define OPTION_SIZE 1024

#define FILE_OPEN_MODE_READ 32768
#define FILE_OPEN_MODE_WRITE 32769
#define FILE_OPEN_MODE_READ_EXCL 32770

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
//#define HEADER_TEXT_SEGMENT_SIZE "X-Object-Meta-Segment-Size"
#define HEADER_TEXT_FILE_SIZE "X-Object-Meta-File-Size"
#define HEADER_TEXT_CONTENT_LEN "Content-Length"
#define HEADER_TEXT_CONTENT_TYPE "Content-Type"
#define HEADER_TEXT_CONTAINER_OBJ_COUNT "X-Container-Object-Count"
#define HEADER_COPY_FROM "X-Copy-From"


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
#define MD5SUM_EMPTY_FILE "d41d8cd98f00b204e9800998ecf8427e"

#define KNRM  "\x1B[0m"
//foreground colors
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMAG  "\x1B[35m"
#define KCYN  "\x1B[36m"
#define KWHT  "\x1B[37m"
//background colors
#define KBRED "\x1B[41m"
#define KBGRN "\x1B[42m"
#define KBYEL "\x1B[43m"
#define KBBLU "\x1B[44m"
#define KBMAG "\x1B[45m"
#define KBCYN "\x1B[46m"
#define KBWHT "\x1B[47m"

#define META_NAME 0
#define META_MANIF_ALL 1
#define META_MANIF_SEG 2
#define META_MANIF_TIME 3
#define META_MANIF_CLOUD 4

#define min(x, y) ({                \
  typeof(x) _min1 = (x);          \
  typeof(y) _min2 = (y);          \
  (void)(&_min1 == &_min2);      \
  _min1 < _min2 ? _min1 : _min2; })

#define max(x, y) ({                \
  typeof(x) _max1 = (x);          \
  typeof(y) _max2 = (y);          \
  (void)(&_max1 == &_max2);      \
  _max1 > _max2 ? _max1 : _max2; })

#define SEM_EMPTY 0
#define SEM_FULL 1
#define SEM_DONE 2

#define FUSE_FLAG_O_RDONLY 32768
#define FUSE_FLAG_O_WRONLY 32769
#define LOCK_WAIT_SEC 10

//START bogus declarations to help synthax in Visual Studio
//---------------------------------------------------------
#ifdef _WIN32
typedef int pthread_mutex_t;
typedef int pthread_mutexattr_t;
typedef int pthread_t;
typedef int sem_t;
typedef int mode_t;
typedef int uid_t;
typedef int gid_t;
typedef int MD5_CTX;
typedef int curl_off_t;
#endif // !sem_t
//-------------------------------------------------------
//END bogus declarations to help synthax in Visual Studio

typedef struct
{
  int fd;
  int flags;
} openfile;



typedef struct progressive_data_buf
{
  const char* readptr;
  size_t work_buf_size;
  //off_t offset;
  size_t size_processed;
  //bool upload_completed;
  //bool write_completed;
  bool signaled_completion;
  bool file_is_in_cache;
  int ahead_thread_count;
  pthread_t thread;
  pthread_mutex_t mutex;//for segment uploads
  bool mutex_initialised;
  sem_t* sem_list[SEM_DONE + 1];
  char* sem_name_list[SEM_DONE + 1];
  bool sem_open;
  size_t fuse_read_size;
  FILE* local_cache_file;
  size_t fuse_buf_size;
  bool feed_from_cache;
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
  char* manifest_cloud;//starts with a slash even if on cloud does not
  off_t size;//size of the file, might not match the size in cloud if is segmented
  off_t size_on_cloud;//size of the file in cloud, should be 0 for segmented files
  time_t last_modified;
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
  struct thread_job* job;
  struct thread_job* job2;//needed for multiple md5sum checks
  bool is_progressive;
  bool is_single_thread;
  //some segments uploaded ok are not yet visible in the cloud
  bool has_unvisible_segments;
  //if true segments were not loaded from cloud, size was taken from meta headers
  //used to increase speed, avoid one http call
  bool lazy_segment_load;
  //delay meta load for file in folders with many files, as is very slow
  bool lazy_meta;
  int isdir;
  int islink;
  struct dir_entry* next;
  struct dir_entry* parent;
  //int object_count_recursive;//container object count from swift header
  int object_count;//number of objects in this folder
  int lock_fd;//file descriptor when locking file, used when fuse info is n/a
} dir_entry;

typedef struct thread_job
{
  char* job_name;
  dir_entry* de;
  dir_entry* de_seg;
  int segment_part;
  off_t segment_offset;
  //FILE* fp;
  pthread_t thread;
  bool is_single_thread;
  MD5_CTX mdContext;
  MD5_CTX mdContext_saved;//save interim md5 snapshot to enable restore point
  bool is_mdcontext_saved;
  char* md5str;
} thread_job;

typedef struct thread_copy_job
{
  dir_entry* de_src;
  char* dest;
  char* manifest;
  int result;
  bool thread_exit;
} thread_copy_job;

typedef struct thread_delete_job
{
  dir_entry* de;
  int fd;
} thread_delete_job;

typedef struct thread_clean_segment_job
{
  char* dir_path;
  char* exclude_path;
} thread_clean_segment_job;

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

//for file locking
typedef struct open_file
{
  char* path;
  char* open_flags;
  time_t opened;
  FILE* cached_file;
  int fd;
  char* process_origin;
  char* fuse_operation;
  struct open_file* next;
  pthread_mutex_t mutex;//for segment uploads
} open_file;

char* override_storage_url;
char* public_container;

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
  char enable_syslog[OPTION_SIZE];
  char enable_chaos_test_monkey[OPTION_SIZE];
  char disable_atime_check[OPTION_SIZE];
  char http_log_path[OPTION_SIZE];
  char fast_list_dir_limit[OPTION_SIZE];
  char async_delete[OPTION_SIZE];
} ExtraFuseOptions;




time_t my_timegm(struct tm* tm);
time_t get_time_from_str_as_gmt(char* time_str);
time_t get_time_as_local(time_t time_t_val, char time_str[],
                         int char_buf_size);
int get_time_as_string(time_t time_t_val, long nsec, char* time_str,
                       int time_str_len);
time_t get_time_now();
int get_timespec_as_str(const struct timespec* times, char* time_str,
                        int time_str_len);
void update_cache_access(dir_entry* de);
char* str2md5(const char* str, int length);
int file_md5(FILE* file_handle, char* md5_file_str);
int file_md5_by_name(const char* file_name_str, char* md5_file_str);
bool init_job_md5(thread_job* job);
bool update_job_md5(thread_job* job, const unsigned char* data_buf,
                    int buf_len);
void save_job_md5(thread_job* job);
void restore_job_md5(thread_job* job);
bool complete_job_md5(thread_job* job);
void removeSubstr(char* string, char* sub);
void debug_print_descriptor(struct fuse_file_info* info);
bool valid_http_response(int response);
void decode_path(char* path);
void split_path(const char* path, char* seg_base, char* container,
                char* object);
void get_segment_manifest(char* manifest_seg, dir_entry* de, int seg_index);
void get_manifest_path(dir_entry* de, char* manifest_path);
int get_safe_cache_file_path(const char* path, char* file_path_safe,
                             char* parent_dir_path_safe, const char* temp_dir,
                             const int segment_part);
void unblock_semaphore(struct progressive_data_buf* data_buf, int sem_index);
int init_semaphores(struct progressive_data_buf* data_buf, dir_entry* de,
                    char* prefix);
void free_semaphores(struct progressive_data_buf* data_buf, int sem_index);
void free_all_semaphores(struct progressive_data_buf* data_buf);
void unblock_close_all_semaphores(struct progressive_data_buf* data_buf);
bool is_semaphore_open(struct progressive_data_buf* data_buf);
long random_at_most(long max);
void init_entry_lazy(dir_entry* de);
dir_entry* init_dir_entry();
void free_de_before_get(dir_entry* de);
void free_de_before_head(dir_entry* de);
thread_copy_job* init_thread_copy_job();
void free_thread_copy_job(thread_copy_job* job);
thread_job* init_thread_job(char* job_name);
void free_thread_job(thread_job* job);
void create_dir_entry(dir_entry* de, const char* path);// , mode_t mode);
void copy_dir_entry(dir_entry* src, dir_entry* dst, bool copy_manifests);
dir_cache* new_cache(const char* path);
void dir_for(const char* path, char* dir);
void debug_print_file_name(FILE* fp);
void debug_list_cache_content();
void update_dir_cache(const char* path, off_t size, int isdir, int islink);
void update_dir_cache_upload(const char* path, off_t size, int isdir,
                             int islink);
dir_entry* path_info(const char* path);
bool append_dir_entry(dir_entry* de);
//dir_entry* replace_cache_object(const dir_entry* de, dir_entry* de_new);
dir_entry* check_path_info(const char* path);
dir_entry* check_path_info_upload(const char* path);
dir_entry* check_parent_folder_for_file(const char* path);
void flags_to_openmode(unsigned int flags, char* openmode);
int get_open_locks();
dir_entry* get_segment(dir_entry* de, int segment_index);
void create_segment_meta(dir_entry* de_seg, int seg_index, dir_entry* de);
void create_manifest_meta(dir_entry* de);
void create_entry_meta(const char* path, dir_entry* de);
dir_entry* get_create_segment(dir_entry* de, int segment_index);
void dir_decache_segments(dir_entry* de);
void dir_decache(const char* path);
void dir_decache_upload(const char* path);
void cloudfs_free_dir_list(dir_entry* dir_list);
extern int cloudfs_list_directory(const char* path, dir_entry**);
int caching_list_directory(const char* path, dir_entry** list);
bool delete_segment_cache(dir_entry* de, dir_entry* de_seg);
bool open_segment_in_cache(dir_entry* de, dir_entry* de_seg,
                           FILE** fp_segment, const char* method);
bool open_segment_cache_md5(dir_entry* de, dir_entry* de_seg,
                            FILE** fp_segment, const char* method);
bool open_file_in_cache(dir_entry* de, FILE** fp, const char* method);
bool open_file_cache_md5(dir_entry* de, FILE** fp, const char* method);
bool check_segment_cache_md5(dir_entry* de, dir_entry* de_seg, FILE* fp);
//bool cleanup_older_segments(char* dir_path, char* exclude_path);
void cleanup_older_segments_th(char* dir_path, char* exclude_path);
void unlink_cache_segments(dir_entry* de);
void sleep_ms(int milliseconds);
off_t get_file_size(FILE* fp);
void close_file(FILE** file);
int file_is_readable(const char* fname);
char* get_home_dir();
bool file_changed_time(dir_entry* de);
bool file_changed_md5(dir_entry* de);
int update_direntry_md5sum(char* md5sum_str, FILE* fp);
bool close_lock_file(const char* path, int fd);
int open_lock_file(const char* path, unsigned int flags, char* fuse_op);
bool update_lock_file(const char* path, int fd, const char* search_flag,
                      const char* new_flag);
void interrupt_handler(int sig);
void sigpipe_callback_handler(int signum);
void clear_full_cache();
void print_options();
bool initialise_options(struct fuse_args args);
int parse_option(void* data, const char* arg, int key,
                 struct fuse_args* outargs);
void set_global_thread_debug(char* operation, const char* path, bool log);
void debug_http(const char* method, const char* url);
void debugf(int level, char* fmt, ...);

#endif
