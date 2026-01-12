#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/statvfs.h>
#include <unistd.h>
#include <time.h>
#include <json-c/json.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/md5.h>
#include "file_handler.h"
#include "database.h"
#include "auth_handler.h"
#include "../common/protocol.h"

#define STORAGE_BASE_PATH "/home/phuctran23/Laptrinhmang-BTL/file_share_app/storage"
#define CHUNK_SIZE 524288  // 512KB - optimal for large files
#define MAX_SESSIONS 100
#define MAX_FILE_SIZE 10737418240LL  // 10GB limit
#define SESSION_TIMEOUT 3600  // 1 hour timeout for inactive sessions
#define OPENSSL_API_COMPAT 30000

// Upload session tracking
typedef struct {
    int upload_id;
    int user_id;
    int group_id;
    char file_name[256];
    char file_path[512];
    char temp_path[512];
    long long total_size;
    long long received_size;
    FILE *fp;
    int active;
    time_t last_activity;
    MD5_CTX md5_context;
    unsigned char md5_digest[MD5_DIGEST_LENGTH];
} UploadSession;

// Download session tracking
typedef struct {
    int download_id;
    int user_id;
    int file_id;
    char file_path[512];
    long long total_size;
    long long sent_size;
    FILE *fp;
    int active;
    time_t last_activity;
    MD5_CTX md5_context;
    unsigned char md5_digest[MD5_DIGEST_LENGTH];
} DownloadSession;

static UploadSession uploads[MAX_SESSIONS];
static DownloadSession downloads[MAX_SESSIONS];
static int next_upload_id = 1;
static int next_download_id = 1;

// Check available disk space
static int check_disk_space(const char *path, long long required_size) {
    struct statvfs stat;
    if (statvfs(path, &stat) != 0) {
        return 0;
    }
    long long available = (long long)stat.f_bavail * stat.f_frsize;
    return available >= required_size;
}

// Convert MD5 digest to hex string
static void md5_to_hex(unsigned char *digest, char *output) {
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", digest[i]);
    }
    output[MD5_DIGEST_LENGTH * 2] = '\0';
}

// Cleanup expired sessions
static void cleanup_expired_sessions() {
    time_t now = time(NULL);
    
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (uploads[i].active && (now - uploads[i].last_activity) > SESSION_TIMEOUT) {
            if (uploads[i].fp) {
                fclose(uploads[i].fp);
            }
            unlink(uploads[i].temp_path);
            uploads[i].active = 0;
        }
        
        if (downloads[i].active && (now - downloads[i].last_activity) > SESSION_TIMEOUT) {
            if (downloads[i].fp) {
                fclose(downloads[i].fp);
            }
            downloads[i].active = 0;
        }
    }
}

// Base64 decode function
static unsigned char* base64_decode(const char *input, size_t *output_length) {
    BIO *bio, *b64;
    size_t input_len = strlen(input);
    unsigned char *buffer = (unsigned char*)malloc(input_len);
    
    bio = BIO_new_mem_buf(input, input_len);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    
    *output_length = BIO_read(bio, buffer, input_len);
    BIO_free_all(bio);
    
    return buffer;
}

// Base64 encode function
static char* base64_encode(const unsigned char *input, size_t length) {
    BIO *bio, *b64;
    BUF_MEM *buffer_ptr;
    
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, input, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &buffer_ptr);
    
    char *output = (char*)malloc(buffer_ptr->length + 1);
    memcpy(output, buffer_ptr->data, buffer_ptr->length);
    output[buffer_ptr->length] = '\0';
    
    BIO_free_all(bio);
    
    return output;
}

void handle_upload_file_start(int sock, struct json_object *request) {
    struct json_object *data_obj, *token_obj, *group_id_obj, *file_name_obj;
    struct json_object *file_path_obj, *file_size_obj;
    
    // Extract data field
    if (!json_object_object_get_ex(request, "data", &data_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing data field");
        return;
    }
    
    // Extract session_token
    if (!json_object_object_get_ex(data_obj, "session_token", &token_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing session_token");
        return;
    }
    const char *session_token = json_object_get_string(token_obj);
    
    // Verify session
    UserInfo *user = db_verify_session(session_token);
    if (!user) {
        send_error_response(sock, STATUS_UNAUTHORIZED, "ERROR_INVALID_SESSION", "Invalid or expired session");
        return;
    }
    
    // Parse request data
    if (!json_object_object_get_ex(data_obj, "group_id", &group_id_obj) ||
        !json_object_object_get_ex(data_obj, "file_name", &file_name_obj) ||
        !json_object_object_get_ex(data_obj, "file_path", &file_path_obj) ||
        !json_object_object_get_ex(data_obj, "file_size", &file_size_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing required fields");
        free(user);
        return;
    }
    
    int group_id = json_object_get_int(group_id_obj);
    const char *file_name = json_object_get_string(file_name_obj);
    const char *file_path = json_object_get_string(file_path_obj);
    long long file_size = json_object_get_int64(file_size_obj);
    
    // Validate file size
    if (file_size <= 0) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_FILE_SIZE", "File size must be greater than 0");
        free(user);
        return;
    }
    
    if (file_size > MAX_FILE_SIZE) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_FILE_TOO_LARGE", "File size exceeds maximum allowed size (10GB)");
        free(user);
        return;
    }
    
    // Check available disk space (require 10% extra space)
    long long required_space = file_size + (file_size / 10);
    if (!check_disk_space(STORAGE_BASE_PATH, required_space)) {
        send_error_response(sock, STATUS_INTERNAL_ERROR, "ERROR_INSUFFICIENT_DISK_SPACE", "Insufficient disk space for upload");
        free(user);
        return;
    }
    
    // Check group membership
    if (!db_is_group_member(user->user_id, group_id)) {
        send_error_response(sock, STATUS_FORBIDDEN, "ERROR_NOT_GROUP_MEMBER", "You are not a member of this group");
        free(user);
        return;
    }
    
    // Allow any group member to upload; admins are implicitly allowed
    int is_admin = db_is_group_admin(user->user_id, group_id);
    (void)is_admin; // kept for future policy tweaks
    
    // Cleanup expired sessions
    cleanup_expired_sessions();
    
    // Find free upload slot
    int slot = -1;
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!uploads[i].active) {
            slot = i;
            break;
        }
    }
    
    if (slot == -1) {
        send_error_response(sock, STATUS_INTERNAL_ERROR, "ERROR_TOO_MANY_UPLOADS", "Too many concurrent uploads");
        free(user);
        return;
    }
    
    // Create temporary file for upload
    char temp_path[512];
    sprintf(temp_path, "%s/temp_upload_%d", STORAGE_BASE_PATH, next_upload_id);
    
    FILE *fp = fopen(temp_path, "wb");
    if (!fp) {
        send_error_response(sock, STATUS_INTERNAL_ERROR, "ERROR_CREATE_TEMP_FILE", "Failed to create temporary file");
        free(user);
        return;
    }
    
    // Initialize upload session
    uploads[slot].upload_id = next_upload_id;
    uploads[slot].user_id = user->user_id;
    uploads[slot].group_id = group_id;
    strncpy(uploads[slot].file_name, file_name, 255);
    strncpy(uploads[slot].file_path, file_path, 511);
    strcpy(uploads[slot].temp_path, temp_path);
    uploads[slot].total_size = file_size;
    uploads[slot].received_size = 0;
    uploads[slot].fp = fp;
    uploads[slot].active = 1;
    uploads[slot].last_activity = time(NULL);
    MD5_Init(&uploads[slot].md5_context);
    
    // Create response
    struct json_object *response = json_object_new_object();
    json_object_object_add(response, "status", json_object_new_int(STATUS_OK));
    json_object_object_add(response, "code", json_object_new_string("SUCCESS_UPLOAD_START"));
    json_object_object_add(response, "message", json_object_new_string("Upload started successfully"));
    
    struct json_object *payload = json_object_new_object();
    json_object_object_add(payload, "upload_id", json_object_new_int(next_upload_id));
    json_object_object_add(payload, "chunk_size", json_object_new_int(CHUNK_SIZE));
    json_object_object_add(response, "payload", payload);
    
    const char *response_str = json_object_to_json_string(response);
    send(sock, response_str, strlen(response_str), 0);
    json_object_put(response);
    
    free(user);
    next_upload_id++;
}

void handle_upload_file_chunk(int sock, struct json_object *request) {
    struct json_object *data_obj, *token_obj, *upload_id_obj, *chunk_data_obj, *chunk_index_obj;
    
    // Extract data field
    if (!json_object_object_get_ex(request, "data", &data_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing data field");
        return;
    }
    
    // Extract session_token
    if (!json_object_object_get_ex(data_obj, "session_token", &token_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing session_token");
        return;
    }
    const char *session_token = json_object_get_string(token_obj);
    
    // Verify session
    UserInfo *user = db_verify_session(session_token);
    if (!user) {
        send_error_response(sock, STATUS_UNAUTHORIZED, "ERROR_INVALID_SESSION", "Invalid or expired session");
        return;
    }
    
    // Parse request data
    if (!json_object_object_get_ex(data_obj, "upload_id", &upload_id_obj) ||
        !json_object_object_get_ex(data_obj, "chunk_data", &chunk_data_obj) ||
        !json_object_object_get_ex(data_obj, "chunk_index", &chunk_index_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing required fields");
        free(user);
        return;
    }
    
    int upload_id = json_object_get_int(upload_id_obj);
    const char *chunk_data_b64 = json_object_get_string(chunk_data_obj);
    int chunk_index = json_object_get_int(chunk_index_obj);
    
    // Find upload session
    int slot = -1;
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (uploads[i].active && uploads[i].upload_id == upload_id) {
            slot = i;
            break;
        }
    }
    
    if (slot == -1) {
        send_error_response(sock, STATUS_NOT_FOUND, "ERROR_UPLOAD_NOT_FOUND", "Upload session not found");
        free(user);
        return;
    }
    
    if (uploads[slot].user_id != user->user_id) {
        send_error_response(sock, STATUS_FORBIDDEN, "ERROR_NOT_YOUR_UPLOAD", "This upload session belongs to another user");
        free(user);
        return;
    }
    
    // Decode base64 chunk
    size_t decoded_length;
    unsigned char *decoded_data = base64_decode(chunk_data_b64, &decoded_length);
    
    // Write chunk to file
    size_t written = fwrite(decoded_data, 1, decoded_length, uploads[slot].fp);
    
    // Update MD5 checksum
    MD5_Update(&uploads[slot].md5_context, decoded_data, decoded_length);
    
    free(decoded_data);
    
    if (written != decoded_length) {
        fclose(uploads[slot].fp);
        unlink(uploads[slot].temp_path);
        uploads[slot].active = 0;
        send_error_response(sock, STATUS_INTERNAL_ERROR, "ERROR_WRITE_CHUNK", "Failed to write chunk");
        free(user);
        return;
    }
    
    uploads[slot].received_size += decoded_length;
    uploads[slot].last_activity = time(NULL);
    
    // Create response
    struct json_object *response = json_object_new_object();
    json_object_object_add(response, "status", json_object_new_int(STATUS_OK));
    json_object_object_add(response, "code", json_object_new_string("SUCCESS_UPLOAD_CHUNK"));
    json_object_object_add(response, "message", json_object_new_string("Chunk received successfully"));
    
    struct json_object *payload = json_object_new_object();
    json_object_object_add(payload, "chunk_index", json_object_new_int(chunk_index));
    json_object_object_add(payload, "received_size", json_object_new_int64(uploads[slot].received_size));
    json_object_object_add(payload, "total_size", json_object_new_int64(uploads[slot].total_size));
    json_object_object_add(response, "payload", payload);
    
    const char *response_str = json_object_to_json_string(response);
    send(sock, response_str, strlen(response_str), 0);
    json_object_put(response);
    
    free(user);
}

void handle_upload_file_complete(int sock, struct json_object *request) {
    struct json_object *data_obj, *token_obj, *upload_id_obj;
    
    // Extract data field
    if (!json_object_object_get_ex(request, "data", &data_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing data field");
        return;
    }
    
    // Extract session_token
    if (!json_object_object_get_ex(data_obj, "session_token", &token_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing session_token");
        return;
    }
    const char *session_token = json_object_get_string(token_obj);
    
    // Verify session
    UserInfo *user = db_verify_session(session_token);
    if (!user) {
        send_error_response(sock, STATUS_UNAUTHORIZED, "ERROR_INVALID_SESSION", "Invalid or expired session");
        return;
    }
    
    // Parse request data
    if (!json_object_object_get_ex(data_obj, "upload_id", &upload_id_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing upload_id");
        free(user);
        return;
    }
    
    int upload_id = json_object_get_int(upload_id_obj);
    
    // Find upload session
    int slot = -1;
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (uploads[i].active && uploads[i].upload_id == upload_id) {
            slot = i;
            break;
        }
    }
    
    if (slot == -1) {
        send_error_response(sock, STATUS_NOT_FOUND, "ERROR_UPLOAD_NOT_FOUND", "Upload session not found");
        free(user);
        return;
    }
    
    if (uploads[slot].user_id != user->user_id) {
        send_error_response(sock, STATUS_FORBIDDEN, "ERROR_NOT_YOUR_UPLOAD", "This upload session belongs to another user");
        free(user);
        return;
    }
    
    // Finalize MD5 checksum
    MD5_Final(uploads[slot].md5_digest, &uploads[slot].md5_context);
    char md5_hex[MD5_DIGEST_LENGTH * 2 + 1];
    md5_to_hex(uploads[slot].md5_digest, md5_hex);
    
    // Close temporary file
    fclose(uploads[slot].fp);
    uploads[slot].fp = NULL;
    
    // Build final file path
    char final_path[1024];
    sprintf(final_path, "%s/group_%d%s", STORAGE_BASE_PATH, uploads[slot].group_id, uploads[slot].file_path);
    
    // Create directory if needed
    char dir_path[1024];
    strcpy(dir_path, final_path);
    char *last_slash = strrchr(dir_path, '/');
    if (last_slash) {
        *last_slash = '\0';
        char mkdir_cmd[2048];
        sprintf(mkdir_cmd, "mkdir -p '%s'", dir_path);
        system(mkdir_cmd);
    }
    
    // Move temp file to final location
    if (rename(uploads[slot].temp_path, final_path) != 0) {
        uploads[slot].active = 0;
        send_error_response(sock, STATUS_INTERNAL_ERROR, "ERROR_MOVE_FILE", "Failed to move uploaded file");
        free(user);
        return;
    }
    
    // Get parent directory
    char parent_dir[512] = "/";
    strcpy(dir_path, uploads[slot].file_path);
    last_slash = strrchr(dir_path, '/');
    if (last_slash && last_slash != dir_path) {
        *last_slash = '\0';
        strcpy(parent_dir, dir_path);
    }
    
    // Create file record in database
    int file_id = db_create_file(
        uploads[slot].group_id,
        uploads[slot].file_name,
        uploads[slot].file_path,
        uploads[slot].received_size,
        "",
        parent_dir,
        user->user_id
    );
    
    if (file_id <= 0) {
        unlink(final_path);
        uploads[slot].active = 0;
        send_error_response(sock, STATUS_INTERNAL_ERROR, "ERROR_CREATE_FILE_RECORD", "Failed to create file record");
        free(user);
        return;
    }
    
    // Save upload info for response
    char file_name[256];
    long long file_size = uploads[slot].received_size;
    strncpy(file_name, uploads[slot].file_name, 255);
    
    // Clear upload session
    uploads[slot].active = 0;
    
    // Create response
    struct json_object *response = json_object_new_object();
    json_object_object_add(response, "status", json_object_new_int(STATUS_OK));
    json_object_object_add(response, "code", json_object_new_string("SUCCESS_UPLOAD_COMPLETE"));
    json_object_object_add(response, "message", json_object_new_string("File uploaded successfully"));
    
    struct json_object *payload = json_object_new_object();
    json_object_object_add(payload, "file_id", json_object_new_int(file_id));
    json_object_object_add(payload, "file_name", json_object_new_string(file_name));
    json_object_object_add(payload, "file_size", json_object_new_int64(file_size));
    json_object_object_add(payload, "md5_checksum", json_object_new_string(md5_hex));
    json_object_object_add(response, "payload", payload);
    
    const char *response_str = json_object_to_json_string(response);
    send(sock, response_str, strlen(response_str), 0);
    json_object_put(response);
    
    free(user);
}

void handle_download_file_start(int sock, struct json_object *request) {
    struct json_object *data_obj, *token_obj, *file_id_obj;
    
    // Extract data field
    if (!json_object_object_get_ex(request, "data", &data_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing data field");
        return;
    }
    
    // Extract session_token
    if (!json_object_object_get_ex(data_obj, "session_token", &token_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing session_token");
        return;
    }
    const char *session_token = json_object_get_string(token_obj);
    
    // Verify session
    UserInfo *user = db_verify_session(session_token);
    if (!user) {
        send_error_response(sock, STATUS_UNAUTHORIZED, "ERROR_INVALID_SESSION", "Invalid or expired session");
        return;
    }
    
    // Parse request data
    if (!json_object_object_get_ex(data_obj, "file_id", &file_id_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing file_id");
        free(user);
        return;
    }
    
    int file_id = json_object_get_int(file_id_obj);
    
    // Get file info
    FileInfo *file = db_get_file_by_id(file_id);
    if (!file) {
        send_error_response(sock, STATUS_NOT_FOUND, "ERROR_FILE_NOT_FOUND", "File not found");
        free(user);
        return;
    }
    
    // Check group membership
    if (!db_is_group_member(user->user_id, file->group_id)) {
        free(file);
        send_error_response(sock, STATUS_FORBIDDEN, "ERROR_NOT_GROUP_MEMBER", "You are not a member of this group");
        free(user);
        return;
    }
    
    // Check read permission
    PermissionInfo *perm = db_get_permissions(user->user_id, file->group_id);
    if (!perm || !perm->can_read) {
        if (perm) free(perm);
        free(file);
        send_error_response(sock, STATUS_FORBIDDEN, "ERROR_NO_PERMISSION", "You don't have read permission");
        free(user);
        return;
    }
    free(perm);
    
    // Cleanup expired sessions
    cleanup_expired_sessions();
    
    // Build physical file path
    char physical_path[1024];
    sprintf(physical_path, "%s/group_%d%s", STORAGE_BASE_PATH, file->group_id, file->file_path);
    
    // Open file
    FILE *fp = fopen(physical_path, "rb");
    if (!fp) {
        free(file);
        send_error_response(sock, STATUS_INTERNAL_ERROR, "ERROR_OPEN_FILE", "Failed to open file");
        free(user);
        return;
    }
    
    // Find free download slot
    int slot = -1;
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!downloads[i].active) {
            slot = i;
            break;
        }
    }
    
    if (slot == -1) {
        fclose(fp);
        free(file);
        send_error_response(sock, STATUS_INTERNAL_ERROR, "ERROR_TOO_MANY_DOWNLOADS", "Too many concurrent downloads");
        free(user);
        return;
    }
    
    // Initialize download session
    downloads[slot].download_id = next_download_id;
    downloads[slot].user_id = user->user_id;
    downloads[slot].file_id = file_id;
    strncpy(downloads[slot].file_path, file->file_path, 511);
    downloads[slot].total_size = file->file_size;
    downloads[slot].sent_size = 0;
    downloads[slot].fp = fp;
    downloads[slot].active = 1;
    downloads[slot].last_activity = time(NULL);
    MD5_Init(&downloads[slot].md5_context);
    
    // Create response
    struct json_object *response = json_object_new_object();
    json_object_object_add(response, "status", json_object_new_int(STATUS_OK));
    json_object_object_add(response, "code", json_object_new_string("SUCCESS_DOWNLOAD_START"));
    json_object_object_add(response, "message", json_object_new_string("Download started successfully"));
    
    struct json_object *payload = json_object_new_object();
    json_object_object_add(payload, "download_id", json_object_new_int(next_download_id));
    json_object_object_add(payload, "file_name", json_object_new_string(file->file_name));
    json_object_object_add(payload, "file_size", json_object_new_int64(file->file_size));
    json_object_object_add(payload, "chunk_size", json_object_new_int(CHUNK_SIZE));
    json_object_object_add(response, "payload", payload);
    
    const char *response_str = json_object_to_json_string(response);
    send(sock, response_str, strlen(response_str), 0);
    json_object_put(response);
    
    free(file);
    free(user);
    next_download_id++;
}

void handle_download_file_chunk(int sock, struct json_object *request) {
    struct json_object *data_obj, *token_obj, *download_id_obj, *chunk_index_obj;
    
    // Extract data field
    if (!json_object_object_get_ex(request, "data", &data_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing data field");
        return;
    }
    
    // Extract session_token
    if (!json_object_object_get_ex(data_obj, "session_token", &token_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing session_token");
        return;
    }
    const char *session_token = json_object_get_string(token_obj);
    
    // Verify session
    UserInfo *user = db_verify_session(session_token);
    if (!user) {
        send_error_response(sock, STATUS_UNAUTHORIZED, "ERROR_INVALID_SESSION", "Invalid or expired session");
        return;
    }
    
    // Parse request data
    if (!json_object_object_get_ex(data_obj, "download_id", &download_id_obj) ||
        !json_object_object_get_ex(data_obj, "chunk_index", &chunk_index_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing required fields");
        free(user);
        return;
    }
    
    int download_id = json_object_get_int(download_id_obj);
    int chunk_index = json_object_get_int(chunk_index_obj);
    
    // Find download session
    int slot = -1;
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (downloads[i].active && downloads[i].download_id == download_id) {
            slot = i;
            break;
        }
    }
    
    if (slot == -1) {
        send_error_response(sock, STATUS_NOT_FOUND, "ERROR_DOWNLOAD_NOT_FOUND", "Download session not found");
        free(user);
        return;
    }
    
    if (downloads[slot].user_id != user->user_id) {
        send_error_response(sock, STATUS_FORBIDDEN, "ERROR_NOT_YOUR_DOWNLOAD", "This download session belongs to another user");
        free(user);
        return;
    }
    
    // Read chunk from file
    unsigned char buffer[CHUNK_SIZE];
    size_t bytes_read = fread(buffer, 1, CHUNK_SIZE, downloads[slot].fp);
    
    if (bytes_read == 0 && ferror(downloads[slot].fp)) {
        fclose(downloads[slot].fp);
        downloads[slot].active = 0;
        send_error_response(sock, STATUS_INTERNAL_ERROR, "ERROR_READ_FILE", "Failed to read file");
        free(user);
        return;
    }
    
    // Update MD5 checksum
    MD5_Update(&downloads[slot].md5_context, buffer, bytes_read);
    
    // Encode chunk to base64
    char *chunk_data_b64 = base64_encode(buffer, bytes_read);
    downloads[slot].sent_size += bytes_read;
    downloads[slot].last_activity = time(NULL);
    
    int is_last = (downloads[slot].sent_size >= downloads[slot].total_size);
    
    // Create response
    struct json_object *response = json_object_new_object();
    json_object_object_add(response, "status", json_object_new_int(STATUS_OK));
    json_object_object_add(response, "code", json_object_new_string("SUCCESS_DOWNLOAD_CHUNK"));
    json_object_object_add(response, "message", json_object_new_string("Chunk sent successfully"));
    
    struct json_object *payload = json_object_new_object();
    json_object_object_add(payload, "chunk_index", json_object_new_int(chunk_index));
    json_object_object_add(payload, "chunk_data", json_object_new_string(chunk_data_b64));
    json_object_object_add(payload, "sent_size", json_object_new_int64(downloads[slot].sent_size));
    json_object_object_add(payload, "total_size", json_object_new_int64(downloads[slot].total_size));
    json_object_object_add(payload, "is_last", json_object_new_boolean(is_last));
    json_object_object_add(response, "payload", payload);
    
    const char *response_str = json_object_to_json_string(response);
    send(sock, response_str, strlen(response_str), 0);
    json_object_put(response);
    
    free(chunk_data_b64);
    free(user);
}

void handle_download_file_complete(int sock, struct json_object *request) {
    struct json_object *data_obj, *token_obj, *download_id_obj;
    
    // Extract data field
    if (!json_object_object_get_ex(request, "data", &data_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing data field");
        return;
    }
    
    // Extract session_token
    if (!json_object_object_get_ex(data_obj, "session_token", &token_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing session_token");
        return;
    }
    const char *session_token = json_object_get_string(token_obj);
    
    // Verify session
    UserInfo *user = db_verify_session(session_token);
    if (!user) {
        send_error_response(sock, STATUS_UNAUTHORIZED, "ERROR_INVALID_SESSION", "Invalid or expired session");
        return;
    }
    
    // Parse request data
    if (!json_object_object_get_ex(data_obj, "download_id", &download_id_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing download_id");
        free(user);
        return;
    }
    
    int download_id = json_object_get_int(download_id_obj);
    
    // Find download session
    int slot = -1;
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (downloads[i].active && downloads[i].download_id == download_id) {
            slot = i;
            break;
        }
    }
    
    if (slot == -1) {
        send_error_response(sock, STATUS_NOT_FOUND, "ERROR_DOWNLOAD_NOT_FOUND", "Download session not found");
        free(user);
        return;
    }
    
    if (downloads[slot].user_id != user->user_id) {
        send_error_response(sock, STATUS_FORBIDDEN, "ERROR_NOT_YOUR_DOWNLOAD", "This download session belongs to another user");
        free(user);
        return;
    }
    
    // Finalize MD5 checksum
    MD5_Final(downloads[slot].md5_digest, &downloads[slot].md5_context);
    char md5_hex[MD5_DIGEST_LENGTH * 2 + 1];
    md5_to_hex(downloads[slot].md5_digest, md5_hex);
    
    long long sent_size = downloads[slot].sent_size;
    
    // Close file and clear session
    fclose(downloads[slot].fp);
    downloads[slot].active = 0;
    
    // Create response
    struct json_object *response = json_object_new_object();
    json_object_object_add(response, "status", json_object_new_int(STATUS_OK));
    json_object_object_add(response, "code", json_object_new_string("SUCCESS_DOWNLOAD_COMPLETE"));
    json_object_object_add(response, "message", json_object_new_string("Download completed successfully"));
    
    struct json_object *payload = json_object_new_object();
    json_object_object_add(payload, "sent_size", json_object_new_int64(sent_size));
    json_object_object_add(payload, "md5_checksum", json_object_new_string(md5_hex));
    json_object_object_add(response, "payload", payload);
    
    const char *response_str = json_object_to_json_string(response);
    send(sock, response_str, strlen(response_str), 0);
    json_object_put(response);
    
    free(user);
}

// ============================================================================
// FILE OPERATIONS - THAO TÁC VỚI FILE
// ============================================================================

/**
 * Handle RENAME_FILE command - Đổi tên file
 * Chỉ file owner hoặc admin mới có quyền rename
 */
void handle_rename_file(int sock, struct json_object *request) {
    struct json_object *data_obj, *token_obj, *file_id_obj, *new_name_obj;
    
    if (!json_object_object_get_ex(request, "data", &data_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing data field");
        return;
    }
    
    if (!json_object_object_get_ex(data_obj, "session_token", &token_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing session_token");
        return;
    }
    const char *session_token = json_object_get_string(token_obj);
    
    UserInfo *user = db_verify_session(session_token);
    if (!user) {
        send_error_response(sock, STATUS_UNAUTHORIZED, "ERROR_INVALID_SESSION", "Invalid or expired session");
        return;
    }
    
    if (!json_object_object_get_ex(data_obj, "file_id", &file_id_obj) ||
        !json_object_object_get_ex(data_obj, "new_name", &new_name_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing required fields");
        free(user);
        return;
    }
    
    int file_id = json_object_get_int(file_id_obj);
    const char *new_name = json_object_get_string(new_name_obj);
    
    FileInfo *file = db_get_file_by_id(file_id);
    if (!file) {
        send_error_response(sock, STATUS_NOT_FOUND, "ERROR_FILE_NOT_FOUND", "File not found");
        free(user);
        return;
    }
    
    if (!db_is_group_member(user->user_id, file->group_id)) {
        free(file);
        send_error_response(sock, STATUS_FORBIDDEN, "ERROR_NOT_GROUP_MEMBER", "You are not a member of this group");
        free(user);
        return;
    }
    
    PermissionInfo *perm = db_get_permissions(user->user_id, file->group_id);
    int is_admin = db_is_group_admin(user->user_id, file->group_id);
    if (file->uploaded_by != user->user_id && !is_admin) {
        if (perm) free(perm);
        free(file);
        send_error_response(sock, STATUS_FORBIDDEN, "ERROR_NO_PERMISSION", "Only file owner or admin can rename files");
        free(user);
        return;
    }
    if (perm) free(perm);
    
    char old_name[256];
    strncpy(old_name, file->file_name, 255);
    
    char old_physical_path[1024];
    sprintf(old_physical_path, "%s/group_%d%s", STORAGE_BASE_PATH, file->group_id, file->file_path);
    
    char new_file_path[512];
    char *last_slash = strrchr(file->file_path, '/');
    if (last_slash) {
        int dir_len = last_slash - file->file_path + 1;
        strncpy(new_file_path, file->file_path, dir_len);
        new_file_path[dir_len] = '\0';
        strcat(new_file_path, new_name);
    } else {
        sprintf(new_file_path, "/%s", new_name);
    }
    
    char new_physical_path[1024];
    sprintf(new_physical_path, "%s/group_%d%s", STORAGE_BASE_PATH, file->group_id, new_file_path);
    
    if (rename(old_physical_path, new_physical_path) != 0) {
        free(file);
        send_error_response(sock, STATUS_INTERNAL_ERROR, "ERROR_RENAME_FILE", "Failed to rename file");
        free(user);
        return;
    }
    
    if (db_rename_file(file_id, new_name) != 0) {
        rename(new_physical_path, old_physical_path);
        free(file);
        send_error_response(sock, STATUS_INTERNAL_ERROR, "ERROR_UPDATE_DATABASE", "Failed to update database");
        free(user);
        return;
    }
    
    time_t now = time(NULL);
    char updated_at[64];
    strftime(updated_at, sizeof(updated_at), "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));
    
    free(file);
    
    struct json_object *response = json_object_new_object();
    json_object_object_add(response, "status", json_object_new_int(STATUS_OK));
    json_object_object_add(response, "code", json_object_new_string("SUCCESS_RENAME_FILE"));
    json_object_object_add(response, "message", json_object_new_string("File renamed successfully"));
    
    struct json_object *payload = json_object_new_object();
    json_object_object_add(payload, "file_id", json_object_new_int(file_id));
    json_object_object_add(payload, "old_name", json_object_new_string(old_name));
    json_object_object_add(payload, "new_name", json_object_new_string(new_name));
    json_object_object_add(payload, "updated_at", json_object_new_string(updated_at));
    json_object_object_add(response, "payload", payload);
    
    const char *response_str = json_object_to_json_string(response);
    send(sock, response_str, strlen(response_str), 0);
    json_object_put(response);
    
    free(user);
}

/**
 * Handle DELETE_FILE command - Xóa file
 * Chỉ file owner hoặc admin mới có quyền delete
 */
void handle_delete_file(int sock, struct json_object *request) {
    struct json_object *data_obj, *token_obj, *file_id_obj;
    
    if (!json_object_object_get_ex(request, "data", &data_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing data field");
        return;
    }
    
    if (!json_object_object_get_ex(data_obj, "session_token", &token_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing session_token");
        return;
    }
    const char *session_token = json_object_get_string(token_obj);
    
    UserInfo *user = db_verify_session(session_token);
    if (!user) {
        send_error_response(sock, STATUS_UNAUTHORIZED, "ERROR_INVALID_SESSION", "Invalid or expired session");
        return;
    }
    
    if (!json_object_object_get_ex(data_obj, "file_id", &file_id_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing file_id");
        free(user);
        return;
    }
    
    int file_id = json_object_get_int(file_id_obj);
    
    FileInfo *file = db_get_file_by_id(file_id);
    if (!file) {
        send_error_response(sock, STATUS_NOT_FOUND, "ERROR_FILE_NOT_FOUND", "File not found");
        free(user);
        return;
    }
    
    if (!db_is_group_member(user->user_id, file->group_id)) {
        free(file);
        send_error_response(sock, STATUS_FORBIDDEN, "ERROR_NOT_GROUP_MEMBER", "You are not a member of this group");
        free(user);
        return;
    }
    
    PermissionInfo *perm = db_get_permissions(user->user_id, file->group_id);
    int is_admin = db_is_group_admin(user->user_id, file->group_id);
    if (file->uploaded_by != user->user_id && !is_admin) {
        if (perm) free(perm);
        free(file);
        send_error_response(sock, STATUS_FORBIDDEN, "ERROR_NO_PERMISSION", "Only file owner or admin can delete files");
        free(user);
        return;
    }
    if (perm) free(perm);
    
    char physical_path[1024];
    sprintf(physical_path, "%s/group_%d%s", STORAGE_BASE_PATH, file->group_id, file->file_path);
    
    if (unlink(physical_path) != 0) {
        free(file);
        send_error_response(sock, STATUS_INTERNAL_ERROR, "ERROR_DELETE_FILE", "Failed to delete file");
        free(user);
        return;
    }
    
    if (db_delete_file(file_id) != 0) {
        free(file);
        send_error_response(sock, STATUS_INTERNAL_ERROR, "ERROR_UPDATE_DATABASE", "Failed to update database");
        free(user);
        return;
    }
    
    time_t now = time(NULL);
    char deleted_at[64];
    strftime(deleted_at, sizeof(deleted_at), "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));
    
    free(file);
    
    struct json_object *response = json_object_new_object();
    json_object_object_add(response, "status", json_object_new_int(STATUS_OK));
    json_object_object_add(response, "code", json_object_new_string("SUCCESS_DELETE_FILE"));
    json_object_object_add(response, "message", json_object_new_string("File deleted successfully"));
    
    struct json_object *payload = json_object_new_object();
    json_object_object_add(payload, "file_id", json_object_new_int(file_id));
    json_object_object_add(payload, "deleted_at", json_object_new_string(deleted_at));
    json_object_object_add(response, "payload", payload);
    
    const char *response_str = json_object_to_json_string(response);
    send(sock, response_str, strlen(response_str), 0);
    json_object_put(response);
    
    free(user);
}

/**
 * Handle COPY_FILE command - Copy file sang thư mục khác
 */
void handle_copy_file(int sock, struct json_object *request) {
    struct json_object *data_obj, *token_obj, *file_id_obj, *dest_path_obj;
    
    if (!json_object_object_get_ex(request, "data", &data_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing data field");
        return;
    }
    
    if (!json_object_object_get_ex(data_obj, "session_token", &token_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing session_token");
        return;
    }
    const char *session_token = json_object_get_string(token_obj);
    
    UserInfo *user = db_verify_session(session_token);
    if (!user) {
        send_error_response(sock, STATUS_UNAUTHORIZED, "ERROR_INVALID_SESSION", "Invalid or expired session");
        return;
    }
    
    if (!json_object_object_get_ex(data_obj, "file_id", &file_id_obj) ||
        !json_object_object_get_ex(data_obj, "destination_path", &dest_path_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing required fields");
        free(user);
        return;
    }
    
    int file_id = json_object_get_int(file_id_obj);
    const char *dest_path = json_object_get_string(dest_path_obj);
    
    FileInfo *source = db_get_file_by_id(file_id);
    if (!source) {
        send_error_response(sock, STATUS_NOT_FOUND, "ERROR_FILE_NOT_FOUND", "Source file not found");
        free(user);
        return;
    }
    
    if (!db_is_group_member(user->user_id, source->group_id)) {
        free(source);
        send_error_response(sock, STATUS_FORBIDDEN, "ERROR_NOT_GROUP_MEMBER", "You are not a member of this group");
        free(user);
        return;
    }
    
    PermissionInfo *perm = db_get_permissions(user->user_id, source->group_id);
    if (!perm || !perm->can_write) {
        if (perm) free(perm);
        free(source);
        send_error_response(sock, STATUS_FORBIDDEN, "ERROR_NO_PERMISSION", "You don't have write permission");
        free(user);
        return;
    }
    free(perm);
    
    char new_file_path[512];
    if (dest_path[strlen(dest_path) - 1] == '/') {
        sprintf(new_file_path, "%s%s", dest_path, source->file_name);
    } else {
        sprintf(new_file_path, "%s/%s", dest_path, source->file_name);
    }
    
    char source_physical[1024];
    sprintf(source_physical, "%s/group_%d%s", STORAGE_BASE_PATH, source->group_id, source->file_path);
    
    char dest_physical[1024];
    sprintf(dest_physical, "%s/group_%d%s", STORAGE_BASE_PATH, source->group_id, new_file_path);
    
    char mkdir_cmd[2048];
    char dir_path[1024];
    strcpy(dir_path, dest_physical);
    char *last_slash = strrchr(dir_path, '/');
    if (last_slash) {
        *last_slash = '\0';
        sprintf(mkdir_cmd, "mkdir -p '%s'", dir_path);
        system(mkdir_cmd);
    }
    
    char cp_cmd[4096];
    snprintf(cp_cmd, sizeof(cp_cmd), "cp '%s' '%s'", source_physical, dest_physical);
    if (system(cp_cmd) != 0) {
        free(source);
        send_error_response(sock, STATUS_INTERNAL_ERROR, "ERROR_COPY_FILE", "Failed to copy file");
        free(user);
        return;
    }
    
    int new_file_id = db_create_file(
        source->group_id,
        source->file_name,
        new_file_path,
        source->file_size,
        source->file_type,
        dest_path,
        user->user_id
    );
    
    if (new_file_id <= 0) {
        unlink(dest_physical);
        free(source);
        send_error_response(sock, STATUS_INTERNAL_ERROR, "ERROR_CREATE_FILE_RECORD", "Failed to create file record");
        free(user);
        return;
    }
    
    time_t now = time(NULL);
    char copied_at[64];
    strftime(copied_at, sizeof(copied_at), "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));
    
    free(source);
    
    struct json_object *response = json_object_new_object();
    json_object_object_add(response, "status", json_object_new_int(STATUS_OK));
    json_object_object_add(response, "code", json_object_new_string("SUCCESS_COPY_FILE"));
    json_object_object_add(response, "message", json_object_new_string("File copied successfully"));
    
    struct json_object *payload = json_object_new_object();
    json_object_object_add(payload, "source_file_id", json_object_new_int(file_id));
    json_object_object_add(payload, "new_file_id", json_object_new_int(new_file_id));
    json_object_object_add(payload, "new_file_path", json_object_new_string(new_file_path));
    json_object_object_add(payload, "copied_at", json_object_new_string(copied_at));
    json_object_object_add(response, "payload", payload);
    
    const char *response_str = json_object_to_json_string(response);
    send(sock, response_str, strlen(response_str), 0);
    json_object_put(response);
    
    free(user);
}

/**
 * Handle MOVE_FILE command - Di chuyển file sang thư mục khác
 * Chỉ file owner hoặc admin mới có quyền move
 */
void handle_move_file(int sock, struct json_object *request) {
    struct json_object *data_obj, *token_obj, *file_id_obj, *dest_path_obj;
    
    if (!json_object_object_get_ex(request, "data", &data_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing data field");
        return;
    }
    
    if (!json_object_object_get_ex(data_obj, "session_token", &token_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing session_token");
        return;
    }
    const char *session_token = json_object_get_string(token_obj);
    
    UserInfo *user = db_verify_session(session_token);
    if (!user) {
        send_error_response(sock, STATUS_UNAUTHORIZED, "ERROR_INVALID_SESSION", "Invalid or expired session");
        return;
    }
    
    if (!json_object_object_get_ex(data_obj, "file_id", &file_id_obj) ||
        !json_object_object_get_ex(data_obj, "destination_path", &dest_path_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing required fields");
        free(user);
        return;
    }
    
    int file_id = json_object_get_int(file_id_obj);
    const char *dest_path = json_object_get_string(dest_path_obj);
    
    FileInfo *file = db_get_file_by_id(file_id);
    if (!file) {
        send_error_response(sock, STATUS_NOT_FOUND, "ERROR_FILE_NOT_FOUND", "File not found");
        free(user);
        return;
    }
    
    if (!db_is_group_member(user->user_id, file->group_id)) {
        free(file);
        send_error_response(sock, STATUS_FORBIDDEN, "ERROR_NOT_GROUP_MEMBER", "You are not a member of this group");
        free(user);
        return;
    }
    
    PermissionInfo *perm = db_get_permissions(user->user_id, file->group_id);
    int is_admin = db_is_group_admin(user->user_id, file->group_id);
    if (file->uploaded_by != user->user_id && !is_admin) {
        if (perm) free(perm);
        free(file);
        send_error_response(sock, STATUS_FORBIDDEN, "ERROR_NO_PERMISSION", "Only file owner or admin can move files");
        free(user);
        return;
    }
    if (perm) free(perm);
    
    char old_path[512];
    strncpy(old_path, file->file_path, 511);
    
    char new_file_path[512];
    if (dest_path[strlen(dest_path) - 1] == '/') {
        sprintf(new_file_path, "%s%s", dest_path, file->file_name);
    } else {
        sprintf(new_file_path, "%s/%s", dest_path, file->file_name);
    }
    
    char old_physical[1024];
    sprintf(old_physical, "%s/group_%d%s", STORAGE_BASE_PATH, file->group_id, file->file_path);
    
    char new_physical[1024];
    sprintf(new_physical, "%s/group_%d%s", STORAGE_BASE_PATH, file->group_id, new_file_path);
    
    char mkdir_cmd[2048];
    char dir_path[1024];
    strcpy(dir_path, new_physical);
    char *last_slash = strrchr(dir_path, '/');
    if (last_slash) {
        *last_slash = '\0';
        sprintf(mkdir_cmd, "mkdir -p '%s'", dir_path);
        system(mkdir_cmd);
    }
    
    if (rename(old_physical, new_physical) != 0) {
        free(file);
        send_error_response(sock, STATUS_INTERNAL_ERROR, "ERROR_MOVE_FILE", "Failed to move file");
        free(user);
        return;
    }
    
    if (db_move_file(file_id, new_file_path) != 0) {
        rename(new_physical, old_physical);
        free(file);
        send_error_response(sock, STATUS_INTERNAL_ERROR, "ERROR_UPDATE_DATABASE", "Failed to update database");
        free(user);
        return;
    }
    
    time_t now = time(NULL);
    char moved_at[64];
    strftime(moved_at, sizeof(moved_at), "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));
    
    free(file);
    
    struct json_object *response = json_object_new_object();
    json_object_object_add(response, "status", json_object_new_int(STATUS_OK));
    json_object_object_add(response, "code", json_object_new_string("SUCCESS_MOVE_FILE"));
    json_object_object_add(response, "message", json_object_new_string("File moved successfully"));
    
    struct json_object *payload = json_object_new_object();
    json_object_object_add(payload, "file_id", json_object_new_int(file_id));
    json_object_object_add(payload, "old_path", json_object_new_string(old_path));
    json_object_object_add(payload, "new_path", json_object_new_string(new_file_path));
    json_object_object_add(payload, "moved_at", json_object_new_string(moved_at));
    json_object_object_add(response, "payload", payload);
    
    const char *response_str = json_object_to_json_string(response);
    send(sock, response_str, strlen(response_str), 0);
    json_object_put(response);
    
    free(user);
}
