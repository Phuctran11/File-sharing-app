#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <json-c/json.h>
#include "../common/protocol.h"
#include "folder_handler.h"
#include "database.h"
#include "auth_handler.h"

#define STORAGE_BASE_PATH "/home/phuctran23/Laptrinhmang-BTL/file_share_app/storage"

void handle_create_directory(int sock, struct json_object *request) {
    struct json_object *data_obj, *token_obj, *group_id_obj, *directory_name_obj, *parent_path_obj;
    
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
    
    // Extract group_id
    if (!json_object_object_get_ex(data_obj, "group_id", &group_id_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing group_id");
        free(user);
        return;
    }
    int group_id = json_object_get_int(group_id_obj);
    
    // Check if user is member of the group
    if (!db_is_group_member(user->user_id, group_id)) {
        send_error_response(sock, STATUS_FORBIDDEN, "ERROR_NOT_GROUP_MEMBER", "You are not a member of this group");
        free(user);
        return;
    }
    
    // Extract directory_name
    if (!json_object_object_get_ex(data_obj, "directory_name", &directory_name_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing directory_name");
        free(user);
        return;
    }
    const char *directory_name = json_object_get_string(directory_name_obj);
    
    // Extract parent_path
    if (!json_object_object_get_ex(data_obj, "parent_path", &parent_path_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing parent_path");
        free(user);
        return;
    }
    const char *parent_path = json_object_get_string(parent_path_obj);
    
    // Validate directory name (no special characters)
    if (strchr(directory_name, '/') 
    || strchr(directory_name, '\\') 
    || strstr(directory_name, "..")) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_DIRECTORY_NAME", "Invalid directory name");
        free(user);
        return;
    }
    
    // Create full directory path in database format
    char db_directory_path[512];
    if (parent_path[strlen(parent_path) - 1] == '/') {
        snprintf(db_directory_path, sizeof(db_directory_path), "%s%s", parent_path, directory_name);
    } else {
        snprintf(db_directory_path, sizeof(db_directory_path), "%s/%s", parent_path, directory_name);
    }
    
    // Create physical directory path in storage
    char physical_parent_path[4096];// tránh tràn do chuỗi có thể lớn hơn mong đợi
    char physical_directory_path[4096];// tránh tràn do chuỗi có thể lớn hơn mong đợi
    
    size_t len_parent = strlen(physical_parent_path);
    size_t len_dir = strlen(directory_name);

    if (len_parent + 1 + len_dir + 1 > sizeof(physical_directory_path)) {
        // Xử lý lỗi: chuỗi sẽ bị cắt bớt hoặc báo lỗi
        send_error_response(sock, STATUS_INTERNAL_ERROR, "ERROR_PATH_TOO_LONG", "Directory path too long");
        free(user);
        return;
    }

    snprintf(physical_parent_path, sizeof(physical_parent_path), "%s/group_%d%s", 
             STORAGE_BASE_PATH, group_id, parent_path);
    snprintf(physical_directory_path, sizeof(physical_directory_path), "%s/%s", 
             physical_parent_path, directory_name);
    
    // Check if parent directory exists in storage
    struct stat st;
    if (stat(physical_parent_path, &st) != 0 || !S_ISDIR(st.st_mode)) {
        // Try to create parent directories
        char temp_path[1024];
        snprintf(temp_path, sizeof(temp_path), "%s/group_%d", STORAGE_BASE_PATH, group_id);
        mkdir(temp_path, 0755);
        
        // Create parent path recursively
        char *path_copy = strdup(parent_path);
        char *token = strtok(path_copy, "/");
        while (token != NULL) {
            strcat(temp_path, "/");
            strcat(temp_path, token);
            mkdir(temp_path, 0755);
            token = strtok(NULL, "/");
        }
        free(path_copy);
    }
    
    // Create the new directory in storage
    if (mkdir(physical_directory_path, 0755) != 0) {
        if (stat(physical_directory_path, &st) == 0) {
            send_error_response(sock, STATUS_CONFLICT, "ERROR_DIRECTORY_EXISTS", "Directory already exists");
        } else {
            send_error_response(sock, STATUS_INTERNAL_ERROR, "ERROR_CREATE_DIRECTORY", "Failed to create directory in storage");
        }
        free(user);
        return;
    }
    
    // Insert directory info into database
    int directory_id = db_create_directory(group_id, directory_name, parent_path, user->user_id);
    
    if (directory_id < 0) {
        // Rollback: remove physical directory
        rmdir(physical_directory_path);
        send_error_response(sock, STATUS_INTERNAL_ERROR, "ERROR_CREATE_DIRECTORY", "Failed to save directory to database");
        free(user);
        return;
    }
    
    // Get directory info for response
    DirectoryInfo *dir_info = db_get_directory_by_id(directory_id);
    
    if (!dir_info) {
        send_error_response(sock, STATUS_INTERNAL_ERROR, "ERROR_CREATE_DIRECTORY", "Failed to retrieve directory info");
        free(user);
        return;
    }
    
    // Build success response
    struct json_object *response = json_object_new_object();
    json_object_object_add(response, "status", json_object_new_int(STATUS_CREATED));
    json_object_object_add(response, "code", json_object_new_string("SUCCESS_CREATE_DIRECTORY"));
    json_object_object_add(response, "message", json_object_new_string("Directory created successfully"));
    
    struct json_object *payload = json_object_new_object();
    json_object_object_add(payload, "directory_id", json_object_new_int(dir_info->directory_id));
    json_object_object_add(payload, "directory_name", json_object_new_string(dir_info->directory_name));
    json_object_object_add(payload, "directory_path", json_object_new_string(dir_info->directory_path));
    json_object_object_add(payload, "created_at", json_object_new_string(dir_info->created_at));
    
    json_object_object_add(response, "payload", payload);
    
    const char *response_str = json_object_to_json_string(response);
    send(sock, response_str, strlen(response_str), 0);
    
    printf("Directory created: %s (ID: %d) by user %s\n", 
           dir_info->directory_path, dir_info->directory_id, user->username);
    
    json_object_put(response);
    free(dir_info);
    free(user);
}

void handle_rename_directory(int sock, struct json_object *request) {
    struct json_object *data_obj, *token_obj, *directory_id_obj, *new_name_obj;
    
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
    
    if (!json_object_object_get_ex(data_obj, "directory_id", &directory_id_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing directory_id");
        free(user);
        return;
    }
    int directory_id = json_object_get_int(directory_id_obj);
    
    if (!json_object_object_get_ex(data_obj, "new_name", &new_name_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing new_name");
        free(user);
        return;
    }
    const char *new_name = json_object_get_string(new_name_obj);
    
    DirectoryInfo *old_dir = db_get_directory_by_id(directory_id);
    if (!old_dir) {
        send_error_response(sock, STATUS_NOT_FOUND, "ERROR_DIRECTORY_NOT_FOUND", "Directory not found");
        free(user);
        return;
    }
    
    if (!db_is_group_admin(user->user_id, old_dir->group_id)) {
        send_error_response(sock, STATUS_FORBIDDEN, "ERROR_NOT_ADMIN", "Only admin can rename directory");
        free(old_dir);
        free(user);
        return;
    }
    
    char old_name[256], old_path[512];
    strncpy(old_name, old_dir->directory_name, 255);
    strncpy(old_path, old_dir->directory_path, 511);
    int group_id = old_dir->group_id;
    free(old_dir);
    
    char old_physical_path[1024], new_physical_path[1024];
    snprintf(old_physical_path, sizeof(old_physical_path), "%s/group_%d%s", 
             STORAGE_BASE_PATH, group_id, old_path);
    
    char parent_path[512];
    strcpy(parent_path, old_path);
    char *last_slash = strrchr(parent_path, '/');
    if (last_slash) *last_slash = '\0';
    snprintf(new_physical_path, sizeof(new_physical_path), "%s/group_%d%s/%s", 
             STORAGE_BASE_PATH, group_id, parent_path, new_name);
    
    if (rename(old_physical_path, new_physical_path) != 0) {
        send_error_response(sock, STATUS_INTERNAL_ERROR, "ERROR_RENAME_DIRECTORY", "Failed to rename directory in storage");
        free(user);
        return;
    }
    
    if (db_rename_directory(directory_id, new_name) != 0) {
        rename(new_physical_path, old_physical_path);
        send_error_response(sock, STATUS_INTERNAL_ERROR, "ERROR_RENAME_DIRECTORY", "Failed to update database");
        free(user);
        return;
    }
    
    DirectoryInfo *new_dir = db_get_directory_by_id(directory_id);
    struct json_object *response = json_object_new_object();
    json_object_object_add(response, "status", json_object_new_int(STATUS_OK));
    json_object_object_add(response, "code", json_object_new_string("SUCCESS_RENAME_DIRECTORY"));
    json_object_object_add(response, "message", json_object_new_string("Directory renamed successfully"));
    
    struct json_object *payload = json_object_new_object();
    json_object_object_add(payload, "directory_id", json_object_new_int(directory_id));
    json_object_object_add(payload, "old_name", json_object_new_string(old_name));
    json_object_object_add(payload, "new_name", json_object_new_string(new_name));
    json_object_object_add(payload, "old_path", json_object_new_string(old_path));
    json_object_object_add(payload, "new_path", json_object_new_string(new_dir->directory_path));
    json_object_object_add(payload, "updated_at", json_object_new_string(new_dir->created_at));
    json_object_object_add(response, "payload", payload);
    
    const char *response_str = json_object_to_json_string(response);
    send(sock, response_str, strlen(response_str), 0);
    
    json_object_put(response);
    free(new_dir);
    free(user);
}

void handle_delete_directory(int sock, struct json_object *request) {
    struct json_object *data_obj, *token_obj, *directory_id_obj, *recursive_obj;
    
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
    
    if (!json_object_object_get_ex(data_obj, "directory_id", &directory_id_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing directory_id");
        free(user);
        return;
    }
    int directory_id = json_object_get_int(directory_id_obj);
    
    int recursive = 0;
    if (json_object_object_get_ex(data_obj, "recursive", &recursive_obj)) {
        recursive = json_object_get_boolean(recursive_obj);
    }
    
    DirectoryInfo *dir = db_get_directory_by_id(directory_id);
    if (!dir) {
        send_error_response(sock, STATUS_NOT_FOUND, "ERROR_DIRECTORY_NOT_FOUND", "Directory not found");
        free(user);
        return;
    }
    
    if (!db_is_group_admin(user->user_id, dir->group_id)) {
        send_error_response(sock, STATUS_FORBIDDEN, "ERROR_NOT_ADMIN", "Only admin can delete directory");
        free(dir);
        free(user);
        return;
    }
    
    char physical_path[1024];
    snprintf(physical_path, sizeof(physical_path), "%s/group_%d%s", 
             STORAGE_BASE_PATH, dir->group_id, dir->directory_path);
    
    int deleted_files = 0, deleted_subdirs = 0;
    if (db_delete_directory(directory_id, &deleted_files, &deleted_subdirs) != 0) {
        send_error_response(sock, STATUS_INTERNAL_ERROR, "ERROR_DELETE_DIRECTORY", "Failed to delete from database");
        free(dir);
        free(user);
        return;
    }
    
    char rm_command[2048];
    if (recursive) {
        snprintf(rm_command, sizeof(rm_command), "rm -rf \"%s\"", physical_path);
    } else {
        snprintf(rm_command, sizeof(rm_command), "rmdir \"%s\"", physical_path);
    }
    system(rm_command);
    
    struct json_object *response = json_object_new_object();
    json_object_object_add(response, "status", json_object_new_int(STATUS_OK));
    json_object_object_add(response, "code", json_object_new_string("SUCCESS_DELETE_DIRECTORY"));
    json_object_object_add(response, "message", json_object_new_string("Directory deleted successfully"));
    
    struct json_object *payload = json_object_new_object();
    json_object_object_add(payload, "directory_id", json_object_new_int(directory_id));
    json_object_object_add(payload, "deleted_files", json_object_new_int(deleted_files));
    json_object_object_add(payload, "deleted_subdirectories", json_object_new_int(deleted_subdirs));
    json_object_object_add(payload, "deleted_at", json_object_new_string(dir->created_at));
    json_object_object_add(response, "payload", payload);
    
    const char *response_str = json_object_to_json_string(response);
    send(sock, response_str, strlen(response_str), 0);
    
    json_object_put(response);
    free(dir);
    free(user);
}

void handle_copy_directory(int sock, struct json_object *request) {
    struct json_object *data_obj, *token_obj, *directory_id_obj, *destination_path_obj;
    
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
    
    if (!json_object_object_get_ex(data_obj, "directory_id", &directory_id_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing directory_id");
        free(user);
        return;
    }
    int directory_id = json_object_get_int(directory_id_obj);
    
    if (!json_object_object_get_ex(data_obj, "destination_path", &destination_path_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing destination_path");
        free(user);
        return;
    }
    const char *destination_path = json_object_get_string(destination_path_obj);
    
    DirectoryInfo *source_dir = db_get_directory_by_id(directory_id);
    if (!source_dir) {
        send_error_response(sock, STATUS_NOT_FOUND, "ERROR_DIRECTORY_NOT_FOUND", "Directory not found");
        free(user);
        return;
    }
    
    if (!db_is_group_member(user->user_id, source_dir->group_id)) {
        send_error_response(sock, STATUS_FORBIDDEN, "ERROR_NOT_MEMBER", "Not a member of this group");
        free(source_dir);
        free(user);
        return;
    }
    
    int new_directory_id = db_copy_directory(directory_id, destination_path, user->user_id);
    if (new_directory_id < 0) {
        send_error_response(sock, STATUS_INTERNAL_ERROR, "ERROR_COPY_DIRECTORY", "Failed to copy directory");
        free(source_dir);
        free(user);
        return;
    }
    
    DirectoryInfo *new_dir = db_get_directory_by_id(new_directory_id);
    
    char source_physical[1024], dest_physical[1024];
    snprintf(source_physical, sizeof(source_physical), "%s/group_%d%s", 
             STORAGE_BASE_PATH, source_dir->group_id, source_dir->directory_path);
    snprintf(dest_physical, sizeof(dest_physical), "%s/group_%d%s", 
             STORAGE_BASE_PATH, new_dir->group_id, new_dir->directory_path);
    
    // Create destination directory first
    char mkdir_cmd[2048];
    snprintf(mkdir_cmd, sizeof(mkdir_cmd), "mkdir -p \"%s\"", dest_physical);
    system(mkdir_cmd);
    
    // Copy contents from source to destination
    char cp_command[4096];
    snprintf(cp_command, sizeof(cp_command), "cp -r \"%s/.\" \"%s/\"", source_physical, dest_physical);
    system(cp_command);
    
    struct json_object *response = json_object_new_object();
    json_object_object_add(response, "status", json_object_new_int(STATUS_OK));
    json_object_object_add(response, "code", json_object_new_string("SUCCESS_COPY_DIRECTORY"));
    json_object_object_add(response, "message", json_object_new_string("Directory copied successfully"));
    
    struct json_object *payload = json_object_new_object();
    json_object_object_add(payload, "source_directory_id", json_object_new_int(directory_id));
    json_object_object_add(payload, "new_directory_id", json_object_new_int(new_directory_id));
    json_object_object_add(payload, "new_directory_path", json_object_new_string(new_dir->directory_path));
    json_object_object_add(payload, "copied_at", json_object_new_string(new_dir->created_at));
    json_object_object_add(response, "payload", payload);
    
    const char *response_str = json_object_to_json_string(response);
    send(sock, response_str, strlen(response_str), 0);
    
    json_object_put(response);
    free(new_dir);
    free(source_dir);
    free(user);
}

void handle_move_directory(int sock, struct json_object *request) {
    struct json_object *data_obj, *token_obj, *directory_id_obj, *destination_path_obj;
    
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
    
    if (!json_object_object_get_ex(data_obj, "directory_id", &directory_id_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing directory_id");
        free(user);
        return;
    }
    int directory_id = json_object_get_int(directory_id_obj);
    
    if (!json_object_object_get_ex(data_obj, "destination_path", &destination_path_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing destination_path");
        free(user);
        return;
    }
    const char *destination_path = json_object_get_string(destination_path_obj);
    
    DirectoryInfo *old_dir = db_get_directory_by_id(directory_id);
    if (!old_dir) {
        send_error_response(sock, STATUS_NOT_FOUND, "ERROR_DIRECTORY_NOT_FOUND", "Directory not found");
        free(user);
        return;
    }
    
    if (!db_is_group_admin(user->user_id, old_dir->group_id)) {
        send_error_response(sock, STATUS_FORBIDDEN, "ERROR_NOT_ADMIN", "Only admin can move directory");
        free(old_dir);
        free(user);
        return;
    }
    
    char old_path[512];
    strncpy(old_path, old_dir->directory_path, 511);
    int group_id = old_dir->group_id;
    
    int affected_files = 0, affected_subdirs = 0;
    if (db_move_directory(directory_id, destination_path, &affected_files, &affected_subdirs) != 0) {
        send_error_response(sock, STATUS_INTERNAL_ERROR, "ERROR_MOVE_DIRECTORY", "Failed to move directory");
        free(old_dir);
        free(user);
        return;
    }
    
    DirectoryInfo *new_dir = db_get_directory_by_id(directory_id);
    
    char old_physical[1024], new_physical[1024];
    snprintf(old_physical, sizeof(old_physical), "%s/group_%d%s", 
             STORAGE_BASE_PATH, group_id, old_path);
    snprintf(new_physical, sizeof(new_physical), "%s/group_%d%s", 
             STORAGE_BASE_PATH, group_id, new_dir->directory_path);
    
    char parent_dir[1024];
    strncpy(parent_dir, new_physical, sizeof(parent_dir) - 1);
    char *last_slash = strrchr(parent_dir, '/');
    if (last_slash) {
        *last_slash = '\0';
        char mkdir_cmd[2048];
        snprintf(mkdir_cmd, sizeof(mkdir_cmd), "mkdir -p \"%s\"", parent_dir);
        system(mkdir_cmd);
    }
    
    if (rename(old_physical, new_physical) != 0) {
        send_error_response(sock, STATUS_INTERNAL_ERROR, "ERROR_MOVE_DIRECTORY", "Failed to move directory in storage");
        free(new_dir);
        free(old_dir);
        free(user);
        return;
    }
    
    struct json_object *response = json_object_new_object();
    json_object_object_add(response, "status", json_object_new_int(STATUS_OK));
    json_object_object_add(response, "code", json_object_new_string("SUCCESS_MOVE_DIRECTORY"));
    json_object_object_add(response, "message", json_object_new_string("Directory moved successfully"));
    
    struct json_object *payload = json_object_new_object();
    json_object_object_add(payload, "directory_id", json_object_new_int(directory_id));
    json_object_object_add(payload, "old_path", json_object_new_string(old_path));
    json_object_object_add(payload, "new_path", json_object_new_string(new_dir->directory_path));
    json_object_object_add(payload, "affected_files", json_object_new_int(affected_files));
    json_object_object_add(payload, "affected_subdirectories", json_object_new_int(affected_subdirs));
    json_object_object_add(payload, "moved_at", json_object_new_string(new_dir->created_at));
    json_object_object_add(response, "payload", payload);
    
    const char *response_str = json_object_to_json_string(response);
    send(sock, response_str, strlen(response_str), 0);
    
    json_object_put(response);
    free(new_dir);
    free(old_dir);
    free(user);
}

void handle_list_directory(int sock, struct json_object *request) {
    struct json_object *data_obj, *token_obj, *group_id_obj, *directory_path_obj;
    
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
    
    // Extract group_id
    if (!json_object_object_get_ex(data_obj, "group_id", &group_id_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing group_id");
        free(user);
        return;
    }
    int group_id = json_object_get_int(group_id_obj);
    
    // Extract directory_path
    if (!json_object_object_get_ex(data_obj, "directory_path", &directory_path_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing directory_path");
        free(user);
        return;
    }
    const char *directory_path = json_object_get_string(directory_path_obj);
    
    // Check if user is member of the group
    if (!db_is_group_member(user->user_id, group_id)) {
        send_error_response(sock, STATUS_FORBIDDEN, "ERROR_NOT_GROUP_MEMBER", "You are not a member of this group");
        free(user);
        return;
    }
    
    // Check read permission
    PermissionInfo *perm = db_get_permissions(user->user_id, group_id);
    if (!perm || !perm->can_read) {
        send_error_response(sock, STATUS_FORBIDDEN, "ERROR_NO_PERMISSION", "You don't have read permission");
        if (perm) free(perm);
        free(user);
        return;
    }
    free(perm);
    
    // Get list of directories in the specified path
    DirectoryInfo **directories = NULL;
    int dir_count = db_list_directories(group_id, directory_path, &directories);
    
    if (dir_count < 0) {
        send_error_response(sock, STATUS_INTERNAL_ERROR, "ERROR_LIST_DIRECTORY", "Failed to list directories");
        free(user);
        return;
    }
    
    // Get list of files in the specified path
    FileInfo **files = NULL;
    int file_count = db_list_files(group_id, directory_path, &files);
    
    if (file_count < 0) {
        send_error_response(sock, STATUS_INTERNAL_ERROR, "ERROR_LIST_DIRECTORY", "Failed to list files");
        // Free directories
        for (int i = 0; i < dir_count; i++) {
            free(directories[i]);
        }
        if (directories) free(directories);
        free(user);
        return;
    }
    
    // Build success response
    struct json_object *response = json_object_new_object();
    json_object_object_add(response, "status", json_object_new_int(STATUS_OK));
    json_object_object_add(response, "code", json_object_new_string("SUCCESS_LIST_DIRECTORY"));
    json_object_object_add(response, "message", json_object_new_string("Directory contents retrieved successfully"));
    
    struct json_object *payload = json_object_new_object();
    json_object_object_add(payload, "group_id", json_object_new_int(group_id));
    json_object_object_add(payload, "current_path", json_object_new_string(directory_path));
    
    // Add directories array
    struct json_object *directories_array = json_object_new_array();
    for (int i = 0; i < dir_count; i++) {
        struct json_object *dir_obj = json_object_new_object();
        json_object_object_add(dir_obj, "directory_id", json_object_new_int(directories[i]->directory_id));
        json_object_object_add(dir_obj, "directory_name", json_object_new_string(directories[i]->directory_name));
        json_object_object_add(dir_obj, "directory_path", json_object_new_string(directories[i]->directory_path));
        json_object_object_add(dir_obj, "created_by", json_object_new_string(directories[i]->created_by));
        json_object_object_add(dir_obj, "created_at", json_object_new_string(directories[i]->created_at));
        json_object_array_add(directories_array, dir_obj);
    }
    json_object_object_add(payload, "directories", directories_array);
    
    // Add files array
    struct json_object *files_array = json_object_new_array();
    for (int i = 0; i < file_count; i++) {
        struct json_object *file_obj = json_object_new_object();
        json_object_object_add(file_obj, "file_id", json_object_new_int(files[i]->file_id));
        json_object_object_add(file_obj, "file_name", json_object_new_string(files[i]->file_name));
        json_object_object_add(file_obj, "file_path", json_object_new_string(files[i]->file_path));
        json_object_object_add(file_obj, "file_size", json_object_new_int64(files[i]->file_size));
        json_object_object_add(file_obj, "file_type", json_object_new_string(files[i]->file_type));
        
        // Get username of uploader
        char uploaded_by_str[32];
        sprintf(uploaded_by_str, "%d", files[i]->uploaded_by);
        json_object_object_add(file_obj, "uploaded_by", json_object_new_string(uploaded_by_str));
        json_object_object_add(file_obj, "uploaded_at", json_object_new_string(files[i]->uploaded_at));
        json_object_array_add(files_array, file_obj);
    }
    json_object_object_add(payload, "files", files_array);
    
    json_object_object_add(response, "payload", payload);
    
    const char *response_str = json_object_to_json_string(response);
    send(sock, response_str, strlen(response_str), 0);
    
    printf("Listed directory %s in group %d: %d directories, %d files\n", 
           directory_path, group_id, dir_count, file_count);
    
    // Cleanup
    json_object_put(response);
    
    for (int i = 0; i < dir_count; i++) {
        free(directories[i]);
    }
    if (directories) free(directories);
    
    for (int i = 0; i < file_count; i++) {
        free(files[i]);
    }
    if (files) free(files);
    
    free(user);
}
