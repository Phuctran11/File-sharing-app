#ifndef FILE_HANDLER_H
#define FILE_HANDLER_H

#include <json-c/json.h>

void handle_upload_file_start(int sock, struct json_object *request);
void handle_upload_file_chunk(int sock, struct json_object *request);
void handle_upload_file_complete(int sock, struct json_object *request);
void handle_download_file_start(int sock, struct json_object *request);
void handle_download_file_chunk(int sock, struct json_object *request);
void handle_download_file_complete(int sock, struct json_object *request);

// File operations
void handle_rename_file(int sock, struct json_object *request);
void handle_delete_file(int sock, struct json_object *request);
void handle_copy_file(int sock, struct json_object *request);
void handle_move_file(int sock, struct json_object *request);

#endif
