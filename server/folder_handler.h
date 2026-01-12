#ifndef FOLDER_HANDLER_H
#define FOLDER_HANDLER_H

#include <json-c/json.h>

void handle_create_directory(int sock, struct json_object *request);
void handle_rename_directory(int sock, struct json_object *request);
void handle_delete_directory(int sock, struct json_object *request);
void handle_copy_directory(int sock, struct json_object *request);
void handle_move_directory(int sock, struct json_object *request);
void handle_list_directory(int sock, struct json_object *request);

#endif
