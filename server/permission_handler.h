#ifndef PERMISSION_HANDLER_H
#define PERMISSION_HANDLER_H

#include <json-c/json.h>

void handle_get_permissions(int sock, struct json_object *request);
void handle_update_permissions(int sock, struct json_object *request);

#endif
