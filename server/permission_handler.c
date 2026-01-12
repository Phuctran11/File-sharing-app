#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <json-c/json.h>
#include "permission_handler.h"
#include "database.h"
#include "auth_handler.h"
#include "../common/protocol.h"

void handle_get_permissions(int sock, struct json_object *request) {
    struct json_object *data_obj, *field;
    
    if (!json_object_object_get_ex(request, "data", &data_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing data field");
        return;
    }
    
    const char *session_token = NULL;
    int group_id = 0;
    
    if (json_object_object_get_ex(data_obj, "session_token", &field))
        session_token = json_object_get_string(field);
    if (json_object_object_get_ex(data_obj, "group_id", &field))
        group_id = json_object_get_int(field);
    
    if (!session_token || group_id <= 0) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing required fields");
        return;
    }
    
    // Verify session
    UserInfo *user = db_verify_session(session_token);
    if (!user) {
        send_error_response(sock, STATUS_UNAUTHORIZED, "ERROR_UNAUTHORIZED", "Invalid session token or session expired");
        return;
    }
    
    // Get permissions
    PermissionInfo *perm = db_get_permissions(user->user_id, group_id);
    if (!perm) {
        free(user);
        send_error_response(sock, STATUS_NOT_FOUND, "ERROR_NOT_FOUND", "Permissions not found");
        return;
    }
    
    // Send success response
    struct json_object *response = json_object_new_object();
    json_object_object_add(response, "status", json_object_new_int(STATUS_OK));
    json_object_object_add(response, "code", json_object_new_string("SUCCESS_GET_PERMISSIONS"));
    json_object_object_add(response, "message", json_object_new_string("Permissions retrieved successfully"));
    
    struct json_object *payload = json_object_new_object();
    json_object_object_add(payload, "user_id", json_object_new_int(user->user_id));
    json_object_object_add(payload, "group_id", json_object_new_int(group_id));
    json_object_object_add(payload, "can_read", json_object_new_boolean(perm->can_read));
    json_object_object_add(payload, "can_write", json_object_new_boolean(perm->can_write));
    json_object_object_add(payload, "can_delete", json_object_new_boolean(perm->can_delete));
    json_object_object_add(payload, "can_manage", json_object_new_boolean(perm->can_manage));
    json_object_object_add(response, "payload", payload);
    
    const char *json_str = json_object_to_json_string(response);
    send(sock, json_str, strlen(json_str), 0);
    
    free(user);
    free(perm);
    json_object_put(response);
}

void handle_update_permissions(int sock, struct json_object *request) {
    struct json_object *data_obj, *field;
    
    if (!json_object_object_get_ex(request, "data", &data_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing data field");
        return;
    }
    
    const char *session_token = NULL;
    int group_id = 0, target_user_id = 0;
    int can_read = 0, can_write = 0, can_delete = 0, can_manage = 0;
    
    if (json_object_object_get_ex(data_obj, "session_token", &field))
        session_token = json_object_get_string(field);
    if (json_object_object_get_ex(data_obj, "group_id", &field))
        group_id = json_object_get_int(field);
    if (json_object_object_get_ex(data_obj, "target_user_id", &field))
        target_user_id = json_object_get_int(field);
    if (json_object_object_get_ex(data_obj, "can_read", &field))
        can_read = json_object_get_boolean(field);
    if (json_object_object_get_ex(data_obj, "can_write", &field))
        can_write = json_object_get_boolean(field);
    if (json_object_object_get_ex(data_obj, "can_delete", &field))
        can_delete = json_object_get_boolean(field);
    if (json_object_object_get_ex(data_obj, "can_manage", &field))
        can_manage = json_object_get_boolean(field);
    
    if (!session_token || group_id <= 0 || target_user_id <= 0) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing required fields");
        return;
    }
    
    // Verify session
    UserInfo *user = db_verify_session(session_token);
    if (!user) {
        send_error_response(sock, STATUS_UNAUTHORIZED, "ERROR_UNAUTHORIZED", "Invalid session token or session expired");
        return;
    }
    
    // Check if user is admin of the group
    if (!db_is_group_admin(user->user_id, group_id)) {
        free(user);
        send_error_response(sock, STATUS_FORBIDDEN, "ERROR_FORBIDDEN", "You don't have permission to manage permissions");
        return;
    }
    
    // Update permissions
    if (!db_update_permissions(target_user_id, group_id, can_read, can_write, can_delete, can_manage)) {
        free(user);
        send_error_response(sock, STATUS_INTERNAL_ERROR, "ERROR_INTERNAL_SERVER", "Failed to update permissions");
        return;
    }
    
    // Send success response
    struct json_object *response = json_object_new_object();
    json_object_object_add(response, "status", json_object_new_int(STATUS_OK));
    json_object_object_add(response, "code", json_object_new_string("SUCCESS_UPDATE_PERMISSIONS"));
    json_object_object_add(response, "message", json_object_new_string("Permissions updated successfully"));
    
    struct json_object *payload = json_object_new_object();
    json_object_object_add(payload, "user_id", json_object_new_int(target_user_id));
    json_object_object_add(payload, "group_id", json_object_new_int(group_id));
    json_object_object_add(payload, "can_read", json_object_new_boolean(can_read));
    json_object_object_add(payload, "can_write", json_object_new_boolean(can_write));
    json_object_object_add(payload, "can_delete", json_object_new_boolean(can_delete));
    json_object_object_add(payload, "can_manage", json_object_new_boolean(can_manage));
    json_object_object_add(response, "payload", payload);
    
    const char *json_str = json_object_to_json_string(response);
    send(sock, json_str, strlen(json_str), 0);
    
    free(user);
    json_object_put(response);
}
