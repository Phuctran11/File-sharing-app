#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <json-c/json.h>
#include "group_handler.h"
#include "database.h"
#include "auth_handler.h"
#include "../common/protocol.h"

void handle_create_group(int sock, struct json_object *request) {
    struct json_object *data_obj, *field;
    
    if (!json_object_object_get_ex(request, "data", &data_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing data field");
        return;
    }
    
    const char *session_token = NULL, *group_name = NULL, *description = NULL;
    
    if (json_object_object_get_ex(data_obj, "session_token", &field))
        session_token = json_object_get_string(field);
    if (json_object_object_get_ex(data_obj, "group_name", &field))
        group_name = json_object_get_string(field);
    if (json_object_object_get_ex(data_obj, "description", &field))
        description = json_object_get_string(field);
    
    if (!session_token || !group_name) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing required fields");
        return;
    }
    
    // Verify session
    UserInfo *user = db_verify_session(session_token);
    if (!user) {
        send_error_response(sock, STATUS_UNAUTHORIZED, "ERROR_UNAUTHORIZED", "Invalid session token or session expired");
        return;
    }
    
    // Create group
    int group_id = db_create_group(user->user_id, group_name, description);
    if (group_id <= 0) {
        free(user);
        send_error_response(sock, STATUS_INTERNAL_ERROR, "ERROR_INTERNAL_SERVER", "Failed to create group");
        return;
    }
    
    // Get current timestamp
    time_t now = time(NULL);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));
    
    // Send success response
    struct json_object *response = json_object_new_object();
    json_object_object_add(response, "status", json_object_new_int(STATUS_CREATED));
    json_object_object_add(response, "code", json_object_new_string("SUCCESS_CREATE_GROUP"));
    json_object_object_add(response, "message", json_object_new_string("Group created successfully"));
    
    struct json_object *payload = json_object_new_object();
    json_object_object_add(payload, "group_id", json_object_new_int(group_id));
    json_object_object_add(payload, "group_name", json_object_new_string(group_name));
    json_object_object_add(payload, "description", json_object_new_string(description ? description : ""));
    json_object_object_add(payload, "owner_id", json_object_new_int(user->user_id));
    json_object_object_add(payload, "created_at", json_object_new_string(timestamp));
    json_object_object_add(response, "payload", payload);
    
    const char *json_str = json_object_to_json_string(response);
    send(sock, json_str, strlen(json_str), 0);
    
    free(user);
    json_object_put(response);
}

void handle_list_my_groups(int sock, struct json_object *request) {
    struct json_object *data_obj, *field;
    
    if (!json_object_object_get_ex(request, "data", &data_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing data field");
        return;
    }
    
    const char *session_token = NULL;
    
    if (json_object_object_get_ex(data_obj, "session_token", &field))
        session_token = json_object_get_string(field);
    
    if (!session_token) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing session_token");
        return;
    }
    
    // Verify session
    UserInfo *user = db_verify_session(session_token);
    if (!user) {
        send_error_response(sock, STATUS_UNAUTHORIZED, "ERROR_UNAUTHORIZED", "Invalid session token or session expired");
        return;
    }
    
    // Get user's groups
    GroupInfo **groups = NULL;
    int count = db_get_user_groups(user->user_id, &groups);
    
    // Send success response
    struct json_object *response = json_object_new_object();
    json_object_object_add(response, "status", json_object_new_int(STATUS_OK));
    json_object_object_add(response, "code", json_object_new_string("SUCCESS_LIST_GROUPS"));
    json_object_object_add(response, "message", json_object_new_string("Groups retrieved successfully"));
    
    struct json_object *payload = json_object_new_object();
    struct json_object *groups_array = json_object_new_array();
    
    for (int i = 0; i < count; i++) {
        struct json_object *group_obj = json_object_new_object();
        json_object_object_add(group_obj, "group_id", json_object_new_int(groups[i]->group_id));
        json_object_object_add(group_obj, "group_name", json_object_new_string(groups[i]->group_name));
        json_object_object_add(group_obj, "description", json_object_new_string(groups[i]->description));
        json_object_object_add(group_obj, "role", json_object_new_string(groups[i]->role));
        json_object_object_add(group_obj, "member_count", json_object_new_int(groups[i]->member_count));
        json_object_object_add(group_obj, "created_at", json_object_new_string(groups[i]->created_at));
        json_object_array_add(groups_array, group_obj);
        free(groups[i]);
    }
    if (groups) free(groups);
    
    json_object_object_add(payload, "groups", groups_array);
    json_object_object_add(response, "payload", payload);
    
    const char *json_str = json_object_to_json_string(response);
    send(sock, json_str, strlen(json_str), 0);
    
    free(user);
    json_object_put(response);
}

void handle_list_group_members(int sock, struct json_object *request) {
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
    
    // Check if user is member of the group
    if (!db_is_group_member(user->user_id, group_id)) {
        free(user);
        send_error_response(sock, STATUS_FORBIDDEN, "ERROR_FORBIDDEN", "You are not a member of this group");
        return;
    }
    
    // Get group members
    MemberInfo **members = NULL;
    int count = db_get_group_members(group_id, &members);
    
    // Send success response
    struct json_object *response = json_object_new_object();
    json_object_object_add(response, "status", json_object_new_int(STATUS_OK));
    json_object_object_add(response, "code", json_object_new_string("SUCCESS_LIST_MEMBERS"));
    json_object_object_add(response, "message", json_object_new_string("Members retrieved successfully"));
    
    struct json_object *payload = json_object_new_object();
    json_object_object_add(payload, "group_id", json_object_new_int(group_id));
    
    struct json_object *members_array = json_object_new_array();
    
    for (int i = 0; i < count; i++) {
        struct json_object *member_obj = json_object_new_object();
        json_object_object_add(member_obj, "user_id", json_object_new_int(members[i]->user_id));
        json_object_object_add(member_obj, "username", json_object_new_string(members[i]->username));
        json_object_object_add(member_obj, "full_name", json_object_new_string(members[i]->full_name));
        json_object_object_add(member_obj, "role", json_object_new_string(members[i]->role));
        json_object_object_add(member_obj, "status", json_object_new_string(members[i]->status));
        json_object_object_add(member_obj, "joined_at", json_object_new_string(members[i]->joined_at));
        json_object_array_add(members_array, member_obj);
        free(members[i]);
    }
    if (members) free(members);
    
    json_object_object_add(payload, "members", members_array);
    json_object_object_add(response, "payload", payload);
    
    const char *json_str = json_object_to_json_string(response);
    send(sock, json_str, strlen(json_str), 0);
    
    free(user);
    json_object_put(response);
}

void handle_request_join_group(int sock, struct json_object *request) {
    struct json_object *data, *token_obj, *group_id_obj;
    
    if (!json_object_object_get_ex(request, "data", &data) ||
        !json_object_object_get_ex(data, "session_token", &token_obj) ||
        !json_object_object_get_ex(data, "group_id", &group_id_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing required fields");
        return;
    }
    
    const char *token = json_object_get_string(token_obj);
    int group_id = json_object_get_int(group_id_obj);
    
    // Verify session
    UserInfo *user = db_verify_session(token);
    if (!user) {
        send_error_response(sock, STATUS_UNAUTHORIZED, "ERROR_UNAUTHORIZED", "Invalid or expired session");
        return;
    }
    
    // Check if already member
    if (db_is_group_member(user->user_id, group_id)) {
        send_error_response(sock, STATUS_CONFLICT, "ERROR_CONFLICT", "Already a member of this group");
        free(user);
        return;
    }
    
    // Send join request
    int request_id = db_request_join_group(user->user_id, group_id);
    if (request_id == -2) {
        send_error_response(sock, STATUS_CONFLICT, "ERROR_CONFLICT", "Already a member");
        free(user);
        return;
    } else if (request_id == -3) {
        send_error_response(sock, STATUS_CONFLICT, "ERROR_CONFLICT", "Join request already pending");
        free(user);
        return;
    } else if (request_id < 0) {
        send_error_response(sock, STATUS_INTERNAL_ERROR, "ERROR_INTERNAL_SERVER", "Failed to create join request");
        free(user);
        return;
    }
    
    // Tạo thông báo cho tất cả admin của group
    int *admin_ids = NULL;
    int admin_count = db_get_group_admin_ids(group_id, &admin_ids);
    
    char *group_name = db_get_group_name_by_id(group_id);
    char *username = db_get_username_by_id(user->user_id);
    char *full_name = user->full_name;
    
    char notif_title[255];
    char notif_message[512];
    snprintf(notif_title, sizeof(notif_title), "New Join Request");
    snprintf(notif_message, sizeof(notif_message), 
            "%s (%s) has requested to join '%s'",
            full_name ? full_name : username,
            username ? username : "Unknown",
            group_name ? group_name : "the group");
    
    for (int i = 0; i < admin_count; i++) {
        db_create_notification(admin_ids[i], "JOIN_REQUEST",
                             notif_title, notif_message, "GROUP", group_id);
    }
    
    if (admin_ids) free(admin_ids);
    if (group_name) free(group_name);
    if (username) free(username);
    
    // Get current time
    time_t now = time(NULL);
    struct tm *tm_info = gmtime(&now);
    char created_at[64];
    strftime(created_at, sizeof(created_at), "%Y-%m-%dT%H:%M:%SZ", tm_info);
    
    struct json_object *response = json_object_new_object();
    json_object_object_add(response, "status", json_object_new_int(STATUS_CREATED));
    json_object_object_add(response, "code", json_object_new_string("SUCCESS_REQUEST_JOIN"));
    json_object_object_add(response, "message", json_object_new_string("Join request sent successfully"));
    
    struct json_object *payload = json_object_new_object();
    json_object_object_add(payload, "request_id", json_object_new_int(request_id));
    json_object_object_add(payload, "group_id", json_object_new_int(group_id));
    json_object_object_add(payload, "user_id", json_object_new_int(user->user_id));
    json_object_object_add(payload, "status", json_object_new_string("pending"));
    json_object_object_add(payload, "created_at", json_object_new_string(created_at));
    json_object_object_add(response, "payload", payload);
    
    const char *json_str = json_object_to_json_string(response);
    send(sock, json_str, strlen(json_str), 0);
    
    free(user);
    json_object_put(response);
}

void handle_list_join_requests(int sock, struct json_object *request) {
    struct json_object *data, *token_obj, *group_id_obj;
    
    if (!json_object_object_get_ex(request, "data", &data) ||
        !json_object_object_get_ex(data, "session_token", &token_obj) ||
        !json_object_object_get_ex(data, "group_id", &group_id_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing required fields");
        return;
    }
    
    const char *token = json_object_get_string(token_obj);
    int group_id = json_object_get_int(group_id_obj);
    
    // Verify session
    UserInfo *user = db_verify_session(token);
    if (!user) {
        send_error_response(sock, STATUS_UNAUTHORIZED, "ERROR_UNAUTHORIZED", "Invalid or expired session");
        return;
    }
    
    // Check if user is admin
    if (!db_is_group_admin(user->user_id, group_id)) {
        send_error_response(sock, STATUS_FORBIDDEN, "ERROR_FORBIDDEN", "Only admins can view join requests");
        free(user);
        return;
    }
    
    // Get join requests
    JoinRequestInfo **requests = NULL;
    int count = db_get_join_requests(group_id, &requests);
    
    struct json_object *response = json_object_new_object();
    json_object_object_add(response, "status", json_object_new_int(STATUS_OK));
    json_object_object_add(response, "code", json_object_new_string("SUCCESS_LIST_REQUESTS"));
    json_object_object_add(response, "message", json_object_new_string("Join requests retrieved successfully"));
    
    struct json_object *payload = json_object_new_object();
    json_object_object_add(payload, "group_id", json_object_new_int(group_id));
    
    struct json_object *requests_array = json_object_new_array();
    for (int i = 0; i < count; i++) {
        struct json_object *req_obj = json_object_new_object();
        json_object_object_add(req_obj, "request_id", json_object_new_int(requests[i]->request_id));
        json_object_object_add(req_obj, "user_id", json_object_new_int(requests[i]->user_id));
        json_object_object_add(req_obj, "username", json_object_new_string(requests[i]->username));
        json_object_object_add(req_obj, "full_name", json_object_new_string(requests[i]->full_name));
        json_object_object_add(req_obj, "status", json_object_new_string(requests[i]->status));
        json_object_object_add(req_obj, "created_at", json_object_new_string(requests[i]->created_at));
        json_object_array_add(requests_array, req_obj);
        free(requests[i]);
    }
    if (requests) free(requests);
    
    json_object_object_add(payload, "requests", requests_array);
    json_object_object_add(response, "payload", payload);
    
    const char *json_str = json_object_to_json_string(response);
    send(sock, json_str, strlen(json_str), 0);
    
    free(user);
    json_object_put(response);
}

void handle_approve_join_request(int sock, struct json_object *request) {
    struct json_object *data, *token_obj, *request_id_obj, *action_obj;
    
    if (!json_object_object_get_ex(request, "data", &data) ||
        !json_object_object_get_ex(data, "session_token", &token_obj) ||
        !json_object_object_get_ex(data, "request_id", &request_id_obj) ||
        !json_object_object_get_ex(data, "action", &action_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing required fields");
        return;
    }
    
    const char *token = json_object_get_string(token_obj);
    int request_id = json_object_get_int(request_id_obj);
    const char *action = json_object_get_string(action_obj);
    
    // Verify session
    UserInfo *user = db_verify_session(token);
    if (!user) {
        send_error_response(sock, STATUS_UNAUTHORIZED, "ERROR_UNAUTHORIZED", "Invalid or expired session");
        return;
    }
    
    // Get request info to check group
    JoinRequestInfo *req_info = db_get_join_request_by_id(request_id);
    if (!req_info) {
        send_error_response(sock, STATUS_NOT_FOUND, "ERROR_NOT_FOUND", "Join request not found");
        free(user);
        return;
    }
    
    // Check if user is admin
    if (!db_is_group_admin(user->user_id, req_info->group_id)) {
        send_error_response(sock, STATUS_FORBIDDEN, "ERROR_FORBIDDEN", "Only admins can approve/reject requests");
        free(user);
        free(req_info);
        return;
    }
    
    // Approve or reject
    if (db_approve_join_request(request_id, user->user_id, action) < 0) {
        send_error_response(sock, STATUS_INTERNAL_ERROR, "ERROR_INTERNAL_SERVER", "Failed to process request");
        free(user);
        free(req_info);
        return;
    }

    // Tạo thông báo cho người gửi request
    char *group_name = db_get_group_name_by_id(req_info->group_id);
    char *admin_username = db_get_username_by_id(user->user_id);
    
    char notif_title[255];
    char notif_message[512];
    
    if (strcmp(action, "approve") == 0) {
        snprintf(notif_title, sizeof(notif_title), "Join Request Approved");
        snprintf(notif_message, sizeof(notif_message), 
                "Your request to join '%s' has been approved by %s", 
                group_name ? group_name : "Unknown", 
                admin_username ? admin_username : "Admin");
    } else {
        snprintf(notif_title, sizeof(notif_title), "Join Request Rejected");
        snprintf(notif_message, sizeof(notif_message), 
                "Your request to join '%s' has been rejected by %s", 
                group_name ? group_name : "Unknown", 
                admin_username ? admin_username : "Admin");
    }
    
    db_create_notification(req_info->user_id, "JOIN_REQUEST_RESPONSE", 
                          notif_title, notif_message, "GROUP", req_info->group_id);
    
    if (group_name) free(group_name);
    if (admin_username) free(admin_username);
    
    // Get current time
    time_t now = time(NULL);
    struct tm *tm_info = gmtime(&now);
    char reviewed_at[64];
    strftime(reviewed_at, sizeof(reviewed_at), "%Y-%m-%dT%H:%M:%SZ", tm_info);
    
    struct json_object *response = json_object_new_object();
    json_object_object_add(response, "status", json_object_new_int(STATUS_OK));
    json_object_object_add(response, "code", json_object_new_string(
        strcmp(action, "approve") == 0 ? "SUCCESS_APPROVE_REQUEST" : "SUCCESS_REJECT_REQUEST"));
    json_object_object_add(response, "message", json_object_new_string(
        strcmp(action, "approve") == 0 ? "Join request approved successfully" : "Join request rejected successfully"));
    
    struct json_object *payload = json_object_new_object();
    json_object_object_add(payload, "request_id", json_object_new_int(request_id));
    json_object_object_add(payload, "user_id", json_object_new_int(req_info->user_id));
    json_object_object_add(payload, "group_id", json_object_new_int(req_info->group_id));
    json_object_object_add(payload, "status", json_object_new_string(
        strcmp(action, "approve") == 0 ? "approved" : "rejected"));
    json_object_object_add(payload, "reviewed_at", json_object_new_string(reviewed_at));
    json_object_object_add(response, "payload", payload);
    
    const char *json_str = json_object_to_json_string(response);
    send(sock, json_str, strlen(json_str), 0);
    
    free(user);
    free(req_info);
    json_object_put(response);
}

void handle_invite_to_group(int sock, struct json_object *request) {
    struct json_object *data, *token_obj, *group_id_obj, *invitee_username_obj;
    
    if (!json_object_object_get_ex(request, "data", &data) ||
        !json_object_object_get_ex(data, "session_token", &token_obj) ||
        !json_object_object_get_ex(data, "group_id", &group_id_obj) ||
        !json_object_object_get_ex(data, "invitee_username", &invitee_username_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing required fields");
        return;
    }
    
    const char *token = json_object_get_string(token_obj);
    int group_id = json_object_get_int(group_id_obj);
    const char *invitee_username = json_object_get_string(invitee_username_obj);
    
    // Verify session
    UserInfo *user = db_verify_session(token);
    if (!user) {
        send_error_response(sock, STATUS_UNAUTHORIZED, "ERROR_UNAUTHORIZED", "Invalid or expired session");
        return;
    }
    
    // Check if user is admin or has manage permission
    if (!db_is_group_admin(user->user_id, group_id)) {
        send_error_response(sock, STATUS_FORBIDDEN, "ERROR_FORBIDDEN", "Only admins can invite members");
        free(user);
        return;
    }
    
    // Get invitee info
    UserInfo *invitee = db_get_user_by_username(invitee_username);
    if (!invitee) {
        send_error_response(sock, STATUS_NOT_FOUND, "ERROR_NOT_FOUND", "User not found");
        free(user);
        return;
    }
    
    // Send invitation
    int invitation_id = db_invite_to_group(user->user_id, group_id, invitee_username);
    if (invitation_id == -2) {
        send_error_response(sock, STATUS_NOT_FOUND, "ERROR_NOT_FOUND", "User not found");
        free(user);
        free(invitee);
        return;
    } else if (invitation_id == -3) {
        send_error_response(sock, STATUS_CONFLICT, "ERROR_CONFLICT", "User is already a member");
        free(user);
        free(invitee);
        return;
    } else if (invitation_id == -4) {
        send_error_response(sock, STATUS_CONFLICT, "ERROR_CONFLICT", "Invitation already pending");
        free(user);
        free(invitee);
        return;
    } else if (invitation_id < 0) {
        send_error_response(sock, STATUS_INTERNAL_ERROR, "ERROR_INTERNAL_SERVER", "Failed to send invitation");
        free(user);
        free(invitee);
        return;
    }
    
    // Tạo thông báo cho người được mời
    char *group_name = db_get_group_name_by_id(group_id);
    char *inviter_username = db_get_username_by_id(user->user_id);
    
    char notif_title[255];
    char notif_message[512];
    snprintf(notif_title, sizeof(notif_title), "Group Invitation");
    snprintf(notif_message, sizeof(notif_message), 
            "%s has invited you to join '%s'",
            inviter_username ? inviter_username : "An admin",
            group_name ? group_name : "a group");
    
    db_create_notification(invitee->user_id, "GROUP_INVITATION",
                          notif_title, notif_message, "GROUP", group_id);
    
    if (group_name) free(group_name);
    if (inviter_username) free(inviter_username);
    
    // Get current time
    time_t now = time(NULL);
    struct tm *tm_info = gmtime(&now);
    char created_at[64];
    strftime(created_at, sizeof(created_at), "%Y-%m-%dT%H:%M:%SZ", tm_info);
    
    struct json_object *response = json_object_new_object();
    json_object_object_add(response, "status", json_object_new_int(STATUS_CREATED));
    json_object_object_add(response, "code", json_object_new_string("SUCCESS_SEND_INVITATION"));
    json_object_object_add(response, "message", json_object_new_string("Invitation sent successfully"));
    
    struct json_object *payload = json_object_new_object();
    json_object_object_add(payload, "invitation_id", json_object_new_int(invitation_id));
    json_object_object_add(payload, "group_id", json_object_new_int(group_id));
    json_object_object_add(payload, "inviter_id", json_object_new_int(user->user_id));
    json_object_object_add(payload, "invitee_id", json_object_new_int(invitee->user_id));
    json_object_object_add(payload, "status", json_object_new_string("pending"));
    json_object_object_add(payload, "created_at", json_object_new_string(created_at));
    json_object_object_add(response, "payload", payload);
    
    const char *json_str = json_object_to_json_string(response);
    send(sock, json_str, strlen(json_str), 0);
    
    free(user);
    free(invitee);
    json_object_put(response);
}

void handle_list_my_invitations(int sock, struct json_object *request) {
    struct json_object *data, *token_obj;
    
    if (!json_object_object_get_ex(request, "data", &data) ||
        !json_object_object_get_ex(data, "session_token", &token_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing required fields");
        return;
    }
    
    const char *token = json_object_get_string(token_obj);
    
    // Verify session
    UserInfo *user = db_verify_session(token);
    if (!user) {
        send_error_response(sock, STATUS_UNAUTHORIZED, "ERROR_UNAUTHORIZED", "Invalid or expired session");
        return;
    }
    
    // Get invitations
    InvitationInfo **invitations = NULL;
    int count = db_get_user_invitations(user->user_id, &invitations);
    
    struct json_object *response = json_object_new_object();
    json_object_object_add(response, "status", json_object_new_int(STATUS_OK));
    json_object_object_add(response, "code", json_object_new_string("SUCCESS_LIST_INVITATIONS"));
    json_object_object_add(response, "message", json_object_new_string("Invitations retrieved successfully"));
    
    struct json_object *payload = json_object_new_object();
    struct json_object *invitations_array = json_object_new_array();
    
    for (int i = 0; i < count; i++) {
        struct json_object *inv_obj = json_object_new_object();
        json_object_object_add(inv_obj, "invitation_id", json_object_new_int(invitations[i]->invitation_id));
        json_object_object_add(inv_obj, "group_id", json_object_new_int(invitations[i]->group_id));
        json_object_object_add(inv_obj, "group_name", json_object_new_string(invitations[i]->group_name));
        json_object_object_add(inv_obj, "inviter_username", json_object_new_string(invitations[i]->inviter_username));
        json_object_object_add(inv_obj, "inviter_name", json_object_new_string(invitations[i]->inviter_name));
        json_object_object_add(inv_obj, "status", json_object_new_string(invitations[i]->status));
        json_object_object_add(inv_obj, "created_at", json_object_new_string(invitations[i]->created_at));
        json_object_array_add(invitations_array, inv_obj);
        free(invitations[i]);
    }
    if (invitations) free(invitations);
    
    json_object_object_add(payload, "invitations", invitations_array);
    json_object_object_add(response, "payload", payload);
    
    const char *json_str = json_object_to_json_string(response);
    send(sock, json_str, strlen(json_str), 0);
    
    free(user);
    json_object_put(response);
}

void handle_respond_invitation(int sock, struct json_object *request) {
    struct json_object *data, *token_obj, *invitation_id_obj, *action_obj;
    
    if (!json_object_object_get_ex(request, "data", &data) ||
        !json_object_object_get_ex(data, "session_token", &token_obj) ||
        !json_object_object_get_ex(data, "invitation_id", &invitation_id_obj) ||
        !json_object_object_get_ex(data, "action", &action_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing required fields");
        return;
    }
    
    const char *token = json_object_get_string(token_obj);
    int invitation_id = json_object_get_int(invitation_id_obj);
    const char *action = json_object_get_string(action_obj);
    
    // Verify session
    UserInfo *user = db_verify_session(token);
    if (!user) {
        send_error_response(sock, STATUS_UNAUTHORIZED, "ERROR_UNAUTHORIZED", "Invalid or expired session");
        return;
    }
    
    // Get invitation info
    InvitationInfo *inv_info = db_get_invitation_by_id(invitation_id);
    if (!inv_info) {
        send_error_response(sock, STATUS_NOT_FOUND, "ERROR_NOT_FOUND", "Invitation not found");
        free(user);
        return;
    }
    
    // Check if user is the invitee
    if (inv_info->invitee_id != user->user_id) {
        send_error_response(sock, STATUS_FORBIDDEN, "ERROR_FORBIDDEN", "You can only respond to your own invitations");
        free(user);
        free(inv_info);
        return;
    }
    
    // Respond to invitation
    if (db_respond_invitation(invitation_id, action) < 0) {
        send_error_response(sock, STATUS_INTERNAL_ERROR, "ERROR_INTERNAL_SERVER", "Failed to respond to invitation");
        free(user);
        free(inv_info);
        return;
    }

    // Nếu accept -> Gửi thông báo cho admin
    if (strcmp(action, "accept") == 0) {
        int *admin_ids = NULL;
        int admin_count = db_get_group_admin_ids(inv_info->group_id, &admin_ids);
        
        char *group_name = db_get_group_name_by_id(inv_info->group_id);
        char *username = db_get_username_by_id(user->user_id);
        
        char notif_title[255];
        char notif_message[512];
        snprintf(notif_title, sizeof(notif_title), "Invitation Accepted");
        snprintf(notif_message, sizeof(notif_message), 
                "%s has accepted the invitation to join '%s'",
                username ? username : "A user",
                group_name ? group_name : "the group");
        
        for (int i = 0; i < admin_count; i++) {
            db_create_notification(admin_ids[i], "INVITATION_ACCEPTED",
                                 notif_title, notif_message, "GROUP", inv_info->group_id);
        }
        
        if (admin_ids) free(admin_ids);
        if (group_name) free(group_name);
        if (username) free(username);
    }
    
    // Get current time
    time_t now = time(NULL);
    struct tm *tm_info = gmtime(&now);
    char responded_at[64];
    strftime(responded_at, sizeof(responded_at), "%Y-%m-%dT%H:%M:%SZ", tm_info);
    
    struct json_object *response = json_object_new_object();
    json_object_object_add(response, "status", json_object_new_int(STATUS_OK));
    json_object_object_add(response, "code", json_object_new_string(
        strcmp(action, "accept") == 0 ? "SUCCESS_ACCEPT_INVITATION" : "SUCCESS_REJECT_INVITATION"));
    json_object_object_add(response, "message", json_object_new_string(
        strcmp(action, "accept") == 0 ? "Invitation accepted successfully" : "Invitation rejected successfully"));
    
    struct json_object *payload = json_object_new_object();
    json_object_object_add(payload, "invitation_id", json_object_new_int(invitation_id));
    json_object_object_add(payload, "group_id", json_object_new_int(inv_info->group_id));
    json_object_object_add(payload, "status", json_object_new_string(
        strcmp(action, "accept") == 0 ? "accepted" : "rejected"));
    json_object_object_add(payload, "responded_at", json_object_new_string(responded_at));
    json_object_object_add(response, "payload", payload);
    
    const char *json_str = json_object_to_json_string(response);
    send(sock, json_str, strlen(json_str), 0);
    
    free(user);
    free(inv_info);
    json_object_put(response);
}

void handle_leave_group(int sock, struct json_object *request) {
    struct json_object *data, *token_obj, *group_id_obj;
    
    if (!json_object_object_get_ex(request, "data", &data) ||
        !json_object_object_get_ex(data, "session_token", &token_obj) ||
        !json_object_object_get_ex(data, "group_id", &group_id_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing required fields");
        return;
    }
    
    const char *token = json_object_get_string(token_obj);
    int group_id = json_object_get_int(group_id_obj);
    
    // Verify session
    UserInfo *user = db_verify_session(token);
    if (!user) {
        send_error_response(sock, STATUS_UNAUTHORIZED, "ERROR_UNAUTHORIZED", "Invalid or expired session");
        return;
    }
    
    // Check if user is a member
    if (!db_is_group_member(user->user_id, group_id)) {
        send_error_response(sock, STATUS_NOT_FOUND, "ERROR_NOT_FOUND", "You are not a member of this group");
        free(user);
        return;
    }
    
    // Leave group
    if (db_leave_group(user->user_id, group_id) < 0) {
        send_error_response(sock, STATUS_INTERNAL_ERROR, "ERROR_INTERNAL_SERVER", "Failed to leave group");
        free(user);
        return;
    }

    // Gửi thông báo cho admin
    int *admin_ids = NULL;
    int admin_count = db_get_group_admin_ids(group_id, &admin_ids);
    
    char *group_name = db_get_group_name_by_id(group_id);
    char *username = db_get_username_by_id(user->user_id);
    
    char notif_title[255];
    char notif_message[512];
    snprintf(notif_title, sizeof(notif_title), "Member Left Group");
    snprintf(notif_message, sizeof(notif_message), 
            "%s has left the group '%s'",
            username ? username : "A member",
            group_name ? group_name : "Unknown");
    
    for (int i = 0; i < admin_count; i++) {
        db_create_notification(admin_ids[i], "MEMBER_LEFT",
                             notif_title, notif_message, "GROUP", group_id);
    }
    
    if (admin_ids) free(admin_ids);
    if (group_name) free(group_name);
    if (username) free(username);
    
    // Get current time
    time_t now = time(NULL);
    struct tm *tm_info = gmtime(&now);
    char left_at[64];
    strftime(left_at, sizeof(left_at), "%Y-%m-%dT%H:%M:%SZ", tm_info);
    
    struct json_object *response = json_object_new_object();
    json_object_object_add(response, "status", json_object_new_int(STATUS_OK));
    json_object_object_add(response, "code", json_object_new_string("SUCCESS_LEAVE_GROUP"));
    json_object_object_add(response, "message", json_object_new_string("Left group successfully"));
    
    struct json_object *payload = json_object_new_object();
    json_object_object_add(payload, "group_id", json_object_new_int(group_id));
    json_object_object_add(payload, "user_id", json_object_new_int(user->user_id));
    json_object_object_add(payload, "left_at", json_object_new_string(left_at));
    json_object_object_add(response, "payload", payload);
    
    const char *json_str = json_object_to_json_string(response);
    send(sock, json_str, strlen(json_str), 0);
    
    free(user);
    json_object_put(response);
}

void handle_remove_member(int sock, struct json_object *request) {
    struct json_object *data, *token_obj, *group_id_obj, *target_user_id_obj;
    
    if (!json_object_object_get_ex(request, "data", &data) ||
        !json_object_object_get_ex(data, "session_token", &token_obj) ||
        !json_object_object_get_ex(data, "group_id", &group_id_obj) ||
        !json_object_object_get_ex(data, "target_user_id", &target_user_id_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing required fields");
        return;
    }
    
    const char *token = json_object_get_string(token_obj);
    int group_id = json_object_get_int(group_id_obj);
    int target_user_id = json_object_get_int(target_user_id_obj);
    
    // Verify session
    UserInfo *user = db_verify_session(token);
    if (!user) {
        send_error_response(sock, STATUS_UNAUTHORIZED, "ERROR_UNAUTHORIZED", "Invalid or expired session");
        return;
    }
    
    // Check if user is admin
    if (!db_is_group_admin(user->user_id, group_id)) {
        send_error_response(sock, STATUS_FORBIDDEN, "ERROR_FORBIDDEN", "Only admins can remove members");
        free(user);
        return;
    }
    
    // Check if target is a member
    if (!db_is_group_member(target_user_id, group_id)) {
        send_error_response(sock, STATUS_NOT_FOUND, "ERROR_NOT_FOUND", "User is not a member of this group");
        free(user);
        return;
    }
    
    // Remove member
    if (db_remove_member(group_id, target_user_id) < 0) {
        send_error_response(sock, STATUS_INTERNAL_ERROR, "ERROR_INTERNAL_SERVER", "Failed to remove member");
        free(user);
        return;
    }

    // Gửi thông báo cho người bị xóa
    char *group_name = db_get_group_name_by_id(group_id);
    char *admin_username = db_get_username_by_id(user->user_id);
    
    char notif_title[255];
    char notif_message[512];
    snprintf(notif_title, sizeof(notif_title), "Removed from Group");
    snprintf(notif_message, sizeof(notif_message), 
            "You have been removed from '%s' by %s",
            group_name ? group_name : "the group",
            admin_username ? admin_username : "an admin");
    
    db_create_notification(target_user_id, "REMOVED_FROM_GROUP",
                          notif_title, notif_message, "GROUP", group_id);
    
    if (group_name) free(group_name);
    if (admin_username) free(admin_username);
    
    // Get current time
    time_t now = time(NULL);
    struct tm *tm_info = gmtime(&now);
    char removed_at[64];
    strftime(removed_at, sizeof(removed_at), "%Y-%m-%dT%H:%M:%SZ", tm_info);
    
    struct json_object *response = json_object_new_object();
    json_object_object_add(response, "status", json_object_new_int(STATUS_OK));
    json_object_object_add(response, "code", json_object_new_string("SUCCESS_REMOVE_MEMBER"));
    json_object_object_add(response, "message", json_object_new_string("Member removed successfully"));
    
    struct json_object *payload = json_object_new_object();
    json_object_object_add(payload, "group_id", json_object_new_int(group_id));
    json_object_object_add(payload, "removed_user_id", json_object_new_int(target_user_id));
    json_object_object_add(payload, "removed_at", json_object_new_string(removed_at));
    json_object_object_add(response, "payload", payload);
    
    const char *json_str = json_object_to_json_string(response);
    send(sock, json_str, strlen(json_str), 0);
    
    free(user);
    json_object_put(response);
}
// Thêm handler mới cho notifications
void handle_get_notifications(int sock, struct json_object *request) {
    struct json_object *data, *token_obj;
    
    if (!json_object_object_get_ex(request, "data", &data) ||
        !json_object_object_get_ex(data, "session_token", &token_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing required fields");
        return;
    }
    
    const char *token = json_object_get_string(token_obj);
    
    // Verify session
    UserInfo *user = db_verify_session(token);
    if (!user) {
        send_error_response(sock, STATUS_UNAUTHORIZED, "ERROR_UNAUTHORIZED", "Invalid or expired session");
        return;
    }
    
    // Get notifications
    NotificationInfo **notifications = NULL;
    int count = db_get_user_notifications(user->user_id, &notifications);
    
    struct json_object *response = json_object_new_object();
    json_object_object_add(response, "status", json_object_new_int(STATUS_OK));
    json_object_object_add(response, "code", json_object_new_string("SUCCESS_GET_NOTIFICATIONS"));
    json_object_object_add(response, "message", json_object_new_string("Notifications retrieved successfully"));
    
    struct json_object *payload = json_object_new_object();
    struct json_object *notif_array = json_object_new_array();
    
    for (int i = 0; i < count; i++) {
        struct json_object *notif_obj = json_object_new_object();
        json_object_object_add(notif_obj, "notification_id", json_object_new_int(notifications[i]->notification_id));
        json_object_object_add(notif_obj, "type", json_object_new_string(notifications[i]->type));
        json_object_object_add(notif_obj, "title", json_object_new_string(notifications[i]->title));
        json_object_object_add(notif_obj, "message", json_object_new_string(notifications[i]->message));
        json_object_object_add(notif_obj, "related_type", json_object_new_string(notifications[i]->related_type));
        json_object_object_add(notif_obj, "related_id", json_object_new_int(notifications[i]->related_id));
        json_object_object_add(notif_obj, "is_read", json_object_new_boolean(notifications[i]->is_read));
        json_object_object_add(notif_obj, "created_at", json_object_new_string(notifications[i]->created_at));
        json_object_array_add(notif_array, notif_obj);
        free(notifications[i]);
    }
    if (notifications) free(notifications);
    
    json_object_object_add(payload, "notifications", notif_array);
    json_object_object_add(payload, "total_count", json_object_new_int(count));
    json_object_object_add(response, "payload", payload);
    
    const char *json_str = json_object_to_json_string(response);
    send(sock, json_str, strlen(json_str), 0);
    
    free(user);
    json_object_put(response);
}

void handle_mark_notification_read(int sock, struct json_object *request) {
    struct json_object *data, *token_obj, *notif_id_obj;
    
    if (!json_object_object_get_ex(request, "data", &data) ||
        !json_object_object_get_ex(data, "session_token", &token_obj) ||
        !json_object_object_get_ex(data, "notification_id", &notif_id_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing required fields");
        return;
    }
    
    const char *token = json_object_get_string(token_obj);
    int notification_id = json_object_get_int(notif_id_obj);
    
    // Verify session
    UserInfo *user = db_verify_session(token);
    if (!user) {
        send_error_response(sock, STATUS_UNAUTHORIZED, "ERROR_UNAUTHORIZED", "Invalid or expired session");
        return;
    }
    
    // Mark as read
    if (db_mark_notification_read(user->user_id, notification_id) < 0) {
        send_error_response(sock, STATUS_INTERNAL_ERROR, "ERROR_INTERNAL_SERVER", "Failed to mark as read");
        free(user);
        return;
    }
    
    struct json_object *response = json_object_new_object();
    json_object_object_add(response, "status", json_object_new_int(STATUS_OK));
    json_object_object_add(response, "code", json_object_new_string("SUCCESS_MARK_READ"));
    json_object_object_add(response, "message", json_object_new_string("Notification marked as read"));
    
    struct json_object *payload = json_object_new_object();
    json_object_object_add(payload, "notification_id", json_object_new_int(notification_id));
    json_object_object_add(response, "payload", payload);
    
    const char *json_str = json_object_to_json_string(response);
    send(sock, json_str, strlen(json_str), 0);
    
    free(user);
    json_object_put(response);
}

void handle_mark_all_notifications_read(int sock, struct json_object *request) {
    struct json_object *data, *token_obj;
    
    if (!json_object_object_get_ex(request, "data", &data) ||
        !json_object_object_get_ex(data, "session_token", &token_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing required fields");
        return;
    }
    
    const char *token = json_object_get_string(token_obj);
    
    // Verify session
    UserInfo *user = db_verify_session(token);
    if (!user) {
        send_error_response(sock, STATUS_UNAUTHORIZED, "ERROR_UNAUTHORIZED", "Invalid or expired session");
        return;
    }
    
    // Mark all as read
    if (db_mark_all_notifications_read(user->user_id) < 0) {
        send_error_response(sock, STATUS_INTERNAL_ERROR, "ERROR_INTERNAL_SERVER", "Failed to mark all as read");
        free(user);
        return;
    }
    
    struct json_object *response = json_object_new_object();
    json_object_object_add(response, "status", json_object_new_int(STATUS_OK));
    json_object_object_add(response, "code", json_object_new_string("SUCCESS_MARK_ALL_READ"));
    json_object_object_add(response, "message", json_object_new_string("All notifications marked as read"));
    
    struct json_object *payload = json_object_new_object();
    json_object_object_add(response, "payload", payload);
    
    const char *json_str = json_object_to_json_string(response);
    send(sock, json_str, strlen(json_str), 0);
    
    free(user);
    json_object_put(response);
}

void handle_get_unread_count(int sock, struct json_object *request) {
    struct json_object *data, *token_obj;
    
    if (!json_object_object_get_ex(request, "data", &data) ||
        !json_object_object_get_ex(data, "session_token", &token_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing required fields");
        return;
    }
    
    const char *token = json_object_get_string(token_obj);
    
    // Verify session
    UserInfo *user = db_verify_session(token);
    if (!user) {
        send_error_response(sock, STATUS_UNAUTHORIZED, "ERROR_UNAUTHORIZED", "Invalid or expired session");
        return;
    }
    
    // Get unread count
    int count = db_get_unread_notification_count(user->user_id);
    
    struct json_object *response = json_object_new_object();
    json_object_object_add(response, "status", json_object_new_int(STATUS_OK));
    json_object_object_add(response, "code", json_object_new_string("SUCCESS_GET_UNREAD_COUNT"));
    json_object_object_add(response, "message", json_object_new_string("Unread count retrieved"));
    
    struct json_object *payload = json_object_new_object();
    json_object_object_add(payload, "unread_count", json_object_new_int(count));
    json_object_object_add(response, "payload", payload);
    
    const char *json_str = json_object_to_json_string(response);
    send(sock, json_str, strlen(json_str), 0);
    
    free(user);
    json_object_put(response);
}

void handle_list_available_groups(int sock, struct json_object *request) {
    struct json_object *data_obj, *field;
    
    if (!json_object_object_get_ex(request, "data", &data_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing data field");
        return;
    }
    
    const char *session_token = NULL;
    
    if (json_object_object_get_ex(data_obj, "session_token", &field))
        session_token = json_object_get_string(field);
    
    if (!session_token) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing session_token");
        return;
    }
    
    // Verify session
    UserInfo *user = db_verify_session(session_token);
    if (!user) {
        send_error_response(sock, STATUS_UNAUTHORIZED, "ERROR_UNAUTHORIZED", "Invalid session token or session expired");
        return;
    }
    
    // Get available groups
    GroupInfo **groups = NULL;
    int count = db_get_available_groups(user->user_id, &groups);
    
    // Send success response
    struct json_object *response = json_object_new_object();
    json_object_object_add(response, "status", json_object_new_int(STATUS_OK));
    json_object_object_add(response, "code", json_object_new_string("SUCCESS_LIST_AVAILABLE_GROUPS"));
    json_object_object_add(response, "message", json_object_new_string("Available groups retrieved successfully"));
    
    struct json_object *payload = json_object_new_object();
    struct json_object *groups_array = json_object_new_array();
    
    for (int i = 0; i < count; i++) {
        struct json_object *group_obj = json_object_new_object();
        json_object_object_add(group_obj, "group_id", json_object_new_int(groups[i]->group_id));
        json_object_object_add(group_obj, "group_name", json_object_new_string(groups[i]->group_name));
        json_object_object_add(group_obj, "description", json_object_new_string(groups[i]->description));
        json_object_object_add(group_obj, "member_count", json_object_new_int(groups[i]->member_count));
        json_object_object_add(group_obj, "created_at", json_object_new_string(groups[i]->created_at));
        json_object_array_add(groups_array, group_obj);
        free(groups[i]);
    }
    if (groups) free(groups);
    
    json_object_object_add(payload, "groups", groups_array);
    json_object_object_add(payload, "total_count", json_object_new_int(count));
    json_object_object_add(response, "payload", payload);
    
    const char *json_str = json_object_to_json_string(response);
    send(sock, json_str, strlen(json_str), 0);
    
    free(user);
    json_object_put(response);
}
