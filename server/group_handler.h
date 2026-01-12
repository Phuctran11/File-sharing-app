#ifndef GROUP_HANDLER_H
#define GROUP_HANDLER_H

#include <json-c/json.h>

void handle_create_group(int sock, struct json_object *request);
void handle_list_my_groups(int sock, struct json_object *request);
void handle_list_group_members(int sock, struct json_object *request);
void handle_request_join_group(int sock, struct json_object *request);
void handle_list_join_requests(int sock, struct json_object *request);
void handle_approve_join_request(int sock, struct json_object *request);
void handle_invite_to_group(int sock, struct json_object *request);
void handle_list_my_invitations(int sock, struct json_object *request);
void handle_respond_invitation(int sock, struct json_object *request);
void handle_leave_group(int sock, struct json_object *request);
void handle_remove_member(int sock, struct json_object *request);
// Notification handlers
void handle_get_notifications(int sock, struct json_object *request);
void handle_mark_notification_read(int sock, struct json_object *request);
void handle_mark_all_notifications_read(int sock, struct json_object *request);
void handle_get_unread_count(int sock, struct json_object *request);
void handle_list_available_groups(int sock, struct json_object *request);
#endif
