#ifndef DATABASE_H
#define DATABASE_H

#include <time.h>

typedef struct {
    int user_id;
    char username[51];
    char role[21];
    char email[101];
    char full_name[101];
} UserInfo;

typedef struct {
    int permission_id;
    int user_id;
    int group_id;
    int can_read;
    int can_write;
    int can_delete;
    int can_manage;
} PermissionInfo;

typedef struct {
    int group_id;
    char group_name[101];
    char description[256];
    char role[21];
    int member_count;
    char created_at[64];
} GroupInfo;

typedef struct {
    int user_id;
    char username[51];
    char full_name[101];
    char role[21];
    char status[21];
    char joined_at[64];
} MemberInfo;

typedef struct {
    int request_id;
    int group_id;
    int user_id;
    char username[51];
    char full_name[101];
    char status[21];
    char created_at[64];
} JoinRequestInfo;

typedef struct {
    int invitation_id;
    int group_id;
    char group_name[101];
    int inviter_id;
    char inviter_username[51];
    char inviter_name[101];
    int invitee_id;
    char status[21];
    char created_at[64];
} InvitationInfo;

typedef struct {
    int directory_id;
    char directory_name[256];
    char directory_path[512];
    int group_id;
    char created_by[51];
    char created_at[64];
} DirectoryInfo;

typedef struct {
    int file_id;
    int group_id;
    char file_name[256];
    char file_path[512];
    long long file_size;
    char file_type[51];
    int uploaded_by;
    char uploaded_at[64];
    char parent_directory[512];
} FileInfo;

// Notification types
typedef struct {
    int notification_id;
    int user_id;
    char type[50];
    char title[255];
    char message[512];
    char related_type[50];
    int related_id;
    int is_read;
    char created_at[64];
} NotificationInfo;

int init_database();
void cleanup_database();
int db_create_user(const char *username, const char *password_hash, const char *email, const char *full_name);
UserInfo* db_verify_user(const char *username, const char *password_hash);
int db_create_session(int user_id, const char *session_token, const char *ip_address, time_t expires_at);
int db_update_last_login(int user_id);
UserInfo* db_verify_session(const char *session_token);
int db_invalidate_session(const char *session_token);
int db_update_profile(int user_id, const char *email, const char *full_name);
UserInfo* db_get_user_by_id(int user_id);
int db_change_password(int user_id, const char *new_password_hash);
PermissionInfo* db_get_permissions(int user_id, int group_id);
int db_update_permissions(int user_id, int group_id, int can_read, int can_write, int can_delete, int can_manage);
int db_is_group_admin(int user_id, int group_id);
int db_create_group(int owner_id, const char *group_name, const char *description);
int db_get_user_groups(int user_id, GroupInfo ***groups);
int db_is_group_member(int user_id, int group_id);
int db_get_group_members(int group_id, MemberInfo ***members);
int db_request_join_group(int user_id, int group_id);
int db_get_join_requests(int group_id, JoinRequestInfo ***requests);
int db_approve_join_request(int request_id, int reviewer_id, const char *action);
JoinRequestInfo* db_get_join_request_by_id(int request_id);
int db_invite_to_group(int inviter_id, int group_id, const char *invitee_username);
int db_get_user_invitations(int user_id, InvitationInfo ***invitations);
InvitationInfo* db_get_invitation_by_id(int invitation_id);
int db_respond_invitation(int invitation_id, const char *action);
int db_leave_group(int user_id, int group_id);
int db_remove_member(int group_id, int target_user_id);
UserInfo* db_get_user_by_username(const char *username);
int db_create_directory(int group_id, const char *directory_name, const char *parent_path, int created_by_user_id);
DirectoryInfo* db_get_directory_by_id(int directory_id);
int db_rename_directory(int directory_id, const char *new_name);
int db_delete_directory(int directory_id, int *deleted_files, int *deleted_subdirs);
int db_copy_directory(int directory_id, const char *destination_path, int user_id);
int db_move_directory(int directory_id, const char *destination_path, int *affected_files, int *affected_subdirs);
int db_list_directories(int group_id, const char *parent_path, DirectoryInfo ***directories);
int db_list_files(int group_id, const char *parent_directory, FileInfo ***files);

// File functions
int db_create_file(int group_id, const char *file_name, const char *file_path, 
                   long long file_size, const char *file_type, 
                   const char *parent_directory, int uploaded_by);
FileInfo* db_get_file_by_id(int file_id);
int db_delete_file(int file_id);
int db_rename_file(int file_id, const char *new_name);
int db_move_file(int file_id, const char *new_path);
int db_copy_file(int file_id, const char *destination_path, int user_id);

// Notification functions
int db_create_notification(int user_id, const char *type, const char *title, 
                          const char *message, const char *related_type, 
                          int related_id);
int db_get_user_notifications(int user_id, NotificationInfo ***notifications);
int db_mark_notification_read(int user_id, int notification_id);
int db_mark_all_notifications_read(int user_id);
int db_get_unread_notification_count(int user_id);

// Helper functions
char* db_get_group_name_by_id(int group_id);
char* db_get_username_by_id(int user_id);
int db_get_group_admin_ids(int group_id, int **admin_ids);

int db_get_available_groups(int user_id, GroupInfo ***groups);
#endif
