/*
 * ============================================================================
 * FILE SHARING CLIENT - MAIN SOURCE FILE
 * ============================================================================
 * Ứng dụng client cho hệ thống chia sẻ file
 * Kết nối tới server qua TCP/IP, giao tiếp bằng JSON
 * ============================================================================
 */

// ============================================================================
// INCLUDE THƯ VIỆN
// ============================================================================
#include <stdio.h>          // Input/Output cơ bản
#include <stdlib.h>         // Memory allocation, exit
#include <string.h>         // String manipulation
#include <unistd.h>         // POSIX API (close, read, write)
#include <arpa/inet.h>      // Socket API cho TCP/IP
#include <sys/stat.h>       // File stat for size
#include <json-c/json.h>    // JSON parsing và generation
#include <openssl/bio.h>    // Base64 encoding/decoding
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/md5.h>    // MD5 checksum
#include "../common/protocol.h"  // Protocol definitions (PORT, BUFFER_SIZE, etc.)

#define CHUNK_SIZE 524288  // 512KB - phải khớp với server

// ============================================================================
// GLOBAL VARIABLES - QUẢN LÝ PHIÊN ĐĂNG NHẬP
// ============================================================================
// Các biến global để lưu trữ thông tin phiên đăng nhập hiện tại
// Được cập nhật khi user login thành công và xóa khi logout
char g_session_token[MAX_TOKEN] = "";     // Session token từ server
int g_user_id = 0;                         // ID của user đang đăng nhập
char g_username[MAX_USERNAME] = "";       // Username của user đang đăng nhập

// ============================================================================
// BASE64 ENCODING/DECODING FUNCTIONS
// ============================================================================

/**
 * Encode dữ liệu binary sang Base64
 */
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

/**
 * Decode Base64 về dữ liệu binary
 */
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

/**
 * Tính MD5 checksum của file
 */
static void calculate_file_md5(const char *filename, unsigned char *md5_out) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        memset(md5_out, 0, MD5_DIGEST_LENGTH);
        return;
    }
    
    MD5_CTX md5_context;
    MD5_Init(&md5_context);
    
    unsigned char buffer[CHUNK_SIZE];
    size_t bytes_read;
    
    while ((bytes_read = fread(buffer, 1, CHUNK_SIZE, fp)) > 0) {
        MD5_Update(&md5_context, buffer, bytes_read);
    }
    
    MD5_Final(md5_out, &md5_context);
    fclose(fp);
}

/**
 * Chuyển MD5 digest sang hex string
 */
static void md5_to_hex(unsigned char *digest, char *output) {
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", digest[i]);
    }
    output[MD5_DIGEST_LENGTH * 2] = '\0';
}

// ============================================================================
// UI HELPER FUNCTIONS - HÀM HỖ TRỢ GIAO DIỆN
// ============================================================================

/**
 * Xóa toàn bộ màn hình console
 * Sử dụng ANSI escape codes: \033[2J xóa màn hình, \033[H về vị trí đầu
 */
void clear_screen() {
    printf("\033[2J\033[H");
}

/**
 * In dấu phân cách ngang để phân chia các phần trên UI
 */
void print_separator() {
    printf("========================================\n");
}

/**
 * In thông báo thành công với icon checkmark
 * @param message: Nội dung thông báo cần hiển thị
 */
void print_success(const char *message) {
    printf("✓ %s\n", message);
}

/**
 * In thông báo lỗi với icon X
 * @param message: Nội dung lỗi cần hiển thị
 */
void print_error(const char *message) {
    printf("✗ %s\n", message);
}

/**
 * Hiển thị một thông báo với format đẹp, bao gồm icon và status
 * @param notif_obj: JSON object chứa thông tin notification từ server
 * 
 * Format hiển thị:
 * ┌─────────────────────────────────────┐
 * │ 🔴 🙋 [ID:123] NEW                 │
 * ├─────────────────────────────────────┤
 * │ 📌 Title                           │
 * │ 💬 Message                         │
 * │ 🕒 Timestamp                       │
 * └─────────────────────────────────────┘
 */
void display_notification(struct json_object *notif_obj) {
    // Parse các field từ JSON object
    struct json_object *id_obj, *type_obj, *title_obj, *message_obj, 
                       *is_read_obj, *created_at_obj, *related_type_obj, *related_id_obj;
    
    json_object_object_get_ex(notif_obj, "notification_id", &id_obj);
    json_object_object_get_ex(notif_obj, "type", &type_obj);
    json_object_object_get_ex(notif_obj, "title", &title_obj);
    json_object_object_get_ex(notif_obj, "message", &message_obj);
    json_object_object_get_ex(notif_obj, "is_read", &is_read_obj);
    json_object_object_get_ex(notif_obj, "created_at", &created_at_obj);
    json_object_object_get_ex(notif_obj, "related_type", &related_type_obj);
    json_object_object_get_ex(notif_obj, "related_id", &related_id_obj);
    
    // Lấy giá trị từ JSON objects
    int id = json_object_get_int(id_obj);
    const char *type = json_object_get_string(type_obj);
    const char *title = json_object_get_string(title_obj);
    const char *message = json_object_get_string(message_obj);
    int is_read = json_object_get_boolean(is_read_obj);
    const char *created_at = json_object_get_string(created_at_obj);
    
    // Chọn icon phù hợp dựa trên loại thông báo
    const char *icon = "📬";  // Default icon
    if (strcmp(type, "JOIN_REQUEST") == 0) icon = "🙋";                    // Yêu cầu tham gia
    else if (strcmp(type, "JOIN_REQUEST_RESPONSE") == 0) icon = "✅";      // Phản hồi yêu cầu
    else if (strcmp(type, "GROUP_INVITATION") == 0) icon = "💌";           // Lời mời vào nhóm
    else if (strcmp(type, "INVITATION_ACCEPTED") == 0) icon = "🎉";        // Lời mời được chấp nhận
    else if (strcmp(type, "MEMBER_LEFT") == 0) icon = "👋";                // Thành viên rời nhóm
    else if (strcmp(type, "REMOVED_FROM_GROUP") == 0) icon = "🚫";         // Bị xóa khỏi nhóm
    
    // Hiển thị đỏ (🔴) nếu chưa đọc, trống nếu đã đọc
    const char *status_mark = is_read ? "  " : "🔴";
    
    printf("┌─────────────────────────────────────────────────────────┐\n");
    printf("│ %s %s [ID:%d] %s\n", status_mark, icon, id, is_read ? "" : "NEW");
    printf("├─────────────────────────────────────────────────────────┤\n");
    printf("│ 📌 %s\n", title);
    printf("│ 💬 %s\n", message);
    printf("│ 🕒 %s\n", created_at);
    printf("└─────────────────────────────────────────────────────────┘\n");
}

// ============================================================================
// RESPONSE HANDLER - XỬ LÝ PHẢN HỒI TỪ SERVER
// ============================================================================

/**
 * Parse và hiển thị response JSON từ server với format đẹp
 * @param json_str: Chuỗi JSON response từ server
 * 
 * Chức năng:
 * 1. Hiển thị raw response để debug
 * 2. Parse JSON và extract status, code, message
 * 3. Hiển thị thông tin đã format dựa trên response code
 * 4. Cập nhật session token nếu là response login
 */
void parse_and_display_response(const char *json_str) {
    // Bước 1: Hiển thị raw response từ server (cho mục đích debug)
    printf("\n[RAW RESPONSE FROM SERVER]\n");
    print_separator();
    printf("%s\n", json_str);
    print_separator();
    
    // Bước 2: Parse JSON string thành object
    struct json_object *response = json_tokener_parse(json_str);
    if (!response) {
        print_error("Failed to parse JSON response");
        return;
    }
    
    // Bước 3: Extract các field chính từ response
    struct json_object *status_obj, *code_obj, *message_obj, *payload_obj;
    
    json_object_object_get_ex(response, "status", &status_obj);      // HTTP status code
    json_object_object_get_ex(response, "code", &code_obj);          // Response code (SUCCESS_LOGIN, ERROR_INVALID_CREDENTIALS, etc.)
    json_object_object_get_ex(response, "message", &message_obj);    // Human-readable message
    json_object_object_get_ex(response, "payload", &payload_obj);    // Data payload (user info, groups, etc.)
    
    // Convert sang C types
    int status = json_object_get_int(status_obj);
    const char *code = json_object_get_string(code_obj);
    const char *message = json_object_get_string(message_obj);
    
    // Bước 4: Hiển thị response đã được xử lý
    printf("\n[PROCESSED RESPONSE]\n");
    print_separator();
    if (status == 200 || status == 201) {
        print_success(message);  // Success: status 200 (OK) hoặc 201 (Created)
    } else {
        print_error(message);    // Error: status 4xx hoặc 5xx
    }
    printf("Status: %d | Code: %s\n", status, code);
    print_separator();
    
    // Bước 5: Xử lý payload dựa trên response code
    if (payload_obj) {
        // Parse và hiển thị data cụ thể cho từng loại response
        if (strcmp(code, "SUCCESS_REGISTER") == 0) {
            struct json_object *user_id_obj, *username_obj, *created_at_obj;
            json_object_object_get_ex(payload_obj, "user_id", &user_id_obj);
            json_object_object_get_ex(payload_obj, "username", &username_obj);
            json_object_object_get_ex(payload_obj, "created_at", &created_at_obj);
            
            printf("\n✓ Registration Successful!\n");
            printf("  👤 Username: %s\n", json_object_get_string(username_obj));
            printf("  🆔 User ID: %d\n", json_object_get_int(user_id_obj));
            printf("  📅 Created at: %s\n", json_object_get_string(created_at_obj));
        } else if (strcmp(code, "SUCCESS_LOGIN") == 0) {
            struct json_object *token_obj, *user_id_obj, *username_obj, *email_obj, *full_name_obj;
            json_object_object_get_ex(payload_obj, "session_token", &token_obj);
            json_object_object_get_ex(payload_obj, "user_id", &user_id_obj);
            json_object_object_get_ex(payload_obj, "username", &username_obj);
            json_object_object_get_ex(payload_obj, "email", &email_obj);
            json_object_object_get_ex(payload_obj, "full_name", &full_name_obj);
            
            if (token_obj) {
                strncpy(g_session_token, json_object_get_string(token_obj), MAX_TOKEN - 1);
                g_user_id = json_object_get_int(user_id_obj);
                strncpy(g_username, json_object_get_string(username_obj), MAX_USERNAME - 1);
                
                printf("\n✓ Login Successful!\n");
                printf("  👤 Username: %s\n", g_username);
                printf("  🆔 User ID: %d\n", g_user_id);
                printf("  📧 Email: %s\n", json_object_get_string(email_obj));
                printf("  📝 Full Name: %s\n", json_object_get_string(full_name_obj));
                printf("  🔑 Session saved!\n");
            }
        } else if (strcmp(code, "SUCCESS_LOGOUT") == 0) {
            printf("\n✓ Successfully logged out!\n");
        } else if (strcmp(code, "SUCCESS_VERIFY_SESSION") == 0) {
            struct json_object *user_id_obj, *username_obj, *email_obj;
            json_object_object_get_ex(payload_obj, "user_id", &user_id_obj);
            json_object_object_get_ex(payload_obj, "username", &username_obj);
            json_object_object_get_ex(payload_obj, "email", &email_obj);
            
            printf("\n✓ Session is valid!\n");
            printf("  👤 Username: %s\n", json_object_get_string(username_obj));
            printf("  🆔 User ID: %d\n", json_object_get_int(user_id_obj));
            printf("  📧 Email: %s\n", json_object_get_string(email_obj));
        } else if (strcmp(code, "SUCCESS_UPDATE_PROFILE") == 0) {
            struct json_object *email_obj, *full_name_obj;
            json_object_object_get_ex(payload_obj, "email", &email_obj);
            json_object_object_get_ex(payload_obj, "full_name", &full_name_obj);
            
            printf("\n✓ Profile updated successfully!\n");
            printf("  📧 New Email: %s\n", json_object_get_string(email_obj));
            printf("  📝 New Full Name: %s\n", json_object_get_string(full_name_obj));
        } else if (strcmp(code, "SUCCESS_CHANGE_PASSWORD") == 0) {
            printf("\n✓ Password changed successfully!\n");
        } else if (strcmp(code, "SUCCESS_CREATE_GROUP") == 0) {
            struct json_object *group_id_obj, *group_name_obj, *description_obj, *created_at_obj;
            json_object_object_get_ex(payload_obj, "group_id", &group_id_obj);
            json_object_object_get_ex(payload_obj, "group_name", &group_name_obj);
            json_object_object_get_ex(payload_obj, "description", &description_obj);
            json_object_object_get_ex(payload_obj, "created_at", &created_at_obj);
            
            printf("\n✓ Group created successfully!\n");
            printf("  🆔 Group ID: %d\n", json_object_get_int(group_id_obj));
            printf("  👥 Name: %s\n", json_object_get_string(group_name_obj));
            printf("  📝 Description: %s\n", json_object_get_string(description_obj));
            printf("  📅 Created at: %s\n", json_object_get_string(created_at_obj));
        } else if (strcmp(code, "SUCCESS_LIST_GROUPS") == 0) {
            struct json_object *groups_obj;
            json_object_object_get_ex(payload_obj, "groups", &groups_obj);
            int count = json_object_array_length(groups_obj);
            
            printf("\n👥 Your Groups (%d):\n", count);
            if (count == 0) {
                printf("  📭 No groups yet. Create or join one!\n");
            } else {
                for (int i = 0; i < count; i++) {
                    struct json_object *group = json_object_array_get_idx(groups_obj, i);
                    struct json_object *id, *name, *role, *members;
                    json_object_object_get_ex(group, "group_id", &id);
                    json_object_object_get_ex(group, "group_name", &name);
                    json_object_object_get_ex(group, "role", &role);
                    json_object_object_get_ex(group, "member_count", &members);
                    
                    printf("\n  [%d] %s\n", json_object_get_int(id), json_object_get_string(name));
                    printf("      Role: %s | Members: %d\n", 
                           json_object_get_string(role),
                           json_object_get_int(members));
                }
            }
        } else if (strcmp(code, "SUCCESS_LIST_MEMBERS") == 0) {
            struct json_object *members_obj, *group_id_obj;
            json_object_object_get_ex(payload_obj, "members", &members_obj);
            json_object_object_get_ex(payload_obj, "group_id", &group_id_obj);
            int count = json_object_array_length(members_obj);
            
            printf("\n👥 Group Members (Group ID: %d) - Total: %d\n", 
                   json_object_get_int(group_id_obj), count);
            if (count == 0) {
                printf("  📭 No members in this group.\n");
            } else {
                for (int i = 0; i < count; i++) {
                    struct json_object *member = json_object_array_get_idx(members_obj, i);
                    struct json_object *id, *username, *name, *role;
                    json_object_object_get_ex(member, "user_id", &id);
                    json_object_object_get_ex(member, "username", &username);
                    json_object_object_get_ex(member, "full_name", &name);
                    json_object_object_get_ex(member, "role", &role);
                    
                    printf("\n  [ID:%d] %s\n", json_object_get_int(id), json_object_get_string(username));
                    printf("      Name: %s | Role: %s\n", 
                           json_object_get_string(name),
                           json_object_get_string(role));
                }
            }
        } else if (strcmp(code, "SUCCESS_REQUEST_JOIN") == 0) {
            struct json_object *request_id_obj, *group_id_obj, *created_at_obj;
            json_object_object_get_ex(payload_obj, "request_id", &request_id_obj);
            json_object_object_get_ex(payload_obj, "group_id", &group_id_obj);
            json_object_object_get_ex(payload_obj, "created_at", &created_at_obj);
            
            printf("\n✓ Join request sent successfully!\n");
            printf("  🆔 Request ID: %d\n", json_object_get_int(request_id_obj));
            printf("  👥 Group ID: %d\n", json_object_get_int(group_id_obj));
            printf("  📅 Created at: %s\n", json_object_get_string(created_at_obj));
            printf("  ⏳ Status: Pending approval\n");
        } else if (strcmp(code, "SUCCESS_LIST_REQUESTS") == 0) {
            struct json_object *requests_obj, *group_id_obj;
            json_object_object_get_ex(payload_obj, "requests", &requests_obj);
            json_object_object_get_ex(payload_obj, "group_id", &group_id_obj);
            int count = json_object_array_length(requests_obj);
            
            printf("\n🙋 Join Requests for Group ID %d - Total: %d\n", 
                   json_object_get_int(group_id_obj), count);
            if (count == 0) {
                printf("  📭 No pending join requests.\n");
            } else {
                for (int i = 0; i < count; i++) {
                    struct json_object *req = json_object_array_get_idx(requests_obj, i);
                    struct json_object *id, *username, *name, *status;
                    json_object_object_get_ex(req, "request_id", &id);
                    json_object_object_get_ex(req, "username", &username);
                    json_object_object_get_ex(req, "full_name", &name);
                    json_object_object_get_ex(req, "status", &status);
                    
                    printf("\n  [ReqID:%d] %s (%s)\n", 
                           json_object_get_int(id),
                           json_object_get_string(username),
                           json_object_get_string(name));
                    printf("      Status: %s\n", json_object_get_string(status));
                }
            }
        } else if (strcmp(code, "SUCCESS_APPROVE_REQUEST") == 0 || strcmp(code, "SUCCESS_REJECT_REQUEST") == 0) {
            struct json_object *request_id_obj, *user_id_obj, *status_obj;
            json_object_object_get_ex(payload_obj, "request_id", &request_id_obj);
            json_object_object_get_ex(payload_obj, "user_id", &user_id_obj);
            json_object_object_get_ex(payload_obj, "status", &status_obj);
            
            const char *action = strcmp(code, "SUCCESS_APPROVE_REQUEST") == 0 ? "Approved" : "Rejected";
            printf("\n✓ Request %s!\n", action);
            printf("  🆔 Request ID: %d\n", json_object_get_int(request_id_obj));
            printf("  👤 User ID: %d\n", json_object_get_int(user_id_obj));
            printf("  📊 Status: %s\n", json_object_get_string(status_obj));
        } else if (strcmp(code, "SUCCESS_SEND_INVITATION") == 0) {
            struct json_object *invitation_id_obj, *group_id_obj, *invitee_id_obj, *created_at_obj;
            json_object_object_get_ex(payload_obj, "invitation_id", &invitation_id_obj);
            json_object_object_get_ex(payload_obj, "group_id", &group_id_obj);
            json_object_object_get_ex(payload_obj, "invitee_id", &invitee_id_obj);
            json_object_object_get_ex(payload_obj, "created_at", &created_at_obj);
            
            printf("\n✓ Invitation sent successfully!\n");
            printf("  🆔 Invitation ID: %d\n", json_object_get_int(invitation_id_obj));
            printf("  👥 Group ID: %d\n", json_object_get_int(group_id_obj));
            printf("  👤 Invitee ID: %d\n", json_object_get_int(invitee_id_obj));
            printf("  📅 Created at: %s\n", json_object_get_string(created_at_obj));
        } else if (strcmp(code, "SUCCESS_LIST_INVITATIONS") == 0) {
            struct json_object *invitations_obj;
            json_object_object_get_ex(payload_obj, "invitations", &invitations_obj);
            int count = json_object_array_length(invitations_obj);
            
            printf("\n💌 Your Invitations - Total: %d\n", count);
            if (count == 0) {
                printf("  📭 No pending invitations.\n");
            } else {
                for (int i = 0; i < count; i++) {
                    struct json_object *inv = json_object_array_get_idx(invitations_obj, i);
                    struct json_object *id, *group_name, *inviter, *status;
                    json_object_object_get_ex(inv, "invitation_id", &id);
                    json_object_object_get_ex(inv, "group_name", &group_name);
                    json_object_object_get_ex(inv, "inviter_username", &inviter);
                    json_object_object_get_ex(inv, "status", &status);
                    
                    printf("\n  [InvID:%d] Group: %s\n", 
                           json_object_get_int(id),
                           json_object_get_string(group_name));
                    printf("      From: %s | Status: %s\n", 
                           json_object_get_string(inviter),
                           json_object_get_string(status));
                }
            }
        } else if (strcmp(code, "SUCCESS_ACCEPT_INVITATION") == 0 || strcmp(code, "SUCCESS_REJECT_INVITATION") == 0) {
            struct json_object *invitation_id_obj, *group_id_obj, *status_obj;
            json_object_object_get_ex(payload_obj, "invitation_id", &invitation_id_obj);
            json_object_object_get_ex(payload_obj, "group_id", &group_id_obj);
            json_object_object_get_ex(payload_obj, "status", &status_obj);
            
            const char *action = strcmp(code, "SUCCESS_ACCEPT_INVITATION") == 0 ? "Accepted" : "Rejected";
            printf("\n✓ Invitation %s!\n", action);
            printf("  🆔 Invitation ID: %d\n", json_object_get_int(invitation_id_obj));
            printf("  👥 Group ID: %d\n", json_object_get_int(group_id_obj));
            printf("  📊 Status: %s\n", json_object_get_string(status_obj));
        } else if (strcmp(code, "SUCCESS_LEAVE_GROUP") == 0) {
            struct json_object *group_id_obj;
            json_object_object_get_ex(payload_obj, "group_id", &group_id_obj);
            
            printf("\n✓ Successfully left the group!\n");
            printf("  👥 Group ID: %d\n", json_object_get_int(group_id_obj));
        } else if (strcmp(code, "SUCCESS_REMOVE_MEMBER") == 0) {
            struct json_object *group_id_obj, *user_id_obj;
            json_object_object_get_ex(payload_obj, "group_id", &group_id_obj);
            json_object_object_get_ex(payload_obj, "user_id", &user_id_obj);
            
            printf("\n✓ Member removed successfully!\n");
            printf("  👥 Group ID: %d\n", json_object_get_int(group_id_obj));
            printf("  👤 User ID: %d\n", json_object_get_int(user_id_obj));
        } else if (strcmp(code, "SUCCESS_GET_NOTIFICATIONS") == 0) {
            struct json_object *notif_array, *total_count_obj;
            json_object_object_get_ex(payload_obj, "notifications", &notif_array);
            json_object_object_get_ex(payload_obj, "total_count", &total_count_obj);
            
            int count = json_object_get_int(total_count_obj);
            
            printf("\n╔══════════════════════════════════════════════════════════╗\n");
            printf("║              📬 YOUR NOTIFICATIONS (%d)                ║\n", count);
            printf("╚══════════════════════════════════════════════════════════╝\n\n");
            
            if (count == 0) {
                printf("  📭 No notifications yet. You're all caught up!\n\n");
            } else {
                // Phân loại thông báo
                int unread_count = 0;
                for (int i = 0; i < json_object_array_length(notif_array); i++) {
                    struct json_object *notif = json_object_array_get_idx(notif_array, i);
                    struct json_object *is_read_obj;
                    json_object_object_get_ex(notif, "is_read", &is_read_obj);
                    if (!json_object_get_boolean(is_read_obj)) {
                        unread_count++;
                    }
                }
                
                if (unread_count > 0) {
                    printf("🔴 Unread: %d | 📖 Read: %d\n\n", unread_count, count - unread_count);
                }
                
                for (int i = 0; i < json_object_array_length(notif_array); i++) {
                    struct json_object *notif = json_object_array_get_idx(notif_array, i);
                    display_notification(notif);
                    printf("\n");
                }
            }
        } else if (strcmp(code, "SUCCESS_MARK_NOTIFICATION_READ") == 0) {
            struct json_object *notif_id_obj;
            json_object_object_get_ex(payload_obj, "notification_id", &notif_id_obj);
            
            printf("\n✓ Notification marked as read!\n");
            printf("  🆔 Notification ID: %d\n", json_object_get_int(notif_id_obj));
        } else if (strcmp(code, "SUCCESS_MARK_ALL_READ") == 0) {
            struct json_object *marked_count_obj;
            json_object_object_get_ex(payload_obj, "marked_count", &marked_count_obj);
            
            printf("\n✓ All notifications marked as read!\n");
            printf("  📊 Total marked: %d\n", json_object_get_int(marked_count_obj));
        } else if (strcmp(code, "SUCCESS_GET_UNREAD_COUNT") == 0) {
            struct json_object *count_obj;
            json_object_object_get_ex(payload_obj, "unread_count", &count_obj);
            int count = json_object_get_int(count_obj);
            
            printf("\n");
            if (count > 0) {
                printf("🔴 You have %d unread notification%s\n", count, count > 1 ? "s" : "");
            } else {
                printf("✅ You're all caught up! No unread notifications.\n");
            }
        } else if (strcmp(code, "SUCCESS_CREATE_DIRECTORY") == 0) {
            struct json_object *dir_id_obj, *dir_name_obj, *dir_path_obj, *created_at_obj;
            json_object_object_get_ex(payload_obj, "directory_id", &dir_id_obj);
            json_object_object_get_ex(payload_obj, "directory_name", &dir_name_obj);
            json_object_object_get_ex(payload_obj, "directory_path", &dir_path_obj);
            json_object_object_get_ex(payload_obj, "created_at", &created_at_obj);
            
            printf("\n✓ Directory created successfully!\n");
            printf("  🆔 Directory ID: %d\n", json_object_get_int(dir_id_obj));
            printf("  📁 Name: %s\n", json_object_get_string(dir_name_obj));
            printf("  📂 Path: %s\n", json_object_get_string(dir_path_obj));
            printf("  📅 Created at: %s\n", json_object_get_string(created_at_obj));
        } else if (strcmp(code, "SUCCESS_LIST_DIRECTORY") == 0) {
            struct json_object *group_id_obj, *current_path_obj, *directories_obj, *files_obj;
            json_object_object_get_ex(payload_obj, "group_id", &group_id_obj);
            json_object_object_get_ex(payload_obj, "current_path", &current_path_obj);
            json_object_object_get_ex(payload_obj, "directories", &directories_obj);
            json_object_object_get_ex(payload_obj, "files", &files_obj);
            
            int dir_count = json_object_array_length(directories_obj);
            int file_count = json_object_array_length(files_obj);
            
            printf("\n✓ Directory contents retrieved successfully!\n");
            printf("  👥 Group ID: %d\n", json_object_get_int(group_id_obj));
            printf("  📂 Current Path: %s\n", json_object_get_string(current_path_obj));
            printf("  📊 Total: %d directories, %d files\n", dir_count, file_count);
            
            // Hiển thị directories
            if (dir_count > 0) {
                printf("\n  📁 Directories:\n");
                for (int i = 0; i < dir_count; i++) {
                    struct json_object *dir = json_object_array_get_idx(directories_obj, i);
                    struct json_object *id, *name, *path, *created_by, *created_at;
                    json_object_object_get_ex(dir, "directory_id", &id);
                    json_object_object_get_ex(dir, "directory_name", &name);
                    json_object_object_get_ex(dir, "directory_path", &path);
                    json_object_object_get_ex(dir, "created_by", &created_by);
                    json_object_object_get_ex(dir, "created_at", &created_at);
                    
                    printf("    [ID:%d] 📁 %s\n", json_object_get_int(id), json_object_get_string(name));
                    printf("        Path: %s\n", json_object_get_string(path));
                    printf("        Created by: %s | %s\n", 
                           json_object_get_string(created_by),
                           json_object_get_string(created_at));
                }
            }
            
            // Hiển thị files
            if (file_count > 0) {
                printf("\n  📄 Files:\n");
                for (int i = 0; i < file_count; i++) {
                    struct json_object *file = json_object_array_get_idx(files_obj, i);
                    struct json_object *id, *name, *path, *size, *type, *uploaded_by, *uploaded_at;
                    json_object_object_get_ex(file, "file_id", &id);
                    json_object_object_get_ex(file, "file_name", &name);
                    json_object_object_get_ex(file, "file_path", &path);
                    json_object_object_get_ex(file, "file_size", &size);
                    json_object_object_get_ex(file, "file_type", &type);
                    json_object_object_get_ex(file, "uploaded_by", &uploaded_by);
                    json_object_object_get_ex(file, "uploaded_at", &uploaded_at);
                    
                    long long file_size = json_object_get_int64(size);
                    double size_mb = file_size / 1024.0 / 1024.0;
                    
                    printf("    [ID:%d] 📄 %s\n", json_object_get_int(id), json_object_get_string(name));
                    printf("        Size: %.2f MB (%lld bytes)\n", size_mb, file_size);
                    printf("        Type: %s\n", json_object_get_string(type));
                    printf("        Uploaded by: %s | %s\n", 
                           json_object_get_string(uploaded_by),
                           json_object_get_string(uploaded_at));
                }
            }
            
            if (dir_count == 0 && file_count == 0) {
                printf("\n  📭 This directory is empty.\n");
            }
        } else if (strcmp(code, "SUCCESS_RENAME_DIRECTORY") == 0) {
            struct json_object *dir_id_obj, *old_name_obj, *new_name_obj, *old_path_obj, *new_path_obj, *updated_at_obj;
            json_object_object_get_ex(payload_obj, "directory_id", &dir_id_obj);
            json_object_object_get_ex(payload_obj, "old_name", &old_name_obj);
            json_object_object_get_ex(payload_obj, "new_name", &new_name_obj);
            json_object_object_get_ex(payload_obj, "old_path", &old_path_obj);
            json_object_object_get_ex(payload_obj, "new_path", &new_path_obj);
            json_object_object_get_ex(payload_obj, "updated_at", &updated_at_obj);
            
            printf("\n✓ Directory renamed successfully!\n");
            printf("  🆔 Directory ID: %d\n", json_object_get_int(dir_id_obj));
            printf("  📁 Old name: %s\n", json_object_get_string(old_name_obj));
            printf("  📁 New name: %s\n", json_object_get_string(new_name_obj));
            printf("  📂 Old path: %s\n", json_object_get_string(old_path_obj));
            printf("  📂 New path: %s\n", json_object_get_string(new_path_obj));
            printf("  📅 Updated at: %s\n", json_object_get_string(updated_at_obj));
        } else if (strcmp(code, "SUCCESS_DELETE_DIRECTORY") == 0) {
            struct json_object *dir_id_obj, *deleted_files_obj, *deleted_subdirs_obj, *deleted_at_obj;
            json_object_object_get_ex(payload_obj, "directory_id", &dir_id_obj);
            json_object_object_get_ex(payload_obj, "deleted_files", &deleted_files_obj);
            json_object_object_get_ex(payload_obj, "deleted_subdirectories", &deleted_subdirs_obj);
            json_object_object_get_ex(payload_obj, "deleted_at", &deleted_at_obj);
            
            printf("\n✓ Directory deleted successfully!\n");
            printf("  🆔 Directory ID: %d\n", json_object_get_int(dir_id_obj));
            printf("  📄 Deleted files: %d\n", json_object_get_int(deleted_files_obj));
            printf("  📁 Deleted subdirectories: %d\n", json_object_get_int(deleted_subdirs_obj));
            printf("  📅 Deleted at: %s\n", json_object_get_string(deleted_at_obj));
        } else if (strcmp(code, "SUCCESS_COPY_DIRECTORY") == 0) {
            struct json_object *source_id_obj, *new_id_obj, *new_path_obj, *copied_at_obj;
            json_object_object_get_ex(payload_obj, "source_directory_id", &source_id_obj);
            json_object_object_get_ex(payload_obj, "new_directory_id", &new_id_obj);
            json_object_object_get_ex(payload_obj, "new_directory_path", &new_path_obj);
            json_object_object_get_ex(payload_obj, "copied_at", &copied_at_obj);
            
            printf("\n✓ Directory copied successfully!\n");
            printf("  🆔 Source directory ID: %d\n", json_object_get_int(source_id_obj));
            printf("  🆔 New directory ID: %d\n", json_object_get_int(new_id_obj));
            printf("  📂 New path: %s\n", json_object_get_string(new_path_obj));
            printf("  📅 Copied at: %s\n", json_object_get_string(copied_at_obj));
        } else if (strcmp(code, "SUCCESS_MOVE_DIRECTORY") == 0) {
            struct json_object *dir_id_obj, *old_path_obj, *new_path_obj, *affected_files_obj, *affected_subdirs_obj, *moved_at_obj;
            json_object_object_get_ex(payload_obj, "directory_id", &dir_id_obj);
            json_object_object_get_ex(payload_obj, "old_path", &old_path_obj);
            json_object_object_get_ex(payload_obj, "new_path", &new_path_obj);
            json_object_object_get_ex(payload_obj, "affected_files", &affected_files_obj);
            json_object_object_get_ex(payload_obj, "affected_subdirectories", &affected_subdirs_obj);
            json_object_object_get_ex(payload_obj, "moved_at", &moved_at_obj);
            
            printf("\n✓ Directory moved successfully!\n");
            printf("  🆔 Directory ID: %d\n", json_object_get_int(dir_id_obj));
            printf("  📂 Old path: %s\n", json_object_get_string(old_path_obj));
            printf("  📂 New path: %s\n", json_object_get_string(new_path_obj));
            printf("  📄 Affected files: %d\n", json_object_get_int(affected_files_obj));
            printf("  📁 Affected subdirectories: %d\n", json_object_get_int(affected_subdirs_obj));
            printf("  📅 Moved at: %s\n", json_object_get_string(moved_at_obj));
        } else if (strcmp(code, "SUCCESS_GET_PERMISSIONS") == 0 ||
                   strcmp(code, "SUCCESS_UPDATE_PERMISSIONS") == 0) {
            printf("\n✓ Permissions operation completed!\n");
            printf("  Details: %s\n", json_object_to_json_string_ext(payload_obj, JSON_C_TO_STRING_PRETTY));
        } else if (strcmp(code, "SUCCESS_LIST_AVAILABLE_GROUPS") == 0) {
            struct json_object *groups_obj, *total_count_obj;
            json_object_object_get_ex(payload_obj, "groups", &groups_obj);
            json_object_object_get_ex(payload_obj, "total_count", &total_count_obj);
            int count = json_object_get_int(total_count_obj);
            
            printf("\n🔍 Available Groups (%d):\n", count);
            if (count == 0) {
                printf("  📭 No groups available to join.\n");
            }
        } else if (strcmp(code, "SUCCESS_RENAME_FILE") == 0) {
            struct json_object *file_id_obj, *old_name_obj, *new_name_obj, *updated_at_obj;
            json_object_object_get_ex(payload_obj, "file_id", &file_id_obj);
            json_object_object_get_ex(payload_obj, "old_name", &old_name_obj);
            json_object_object_get_ex(payload_obj, "new_name", &new_name_obj);
            json_object_object_get_ex(payload_obj, "updated_at", &updated_at_obj);
            
            printf("\n✓ File renamed successfully!\n");
            printf("  🆔 File ID: %d\n", json_object_get_int(file_id_obj));
            printf("  📄 Old name: %s\n", json_object_get_string(old_name_obj));
            printf("  📄 New name: %s\n", json_object_get_string(new_name_obj));
            printf("  📅 Updated at: %s\n", json_object_get_string(updated_at_obj));
        } else if (strcmp(code, "SUCCESS_DELETE_FILE") == 0) {
            struct json_object *file_id_obj, *deleted_at_obj;
            json_object_object_get_ex(payload_obj, "file_id", &file_id_obj);
            json_object_object_get_ex(payload_obj, "deleted_at", &deleted_at_obj);
            
            printf("\n✓ File deleted successfully!\n");
            printf("  🆔 File ID: %d\n", json_object_get_int(file_id_obj));
            printf("  📅 Deleted at: %s\n", json_object_get_string(deleted_at_obj));
        } else if (strcmp(code, "SUCCESS_COPY_FILE") == 0) {
            struct json_object *source_id_obj, *new_id_obj, *new_path_obj, *copied_at_obj;
            json_object_object_get_ex(payload_obj, "source_file_id", &source_id_obj);
            json_object_object_get_ex(payload_obj, "new_file_id", &new_id_obj);
            json_object_object_get_ex(payload_obj, "new_file_path", &new_path_obj);
            json_object_object_get_ex(payload_obj, "copied_at", &copied_at_obj);
            
            printf("\n✓ File copied successfully!\n");
            printf("  🆔 Source file ID: %d\n", json_object_get_int(source_id_obj));
            printf("  🆔 New file ID: %d\n", json_object_get_int(new_id_obj));
            printf("  📂 New path: %s\n", json_object_get_string(new_path_obj));
            printf("  📅 Copied at: %s\n", json_object_get_string(copied_at_obj));
        } else if (strcmp(code, "SUCCESS_MOVE_FILE") == 0) {
            struct json_object *file_id_obj, *old_path_obj, *new_path_obj, *moved_at_obj;
            json_object_object_get_ex(payload_obj, "file_id", &file_id_obj);
            json_object_object_get_ex(payload_obj, "old_path", &old_path_obj);
            json_object_object_get_ex(payload_obj, "new_path", &new_path_obj);
            json_object_object_get_ex(payload_obj, "moved_at", &moved_at_obj);
            
            printf("\n✓ File moved successfully!\n");
            printf("  🆔 File ID: %d\n", json_object_get_int(file_id_obj));
            printf("  📂 Old path: %s\n", json_object_get_string(old_path_obj));
            printf("  📂 New path: %s\n", json_object_get_string(new_path_obj));
            printf("  📅 Moved at: %s\n", json_object_get_string(moved_at_obj));
        } else {
            // Display raw payload for unknown responses
            printf("\nDetails:\n%s\n", json_object_to_json_string_ext(payload_obj, JSON_C_TO_STRING_PRETTY));
        }
    }
    
    print_separator();
    json_object_put(response);
}

/**
 * Tạm dừng chương trình và đợi user nhấn ENTER để tiếp tục
 * Sử dụng 2 lần getchar() để xử lý cả newline buffer
 */
void wait_for_enter() {
    printf("\nPress ENTER to continue...");
    getchar();
    getchar();
}

// ============================================================================
// NETWORK CONNECTION - KẾT NỐI MẠNG
// ============================================================================

/**
 * Kết nối tới server qua TCP/IP socket
 * @return: Socket file descriptor nếu thành công, -1 nếu lỗi
 * 
 * Quy trình:
 * 1. Tạo socket với AF_INET (IPv4) và SOCK_STREAM (TCP)
 * 2. Cấu hình địa chỉ server (IP và port)
 * 3. Thực hiện kết nối
 * 4. Trả về socket descriptor để sử dụng cho communication
 */
int connect_to_server() {
    // Bước 1: Tạo socket
    // AF_INET = IPv4, SOCK_STREAM = TCP, 0 = default protocol
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return -1;
    }
    
    // Bước 2: Cấu hình thông tin server
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;                          // IPv4
    server_addr.sin_port = htons(PORT);                        // Port (convert to network byte order)
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1"); // IP address của server
    
    // Bước 3: Kết nối tới server
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(sock);
        return -1;
    }
    
    printf("Connected to server\n");
    return sock;
}

// ============================================================================
// AUTHENTICATION FUNCTIONS - XÁC THỰC VÀ QUẢN LÝ TÀI KHOẢN
// ============================================================================

/**
 * Gửi yêu cầu đăng ký tài khoản mới
 * @param sock: Socket đã kết nối tới server
 * 
 * Thu thập thông tin: username, password, email, full_name
 * Gửi request với command "REGISTER" lên server
 * Nhận và hiển thị response
 */
void send_register_request(int sock) {
    char username[MAX_USERNAME], password[MAX_PASSWORD];
    char email[MAX_EMAIL], full_name[MAX_FULLNAME];
    
    // Hiển thị form đăng ký
    clear_screen();
    printf("\n=== REGISTER NEW ACCOUNT ===\n");
    
    // Thu thập thông tin từ user
    printf("Username: ");
    scanf("%s", username);
    printf("Password: ");
    scanf("%s", password);
    printf("Email: ");
    scanf("%s", email);
    printf("Full name: ");
    getchar(); // Xóa newline từ buffer
    fgets(full_name, MAX_FULLNAME, stdin);
    full_name[strcspn(full_name, "\n")] = 0;  // Loại bỏ newline cuối
    
    // Tạo JSON request
    struct json_object *request = json_object_new_object();
    json_object_object_add(request, "command", json_object_new_string("REGISTER"));
    
    // Tạo data object chứa thông tin đăng ký
    struct json_object *data = json_object_new_object();
    json_object_object_add(data, "username", json_object_new_string(username));
    json_object_object_add(data, "password", json_object_new_string(password));
    json_object_object_add(data, "email", json_object_new_string(email));
    json_object_object_add(data, "full_name", json_object_new_string(full_name));
    json_object_object_add(request, "data", data);
    
    // Gửi request lên server
    const char *json_str = json_object_to_json_string(request);
    send(sock, json_str, strlen(json_str), 0);
    
    // Giải phóng bộ nhớ JSON
    json_object_put(request);
    
    // Nhận response từ server
    char buffer[BUFFER_SIZE];
    int bytes = recv(sock, buffer, BUFFER_SIZE - 1, 0);
    buffer[bytes] = '\0';
    
    // Hiển thị response
    parse_and_display_response(buffer);
    wait_for_enter();
}

/**
 * Gửi yêu cầu đăng nhập
 * @param sock: Socket đã kết nối tới server
 * 
 * Thành công: Lưu session_token, user_id, username vào global variables
 * Thất bại: Hiển thị lỗi
 */
void send_login_request(int sock) {
    char username[MAX_USERNAME], password[MAX_PASSWORD];
    
    // Hiển thị form login
    clear_screen();
    printf("\n=== LOGIN ===\n");
    printf("Username: ");
    scanf("%s", username);
    printf("Password: ");
    scanf("%s", password);
    
    // Tạo JSON request với command "LOGIN"
    struct json_object *request = json_object_new_object();
    json_object_object_add(request, "command", json_object_new_string("LOGIN"));
    
    struct json_object *data = json_object_new_object();
    json_object_object_add(data, "username", json_object_new_string(username));
    json_object_object_add(data, "password", json_object_new_string(password));
    json_object_object_add(request, "data", data);
    
    // Gửi và nhận response
    const char *json_str = json_object_to_json_string(request);
    send(sock, json_str, strlen(json_str), 0);
    json_object_put(request);
    
    char buffer[BUFFER_SIZE];
    int bytes = recv(sock, buffer, BUFFER_SIZE - 1, 0);
    buffer[bytes] = '\0';
    
    // Response handler sẽ tự động cập nhật g_session_token, g_user_id, g_username
    parse_and_display_response(buffer);
    wait_for_enter();
}

/**
 * Gửi yêu cầu đăng xuất
 * @param sock: Socket đã kết nối tới server
 * 
 * Kiểm tra user đã login chưa
 * Gửi session_token lên server để hủy phiên
 * Xóa session data local (token, user_id, username)
 */
void send_logout_request(int sock) {
    clear_screen();
    printf("\n=== LOGOUT ===\n");
    
    // Kiểm tra đã login chưa
    if (strlen(g_session_token) == 0) {
        print_error("You are not logged in!");
        wait_for_enter();
        return;
    }
    
    // Tạo logout request với session_token
    struct json_object *request = json_object_new_object();
    json_object_object_add(request, "command", json_object_new_string("LOGOUT"));
    
    struct json_object *data = json_object_new_object();
    json_object_object_add(data, "session_token", json_object_new_string(g_session_token));
    json_object_object_add(request, "data", data);
    
    const char *json_str = json_object_to_json_string(request);
    send(sock, json_str, strlen(json_str), 0);
    json_object_put(request);
    
    // Nhận response
    char buffer[BUFFER_SIZE];
    int bytes = recv(sock, buffer, BUFFER_SIZE - 1, 0);
    buffer[bytes] = '\0';
    
    parse_and_display_response(buffer);
    
    // Xóa session data local
    g_session_token[0] = '\0';
    g_user_id = 0;
    g_username[0] = '\0';
    
    wait_for_enter();
}

/**
 * Xác minh session hiện tại có hợp lệ không
 * @param sock: Socket đã kết nối tới server
 * 
 * Gửi session_token lên server để kiểm tra
 * Server sẽ verify token và trả về thông tin session
 */
void send_verify_session_request(int sock) {
    clear_screen();
    printf("\n=== VERIFY SESSION ===\n");
    
    // Kiểm tra đã login chưa
    if (strlen(g_session_token) == 0) {
        print_error("Please login first!");
        wait_for_enter();
        return;
    }
    
    // Tạo request với session_token
    struct json_object *request = json_object_new_object();
    json_object_object_add(request, "command", json_object_new_string("VERIFY_SESSION"));
    
    struct json_object *data = json_object_new_object();
    json_object_object_add(data, "session_token", json_object_new_string(g_session_token));
    json_object_object_add(request, "data", data);
    
    const char *json_str = json_object_to_json_string(request);
    send(sock, json_str, strlen(json_str), 0);
    
    json_object_put(request);
    
    // Nhận và hiển thị response
    char buffer[BUFFER_SIZE];
    int bytes = recv(sock, buffer, BUFFER_SIZE - 1, 0);
    buffer[bytes] = '\0';
    
    parse_and_display_response(buffer);
    wait_for_enter();
}

/**
 * Cập nhật thông tin profile của user
 * @param sock: Socket đã kết nối tới server
 * 
 * Cho phép user cập nhật: email, full_name
 * Yêu cầu session_token để xác thực
 */
void send_update_profile_request(int sock) {
    char email[MAX_EMAIL], full_name[MAX_FULLNAME];
    
    clear_screen();
    printf("\n=== UPDATE PROFILE ===\n");
    
    // Kiểm tra authentication
    if (strlen(g_session_token) == 0) {
        print_error("Please login first!");
        wait_for_enter();
        return;
    }
    
    // Nhập thông tin mới
    printf("New email: ");
    scanf("%s", email);
    printf("New full name: ");
    getchar(); // consume newline
    fgets(full_name, MAX_FULLNAME, stdin);
    full_name[strcspn(full_name, "\n")] = 0;
    
    // Tạo request với các trường cần update
    struct json_object *request = json_object_new_object();
    json_object_object_add(request, "command", json_object_new_string("UPDATE_PROFILE"));
    
    struct json_object *data = json_object_new_object();
    json_object_object_add(data, "session_token", json_object_new_string(g_session_token));
    json_object_object_add(data, "email", json_object_new_string(email));
    json_object_object_add(data, "full_name", json_object_new_string(full_name));
    json_object_object_add(request, "data", data);
    
    const char *json_str = json_object_to_json_string(request);
    send(sock, json_str, strlen(json_str), 0);
    
    json_object_put(request);
    
    // Nhận response
    char buffer[BUFFER_SIZE];
    int bytes = recv(sock, buffer, BUFFER_SIZE - 1, 0);
    buffer[bytes] = '\0';
    
    parse_and_display_response(buffer);
    wait_for_enter();
}

/**
 * Đổi mật khẩu tài khoản
 * @param sock: Socket đã kết nối tới server
 * 
 * Yêu cầu: old_password (để xác nhận), new_password
 * Server sẽ verify old_password trước khi cập nhật
 */
void send_change_password_request(int sock) {
    char old_pass[MAX_PASSWORD], new_pass[MAX_PASSWORD];
    
    clear_screen();
    printf("\n=== CHANGE PASSWORD ===\n");
    
    // Kiểm tra authentication
    if (strlen(g_session_token) == 0) {
        print_error("Please login first!");
        wait_for_enter();
        return;
    }
    
    // Nhập mật khẩu cũ và mới
    printf("Old password: ");
    scanf("%s", old_pass);
    printf("New password: ");
    scanf("%s", new_pass);
    
    // Tạo request với cả 2 password
    struct json_object *request = json_object_new_object();
    json_object_object_add(request, "command", json_object_new_string("CHANGE_PASSWORD"));
    
    struct json_object *data = json_object_new_object();
    json_object_object_add(data, "session_token", json_object_new_string(g_session_token));
    json_object_object_add(data, "old_password", json_object_new_string(old_pass));
    json_object_object_add(data, "new_password", json_object_new_string(new_pass));
    json_object_object_add(request, "data", data);
    
    const char *json_str = json_object_to_json_string(request);
    send(sock, json_str, strlen(json_str), 0);
    
    json_object_put(request);
    
    // Nhận response
    char buffer[BUFFER_SIZE];
    int bytes = recv(sock, buffer, BUFFER_SIZE - 1, 0);
    buffer[bytes] = '\0';
    
    parse_and_display_response(buffer);
    wait_for_enter();
}

// ============================================================================
// PERMISSION MANAGEMENT - QUẢN LÝ QUYỀN TRUY CẬP
// ============================================================================

/**
 * Lấy danh sách quyền của user trong một group cụ thể
 * @param sock: Socket đã kết nối tới server
 * 
 * Hiển thị các quyền: READ, WRITE, DELETE, MANAGE_MEMBERS, etc.
 */
void send_get_permissions_request(int sock) {
    int group_id;
    
    clear_screen();
    printf("\n=== GET PERMISSIONS ===\n");
    
    // Kiểm tra authentication
    if (strlen(g_session_token) == 0) {
        print_error("Please login first!");
        wait_for_enter();
        return;
    }
    
    // Nhập group_id cần kiểm tra quyền
    printf("Group ID: ");
    scanf("%d", &group_id);
    
    // Tạo request
    struct json_object *request = json_object_new_object();
    json_object_object_add(request, "command", json_object_new_string("GET_PERMISSIONS"));
    
    struct json_object *data = json_object_new_object();
    json_object_object_add(data, "session_token", json_object_new_string(g_session_token));
    json_object_object_add(data, "group_id", json_object_new_int(group_id));
    json_object_object_add(request, "data", data);
    
    const char *json_str = json_object_to_json_string(request);
    send(sock, json_str, strlen(json_str), 0);
    
    json_object_put(request);
    
    // Nhận và parse response để hiển thị permissions
    char buffer[BUFFER_SIZE];
    int bytes = recv(sock, buffer, BUFFER_SIZE - 1, 0);
    buffer[bytes] = '\0';
    
    parse_and_display_response(buffer);
    wait_for_enter();
}

/**
 * Cập nhật quyền của một user trong group (chỉ admin/owner)
 * @param sock: Socket đã kết nối tới server
 * 
 * Quyền có thể cấp: can_read, can_write, can_delete, can_manage
 * Yêu cầu quyền ADMIN hoặc GROUP_OWNER
 */
void send_update_permissions_request(int sock) {
    int group_id, target_user_id;
    int can_read, can_write, can_delete, can_manage;
    
    clear_screen();
    printf("\n=== UPDATE PERMISSIONS ===\n");
    
    // Kiểm tra authentication
    if (strlen(g_session_token) == 0) {
        print_error("Please login first!");
        wait_for_enter();
        return;
    }
    
    // Nhập thông tin: group, target user, permissions mới
    printf("Group ID: ");
    scanf("%d", &group_id);
    printf("Target User ID: ");
    scanf("%d", &target_user_id);
    printf("Can read (1/0): ");
    scanf("%d", &can_read);
    printf("Can write (1/0): ");
    scanf("%d", &can_write);
    printf("Can delete (1/0): ");
    scanf("%d", &can_delete);
    printf("Can manage (1/0): ");
    scanf("%d", &can_manage);
    
    // Tạo request với tất cả các quyền mới
    struct json_object *request = json_object_new_object();
    json_object_object_add(request, "command", json_object_new_string("UPDATE_PERMISSIONS"));
    
    struct json_object *data = json_object_new_object();
    json_object_object_add(data, "session_token", json_object_new_string(g_session_token));
    json_object_object_add(data, "group_id", json_object_new_int(group_id));
    json_object_object_add(data, "target_user_id", json_object_new_int(target_user_id));
    json_object_object_add(data, "can_read", json_object_new_boolean(can_read));
    json_object_object_add(data, "can_write", json_object_new_boolean(can_write));
    json_object_object_add(data, "can_delete", json_object_new_boolean(can_delete));
    json_object_object_add(data, "can_manage", json_object_new_boolean(can_manage));
    json_object_object_add(request, "data", data);
    
    const char *json_str = json_object_to_json_string(request);
    send(sock, json_str, strlen(json_str), 0);
    
    json_object_put(request);
    
    // Nhận response
    char buffer[BUFFER_SIZE];
    int bytes = recv(sock, buffer, BUFFER_SIZE - 1, 0);
    buffer[bytes] = '\0';
    
    parse_and_display_response(buffer);
    wait_for_enter();
}

// ============================================================================
// GROUP MANAGEMENT - QUẢN LÝ NHÓM CHIA SẺ
// ============================================================================

/**
 * Tạo nhóm mới để chia sẻ file
 * @param sock: Socket đã kết nối tới server
 * 
 * User tạo group sẽ trở thành OWNER với full quyền
 * Nhập: group_name, description
 */
void send_create_group_request(int sock) {
    char group_name[101], description[256];
    
    clear_screen();
    printf("\n=== CREATE GROUP ===\n");
    printf("\n📋 Instructions:\n");
    printf("   - Group name: 3-100 characters\n");
    printf("   - Description: Optional, max 255 characters\n");
    printf("   - You will become the OWNER with full permissions\n");
    print_separator();
    
    // Kiểm tra authentication
    if (strlen(g_session_token) == 0) {
        print_error("Please login first!");
        wait_for_enter();
        return;
    }
    
    // Nhập thông tin group với validation
    printf("\n📝 Group name: ");
    // Không cần getchar() ở đây vì không có scanf trước đó
    fgets(group_name, 101, stdin);
    group_name[strcspn(group_name, "\n")] = 0;
    
    // Validation: group name không được rỗng và phải >= 3 ký tự
    if (strlen(group_name) == 0) {
        print_error("Group name cannot be empty!");
        wait_for_enter();
        return;
    }
    if (strlen(group_name) < 3) {
        print_error("Group name must be at least 3 characters!");
        wait_for_enter();
        return;
    }
    
    printf("📝 Description (press ENTER to skip): ");
    fgets(description, 256, stdin);
    description[strcspn(description, "\n")] = 0;
    
    // Confirmation
    printf("\n✓ Review your group information:\n");
    printf("  Name: %s\n", group_name);
    printf("  Description: %s\n", strlen(description) > 0 ? description : "(none)");
    printf("\n❓ Confirm create group? (yes/no): ");
    char confirm[10];
    scanf("%s", confirm);
    if (strcasecmp(confirm, "yes") != 0 && strcasecmp(confirm, "y") != 0) {
        printf("\n❌ Group creation cancelled.\n");
        wait_for_enter();
        return;
    }
    
    struct json_object *request = json_object_new_object();
    json_object_object_add(request, "command", json_object_new_string("CREATE_GROUP"));
    
    struct json_object *data = json_object_new_object();
    json_object_object_add(data, "session_token", json_object_new_string(g_session_token));
    json_object_object_add(data, "group_name", json_object_new_string(group_name));
    json_object_object_add(data, "description", json_object_new_string(description));
    json_object_object_add(request, "data", data);
    
    const char *json_str = json_object_to_json_string(request);
    send(sock, json_str, strlen(json_str), 0);
    
    json_object_put(request);
    
    // Receive response
    char buffer[BUFFER_SIZE];
    int bytes = recv(sock, buffer, BUFFER_SIZE - 1, 0);
    buffer[bytes] = '\0';
    
    parse_and_display_response(buffer);
    wait_for_enter();
}

/**
 * Liệt kê danh sách các nhóm mà user tham gia
 * @param sock: Socket đã kết nối tới server
 * 
 * Hiển thị: group_id, group_name, role (owner/admin/member), member_count
 */
void send_list_my_groups_request(int sock) {
    clear_screen();
    printf("\n=== LIST MY GROUPS ===\n");
    
    // Kiểm tra authentication
    if (strlen(g_session_token) == 0) {
        print_error("Please login first!");
        wait_for_enter();
        return;
    }
    
    // Tạo request
    struct json_object *request = json_object_new_object();
    json_object_object_add(request, "command", json_object_new_string("LIST_MY_GROUPS"));
    
    struct json_object *data = json_object_new_object();
    json_object_object_add(data, "session_token", json_object_new_string(g_session_token));
    json_object_object_add(request, "data", data);
    
    const char *json_str = json_object_to_json_string(request);
    send(sock, json_str, strlen(json_str), 0);
    
    json_object_put(request);
    
    // Nhận và hiển thị danh sách groups
    char buffer[BUFFER_SIZE];
    int bytes = recv(sock, buffer, BUFFER_SIZE - 1, 0);
    buffer[bytes] = '\0';
    
    parse_and_display_response(buffer);
    wait_for_enter();
}

/**
 * Liệt kê danh sách thành viên trong một nhóm
 * @param sock: Socket đã kết nối tới server
 * 
 * Quy trình:
 * 1. Lấy danh sách tất cả groups của user
 * 2. Hiển thị để user chọn group
 * 3. Gửi request lấy members của group đã chọn
 * 4. Hiển thị: user_id, username, role, permissions
 */
void send_list_group_members_request(int sock) {
    clear_screen();
    printf("\n=== LIST GROUP MEMBERS ===\n");
    
    // Kiểm tra authentication
    if (strlen(g_session_token) == 0) {
        print_error("Please login first!");
        wait_for_enter();
        return;
    }
    
    // Bước 1: Lấy danh sách tất cả groups
    struct json_object *list_req = json_object_new_object();
    json_object_object_add(list_req, "command", json_object_new_string("LIST_MY_GROUPS"));
    
    struct json_object *list_data = json_object_new_object();
    json_object_object_add(list_data, "session_token", json_object_new_string(g_session_token));
    json_object_object_add(list_req, "data", list_data);
    
    const char *list_json = json_object_to_json_string(list_req);
    send(sock, list_json, strlen(list_json), 0);
    json_object_put(list_req);
    
    // Nhận danh sách groups
    char list_buffer[BUFFER_SIZE];
    int list_bytes = recv(sock, list_buffer, BUFFER_SIZE - 1, 0);
    list_buffer[list_bytes] = '\0';
    
    struct json_object *list_response = json_tokener_parse(list_buffer);
    if (!list_response) {
        print_error("Failed to get groups list");
        wait_for_enter();
        return;
    }
    
    struct json_object *status_obj, *payload_obj, *groups_obj;
    json_object_object_get_ex(list_response, "status", &status_obj);
    json_object_object_get_ex(list_response, "payload", &payload_obj);
    
    if (json_object_get_int(status_obj) != 200 || !payload_obj) {
        print_error("Failed to retrieve groups");
        json_object_put(list_response);
        wait_for_enter();
        return;
    }
    
    json_object_object_get_ex(payload_obj, "groups", &groups_obj);
    int group_count = json_object_array_length(groups_obj);
    
    if (group_count == 0) {
        printf("\n📭 No groups available.\n");
        json_object_put(list_response);
        wait_for_enter();
        return;
    }
    
    // Hiển thị danh sách groups với thông tin chi tiết
    printf("\n👥 Your Groups (%d):\n", group_count);
    print_separator();
    for (int i = 0; i < group_count; i++) {
        struct json_object *group = json_object_array_get_idx(groups_obj, i);
        struct json_object *id_obj, *name_obj, *member_count_obj, *role_obj;
        json_object_object_get_ex(group, "group_id", &id_obj);
        json_object_object_get_ex(group, "group_name", &name_obj);
        json_object_object_get_ex(group, "member_count", &member_count_obj);
        json_object_object_get_ex(group, "role", &role_obj);
        
        const char *role = role_obj ? json_object_get_string(role_obj) : "member";
        const char *role_icon = strcmp(role, "owner") == 0 ? "👑" : 
                                 strcmp(role, "admin") == 0 ? "⚡" : "👤";
        
        printf("%s [%d] %s (Role: %s | Members: %d)\n", 
               role_icon,
               json_object_get_int(id_obj),
               json_object_get_string(name_obj),
               role,
               json_object_get_int(member_count_obj));
    }
    print_separator();
    
    // Cho người dùng chọn
    int selected_group_id;
    printf("\nEnter Group ID to view members (0 to cancel): ");
    scanf("%d", &selected_group_id);
    
    json_object_put(list_response);
    
    if (selected_group_id == 0) {
        return;
    }
    
    // Bước 2: Lấy danh sách members của group đã chọn
    struct json_object *member_req = json_object_new_object();
    json_object_object_add(member_req, "command", json_object_new_string("LIST_GROUP_MEMBERS"));
    
    struct json_object *member_data = json_object_new_object();
    json_object_object_add(member_data, "session_token", json_object_new_string(g_session_token));
    json_object_object_add(member_data, "group_id", json_object_new_int(selected_group_id));
    json_object_object_add(member_req, "data", member_data);
    
    const char *member_json = json_object_to_json_string(member_req);
    send(sock, member_json, strlen(member_json), 0);
    json_object_put(member_req);
    
    // Nhận danh sách members
    char member_buffer[BUFFER_SIZE];
    int member_bytes = recv(sock, member_buffer, BUFFER_SIZE - 1, 0);
    member_buffer[member_bytes] = '\0';
    
    parse_and_display_response(member_buffer);
    wait_for_enter();
}

/**
 * Gửi yêu cầu xin tham gia vào một nhóm
 * @param sock: Socket đã kết nối tới server
 * 
 * Quy trình:
 * 1. Lấy danh sách các nhóm có thể tham gia (chưa là thành viên)
 * 2. Hiển thị thông tin chi tiết của từng nhóm
 * 3. User chọn group và gửi request
 * 4. Admin/owner sẽ nhận được yêu cầu và phê duyệt
 */
void send_request_join_group_request(int sock) {
    clear_screen();
    printf("\n=== REQUEST JOIN GROUP ===\n");
    
    // Kiểm tra authentication
    if (strlen(g_session_token) == 0) {
        print_error("Please login first!");
        wait_for_enter();
        return;
    }
    
    // Bước 1: Lấy danh sách các nhóm có thể tham gia
    struct json_object *list_req = json_object_new_object();
    json_object_object_add(list_req, "command", json_object_new_string("LIST_AVAILABLE_GROUPS"));
    
    struct json_object *list_data = json_object_new_object();
    json_object_object_add(list_data, "session_token", json_object_new_string(g_session_token));
    json_object_object_add(list_req, "data", list_data);
    
    const char *list_json = json_object_to_json_string(list_req);
    send(sock, list_json, strlen(list_json), 0);
    json_object_put(list_req);
    
    // Nhận danh sách groups
    char list_buffer[BUFFER_SIZE];
    int list_bytes = recv(sock, list_buffer, BUFFER_SIZE - 1, 0);
    list_buffer[list_bytes] = '\0';
    
    struct json_object *list_response = json_tokener_parse(list_buffer);
    if (!list_response) {
        print_error("Failed to parse server response");
        printf("\n🔍 Raw response:\n%s\n", list_buffer);
        wait_for_enter();
        return;
    }
    
    struct json_object *status_obj, *payload_obj, *groups_obj;
    json_object_object_get_ex(list_response, "status", &status_obj);
    json_object_object_get_ex(list_response, "payload", &payload_obj);
    
    if (json_object_get_int(status_obj) != 200 || !payload_obj) {
        printf("\n❌ Failed to retrieve available groups\n");
        printf("\n📋 Server Response:\n");
        parse_and_display_response(list_buffer);
        json_object_put(list_response);
        wait_for_enter();
        return;
    }
    
    json_object_object_get_ex(payload_obj, "groups", &groups_obj);
    int group_count = json_object_array_length(groups_obj);
    
    if (group_count == 0) {
        printf("\n📭 No available groups to join.\n");
        printf("   You are already a member of all existing groups,\n");
        printf("   or you have pending requests/invitations for all other groups.\n");
        json_object_put(list_response);
        wait_for_enter();
        return;
    }
    
    // Hiển thị danh sách groups
        printf("\n🔍 Available Groups to Join (%d):\n", group_count);
    
    for (int i = 0; i < group_count; i++) {
        struct json_object *group = json_object_array_get_idx(groups_obj, i);
        struct json_object *id_obj, *name_obj, *desc_obj, *member_count_obj, *created_at_obj;
        json_object_object_get_ex(group, "group_id", &id_obj);
        json_object_object_get_ex(group, "group_name", &name_obj);
        json_object_object_get_ex(group, "description", &desc_obj);
        json_object_object_get_ex(group, "member_count", &member_count_obj);
        json_object_object_get_ex(group, "created_at", &created_at_obj);
        
        printf("\n┌─────────────────────────────────────────────────────┐\n");
        printf("│ [%d] %s\n", 
               json_object_get_int(id_obj),
               json_object_get_string(name_obj));
        printf("├─────────────────────────────────────────────────────┤\n");
        printf("│ 📝 Description: %s\n", json_object_get_string(desc_obj));
        printf("│ 👥 Members: %d\n", json_object_get_int(member_count_obj));
        printf("│ 📅 Created: %s\n", json_object_get_string(created_at_obj));
        printf("└─────────────────────────────────────────────────────┘\n");
    }
    
    // Cho người dùng chọn
    int selected_group_id;
    printf("\n➤ Enter Group ID to request join (0 to cancel): ");
    scanf("%d", &selected_group_id);
    getchar(); // consume newline
    
    json_object_put(list_response);
    
    if (selected_group_id == 0) {
        printf("\n❌ Request cancelled.\n");
        wait_for_enter();
        return;
    }
    
    // Bước 2: Gửi yêu cầu tham gia
    struct json_object *request = json_object_new_object();
    json_object_object_add(request, "command", json_object_new_string("REQUEST_JOIN_GROUP"));
    
    struct json_object *data = json_object_new_object();
    json_object_object_add(data, "session_token", json_object_new_string(g_session_token));
    json_object_object_add(data, "group_id", json_object_new_int(selected_group_id));
    json_object_object_add(request, "data", data);
    
    const char *json_str = json_object_to_json_string(request);
    send(sock, json_str, strlen(json_str), 0);
    json_object_put(request);
    
    // Receive response
    char buffer[BUFFER_SIZE];
    int bytes = recv(sock, buffer, BUFFER_SIZE - 1, 0);
    buffer[bytes] = '\0';
    
    parse_and_display_response(buffer);
    wait_for_enter();
}

/**
 * Liệt kê danh sách yêu cầu xin tham gia nhóm (chỉ admin/owner)
 * @param sock: Socket đã kết nối tới server
 * 
 * Hiển thị: request_id, user_id, username, requested_at, status
 * Admin/owner sử dụng thông tin này để phê duyệt/từ chối
 */
void send_list_join_requests_request(int sock) {
    clear_screen();
    printf("\n=== LIST JOIN REQUESTS (ADMIN) ===\n");
    printf("\n⚠️  Note: This function requires ADMIN or OWNER role\n");
    print_separator();
    
    // Kiểm tra authentication
    if (strlen(g_session_token) == 0) {
        print_error("Please login first!");
        wait_for_enter();
        return;
    }
    
    // Bước 1: Hiển thị danh sách groups của user (chỉ những group mà user là admin/owner)
    struct json_object *list_req = json_object_new_object();
    json_object_object_add(list_req, "command", json_object_new_string("LIST_MY_GROUPS"));
    
    struct json_object *list_data = json_object_new_object();
    json_object_object_add(list_data, "session_token", json_object_new_string(g_session_token));
    json_object_object_add(list_req, "data", list_data);
    
    const char *list_json = json_object_to_json_string(list_req);
    send(sock, list_json, strlen(list_json), 0);
    json_object_put(list_req);
    
    // Nhận danh sách groups
    char list_buffer[BUFFER_SIZE];
    int list_bytes = recv(sock, list_buffer, BUFFER_SIZE - 1, 0);
    list_buffer[list_bytes] = '\0';
    
    struct json_object *list_response = json_tokener_parse(list_buffer);
    if (!list_response) {
        print_error("Failed to get groups list");
        wait_for_enter();
        return;
    }
    
    struct json_object *status_obj, *payload_obj, *groups_obj;
    json_object_object_get_ex(list_response, "status", &status_obj);
    json_object_object_get_ex(list_response, "payload", &payload_obj);
    
    if (json_object_get_int(status_obj) != 200 || !payload_obj) {
        print_error("Failed to retrieve groups");
        json_object_put(list_response);
        wait_for_enter();
        return;
    }
    
    json_object_object_get_ex(payload_obj, "groups", &groups_obj);
    int group_count = json_object_array_length(groups_obj);
    
    if (group_count == 0) {
        printf("\n📭 No groups available. You must be a member of a group first.\n");
        json_object_put(list_response);
        wait_for_enter();
        return;
    }
    
    // Hiển thị danh sách groups (chỉ admin/owner)
    printf("\n👥 Your Groups (Admin/Owner only can view requests):\n");
    print_separator();
    int has_admin_group = 0;
    for (int i = 0; i < group_count; i++) {
        struct json_object *group = json_object_array_get_idx(groups_obj, i);
        struct json_object *id_obj, *name_obj, *role_obj;
        json_object_object_get_ex(group, "group_id", &id_obj);
        json_object_object_get_ex(group, "group_name", &name_obj);
        json_object_object_get_ex(group, "role", &role_obj);
        
        const char *role = role_obj ? json_object_get_string(role_obj) : "member";
        if (strcmp(role, "owner") == 0 || strcmp(role, "admin") == 0) {
            has_admin_group = 1;
            const char *role_icon = strcmp(role, "owner") == 0 ? "👑" : "⚡";
            printf("%s [%d] %s (Role: %s)\n", 
                   role_icon,
                   json_object_get_int(id_obj),
                   json_object_get_string(name_obj),
                   role);
        }
    }
    print_separator();
    
    if (!has_admin_group) {
        printf("\n⚠️  You don't have ADMIN or OWNER role in any group.\n");
        json_object_put(list_response);
        wait_for_enter();
        return;
    }
    
    // Nhập group_id cần xem requests
    int group_id;
    printf("\n➤ Enter Group ID to view join requests (0 to cancel): ");
    scanf("%d", &group_id);
    getchar(); // consume newline
    
    json_object_put(list_response);
    
    if (group_id == 0) {
        printf("\n❌ Cancelled.\n");
        wait_for_enter();
        return;
    }
    
    // Tạo request
    struct json_object *request = json_object_new_object();
    json_object_object_add(request, "command", json_object_new_string("LIST_JOIN_REQUESTS"));
    
    struct json_object *data = json_object_new_object();
    json_object_object_add(data, "session_token", json_object_new_string(g_session_token));
    json_object_object_add(data, "group_id", json_object_new_int(group_id));
    json_object_object_add(request, "data", data);
    
    const char *json_str = json_object_to_json_string(request);
    send(sock, json_str, strlen(json_str), 0);
    
    json_object_put(request);
    
    // Nhận và hiển thị danh sách requests
    char buffer[BUFFER_SIZE];
    int bytes = recv(sock, buffer, BUFFER_SIZE - 1, 0);
    buffer[bytes] = '\0';
    
    parse_and_display_response(buffer);
    wait_for_enter();
}

/**
 * Phê duyệt hoặc từ chối yêu cầu tham gia nhóm (admin/owner)
 * @param sock: Socket đã kết nối tới server
 * 
 * Action: "APPROVE" hoặc "REJECT"
 * Nếu approve: User sẽ được thêm vào group
 * Nếu reject: Request sẽ bị xóa
 */
void send_approve_join_request_request(int sock) {
    char action[20];
    int request_id;
    
    clear_screen();
    printf("\n=== APPROVE/REJECT JOIN REQUEST ===\n");
    printf("\n📋 Instructions:\n");
    printf("   - 'approve': Accept user into group\n");
    printf("   - 'reject': Decline the request\n");
    printf("   💡 Tip: Use LIST JOIN REQUESTS first to see pending requests\n");
    print_separator();
    
    // Kiểm tra authentication
    if (strlen(g_session_token) == 0) {
        print_error("Please login first!");
        wait_for_enter();
        return;
    }
    
    // Nhập thông tin request cần xử lý
    printf("\n🆔 Request ID (0 to cancel): ");
    scanf("%d", &request_id);
    
    if (request_id == 0) {
        printf("\n❌ Cancelled.\n");
        wait_for_enter();
        return;
    }
    
    printf("🎯 Action (approve/reject): ");
    scanf("%s", action);
    
    // Validation action
    if (strcasecmp(action, "approve") != 0 && strcasecmp(action, "reject") != 0) {
        print_error("Invalid action! Must be 'approve' or 'reject'");
        wait_for_enter();
        return;
    }
    
    // Confirmation
    printf("\n❓ Confirm %s request ID %d? (yes/no): ", action, request_id);
    char confirm[10];
    scanf("%s", confirm);
    if (strcasecmp(confirm, "yes") != 0 && strcasecmp(confirm, "y") != 0) {
        printf("\n❌ Action cancelled.\n");
        wait_for_enter();
        return;
    }
    
    // Tạo request với action (approve/reject)
    struct json_object *request = json_object_new_object();
    json_object_object_add(request, "command", json_object_new_string("APPROVE_JOIN_REQUEST"));
    
    struct json_object *data = json_object_new_object();
    json_object_object_add(data, "session_token", json_object_new_string(g_session_token));
    json_object_object_add(data, "request_id", json_object_new_int(request_id));
    json_object_object_add(data, "action", json_object_new_string(action));
    json_object_object_add(request, "data", data);
    
    const char *json_str = json_object_to_json_string(request);
    send(sock, json_str, strlen(json_str), 0);
    
    json_object_put(request);
    
    // Nhận response
    char buffer[BUFFER_SIZE];
    int bytes = recv(sock, buffer, BUFFER_SIZE - 1, 0);
    buffer[bytes] = '\0';
    
    parse_and_display_response(buffer);
    wait_for_enter();
}

/**
 * Mời user khác vào nhóm (admin/owner)
 * @param sock: Socket đã kết nối tới server
 * 
 * Admin/owner nhập username của người muốn mời
 * Người được mời sẽ nhận invitation và có thể accept/reject
 */
void send_invite_to_group_request(int sock) {
    char invitee_username[MAX_USERNAME];
    
    clear_screen();
    printf("\n=== INVITE TO GROUP ===\n");
    printf("\n⚠️  Note: This function requires ADMIN or OWNER role\n");
    print_separator();
    
    // Kiểm tra authentication
    if (strlen(g_session_token) == 0) {
        print_error("Please login first!");
        wait_for_enter();
        return;
    }
    
    // Bước 1: Hiển thị danh sách groups của user (chỉ những group mà user là admin/owner)
    struct json_object *list_req = json_object_new_object();
    json_object_object_add(list_req, "command", json_object_new_string("LIST_MY_GROUPS"));
    
    struct json_object *list_data = json_object_new_object();
    json_object_object_add(list_data, "session_token", json_object_new_string(g_session_token));
    json_object_object_add(list_req, "data", list_data);
    
    const char *list_json = json_object_to_json_string(list_req);
    send(sock, list_json, strlen(list_json), 0);
    json_object_put(list_req);
    
    // Nhận danh sách groups
    char list_buffer[BUFFER_SIZE];
    int list_bytes = recv(sock, list_buffer, BUFFER_SIZE - 1, 0);
    list_buffer[list_bytes] = '\0';
    
    struct json_object *list_response = json_tokener_parse(list_buffer);
    if (!list_response) {
        print_error("Failed to get groups list");
        wait_for_enter();
        return;
    }
    
    struct json_object *status_obj, *payload_obj, *groups_obj;
    json_object_object_get_ex(list_response, "status", &status_obj);
    json_object_object_get_ex(list_response, "payload", &payload_obj);
    
    if (json_object_get_int(status_obj) != 200 || !payload_obj) {
        print_error("Failed to retrieve groups");
        json_object_put(list_response);
        wait_for_enter();
        return;
    }
    
    json_object_object_get_ex(payload_obj, "groups", &groups_obj);
    int group_count = json_object_array_length(groups_obj);
    
    if (group_count == 0) {
        printf("\n📭 No groups available.\n");
        json_object_put(list_response);
        wait_for_enter();
        return;
    }
    
    // Hiển thị danh sách groups (chỉ admin/owner)
    printf("\n👥 Your Groups (where you can invite members):\n");
    print_separator();
    int has_admin_group = 0;
    for (int i = 0; i < group_count; i++) {
        struct json_object *group = json_object_array_get_idx(groups_obj, i);
        struct json_object *id_obj, *name_obj, *role_obj, *member_count_obj;
        json_object_object_get_ex(group, "group_id", &id_obj);
        json_object_object_get_ex(group, "group_name", &name_obj);
        json_object_object_get_ex(group, "role", &role_obj);
        json_object_object_get_ex(group, "member_count", &member_count_obj);
        
        const char *role = role_obj ? json_object_get_string(role_obj) : "member";
        if (strcmp(role, "owner") == 0 || strcmp(role, "admin") == 0) {
            has_admin_group = 1;
            const char *role_icon = strcmp(role, "owner") == 0 ? "👑" : "⚡";
            printf("%s [%d] %s (Role: %s | Members: %d)\n", 
                   role_icon,
                   json_object_get_int(id_obj),
                   json_object_get_string(name_obj),
                   role,
                   json_object_get_int(member_count_obj));
        }
    }
    print_separator();
    
    if (!has_admin_group) {
        printf("\n⚠️  You don't have ADMIN or OWNER role in any group.\n");
        json_object_put(list_response);
        wait_for_enter();
        return;
    }
    
    // Nhập thông tin: group và username người được mời
    int group_id;
    printf("\n➤ Enter Group ID (0 to cancel): ");
    scanf("%d", &group_id);
    getchar(); // consume newline
    
    json_object_put(list_response);
    
    if (group_id == 0) {
        printf("\n❌ Cancelled.\n");
        wait_for_enter();
        return;
    }
    
    printf("👤 Enter username to invite: ");
    scanf("%s", invitee_username);
    
    // Validation
    if (strlen(invitee_username) == 0) {
        print_error("Username cannot be empty!");
        wait_for_enter();
        return;
    }
    
    // Confirmation
    printf("\n✓ You are inviting '%s' to group ID %d\n", invitee_username, group_id);
    printf("❓ Confirm? (yes/no): ");
    char confirm[10];
    scanf("%s", confirm);
    if (strcasecmp(confirm, "yes") != 0 && strcasecmp(confirm, "y") != 0) {
        printf("\n❌ Invitation cancelled.\n");
        wait_for_enter();
        return;
    }
    
    // Tạo invitation request
    struct json_object *request = json_object_new_object();
    json_object_object_add(request, "command", json_object_new_string("INVITE_TO_GROUP"));
    
    struct json_object *data = json_object_new_object();
    json_object_object_add(data, "session_token", json_object_new_string(g_session_token));
    json_object_object_add(data, "group_id", json_object_new_int(group_id));
    json_object_object_add(data, "invitee_username", json_object_new_string(invitee_username));
    json_object_object_add(request, "data", data);
    
    const char *json_str = json_object_to_json_string(request);
    send(sock, json_str, strlen(json_str), 0);
    
    json_object_put(request);
    
    // Nhận response
    char buffer[BUFFER_SIZE];
    int bytes = recv(sock, buffer, BUFFER_SIZE - 1, 0);
    buffer[bytes] = '\0';
    
    parse_and_display_response(buffer);
    wait_for_enter();
}

/**
 * Liệt kê các lời mời tham gia nhóm của user
 * @param sock: Socket đã kết nối tới server
 * 
 * Hiển thị: invitation_id, group_name, inviter_username, invited_at
 * User có thể dùng thông tin này để accept/reject invitation
 */
void send_list_my_invitations_request(int sock) {
    clear_screen();
    printf("\n=== LIST MY INVITATIONS ===\n");
    
    // Tạo request lấy danh sách invitations
    struct json_object *request = json_object_new_object();
    json_object_object_add(request, "command", json_object_new_string("LIST_MY_INVITATIONS"));
    
    struct json_object *data = json_object_new_object();
    json_object_object_add(data, "session_token", json_object_new_string(g_session_token));
    json_object_object_add(request, "data", data);
    
    const char *json_str = json_object_to_json_string(request);
    send(sock, json_str, strlen(json_str), 0);
    
    json_object_put(request);
    
    // Nhận và hiển thị danh sách invitations
    char buffer[BUFFER_SIZE];
    int bytes = recv(sock, buffer, BUFFER_SIZE - 1, 0);
    buffer[bytes] = '\0';
    
    parse_and_display_response(buffer);
    wait_for_enter();
}

/**
 * Phản hồi lời mời tham gia nhóm
 * @param sock: Socket đã kết nối tới server
 * 
 * Action: "accept" hoặc "reject"
 * Nếu accept: User sẽ trở thành member của group
 * Nếu reject: Invitation sẽ bị xóa
 */
void send_respond_invitation_request(int sock) {
    char action[20];
    int invitation_id;
    
    clear_screen();
    printf("\n=== RESPOND TO INVITATION ===\n");
    printf("\n📋 Instructions:\n");
    printf("   - 'accept': Join the group\n");
    printf("   - 'reject': Decline the invitation\n");
    printf("   💡 Tip: Use LIST MY INVITATIONS first to see pending invitations\n");
    print_separator();
    
    // Kiểm tra authentication
    if (strlen(g_session_token) == 0) {
        print_error("Please login first!");
        wait_for_enter();
        return;
    }
    
    // Nhập invitation ID và action
    printf("\n🆔 Invitation ID (0 to cancel): ");
    scanf("%d", &invitation_id);
    
    if (invitation_id == 0) {
        printf("\n❌ Cancelled.\n");
        wait_for_enter();
        return;
    }
    
    printf("🎯 Action (accept/reject): ");
    scanf("%s", action);
    
    // Validation
    if (strcasecmp(action, "accept") != 0 && strcasecmp(action, "reject") != 0) {
        print_error("Invalid action! Must be 'accept' or 'reject'");
        wait_for_enter();
        return;
    }
    
    // Confirmation
    printf("\n❓ Confirm %s invitation ID %d? (yes/no): ", action, invitation_id);
    char confirm[10];
    scanf("%s", confirm);
    if (strcasecmp(confirm, "yes") != 0 && strcasecmp(confirm, "y") != 0) {
        printf("\n❌ Action cancelled.\n");
        wait_for_enter();
        return;
    }
    
    // Tạo response request
    struct json_object *request = json_object_new_object();
    json_object_object_add(request, "command", json_object_new_string("RESPOND_INVITATION"));
    
    struct json_object *data = json_object_new_object();
    json_object_object_add(data, "session_token", json_object_new_string(g_session_token));
    json_object_object_add(data, "invitation_id", json_object_new_int(invitation_id));
    json_object_object_add(data, "action", json_object_new_string(action));
    json_object_object_add(request, "data", data);
    
    const char *json_str = json_object_to_json_string(request);
    send(sock, json_str, strlen(json_str), 0);
    
    json_object_put(request);
    
    // Nhận response
    char buffer[BUFFER_SIZE];
    int bytes = recv(sock, buffer, BUFFER_SIZE - 1, 0);
    buffer[bytes] = '\0';
    
    parse_and_display_response(buffer);
    wait_for_enter();
}

/**
 * Rời khỏi nhóm (tự nguyện)
 * @param sock: Socket đã kết nối tới server
 * 
 * User sẽ bị xóa khỏi group và mất quyền truy cập
 * Lưu ý: Owner không thể leave, phải transfer ownership trước
 */
void send_leave_group_request(int sock) {
    clear_screen();
    printf("\n=== LEAVE GROUP ===\n");
    printf("\n⚠️  WARNING:\n");
    printf("   - You will lose access to all group files and folders\n");
    printf("   - Owners cannot leave (must transfer ownership first)\n");
    printf("   - This action cannot be undone\n");
    print_separator();
    
    // Kiểm tra authentication
    if (strlen(g_session_token) == 0) {
        print_error("Please login first!");
        wait_for_enter();
        return;
    }
    
    // Bước 1: Hiển thị danh sách groups của user
    struct json_object *list_req = json_object_new_object();
    json_object_object_add(list_req, "command", json_object_new_string("LIST_MY_GROUPS"));
    
    struct json_object *list_data = json_object_new_object();
    json_object_object_add(list_data, "session_token", json_object_new_string(g_session_token));
    json_object_object_add(list_req, "data", list_data);
    
    const char *list_json = json_object_to_json_string(list_req);
    send(sock, list_json, strlen(list_json), 0);
    json_object_put(list_req);
    
    // Nhận danh sách groups
    char list_buffer[BUFFER_SIZE];
    int list_bytes = recv(sock, list_buffer, BUFFER_SIZE - 1, 0);
    list_buffer[list_bytes] = '\0';
    
    struct json_object *list_response = json_tokener_parse(list_buffer);
    if (!list_response) {
        print_error("Failed to get groups list");
        wait_for_enter();
        return;
    }
    
    struct json_object *status_obj, *payload_obj, *groups_obj;
    json_object_object_get_ex(list_response, "status", &status_obj);
    json_object_object_get_ex(list_response, "payload", &payload_obj);
    
    if (json_object_get_int(status_obj) != 200 || !payload_obj) {
        print_error("Failed to retrieve groups");
        json_object_put(list_response);
        wait_for_enter();
        return;
    }
    
    json_object_object_get_ex(payload_obj, "groups", &groups_obj);
    int group_count = json_object_array_length(groups_obj);
    
    if (group_count == 0) {
        printf("\n📭 No groups available.\n");
        json_object_put(list_response);
        wait_for_enter();
        return;
    }
    
    // Hiển thị danh sách groups
    printf("\n👥 Your Groups:\n");
    print_separator();
    for (int i = 0; i < group_count; i++) {
        struct json_object *group = json_object_array_get_idx(groups_obj, i);
        struct json_object *id_obj, *name_obj, *role_obj, *member_count_obj;
        json_object_object_get_ex(group, "group_id", &id_obj);
        json_object_object_get_ex(group, "group_name", &name_obj);
        json_object_object_get_ex(group, "role", &role_obj);
        json_object_object_get_ex(group, "member_count", &member_count_obj);
        
        const char *role = role_obj ? json_object_get_string(role_obj) : "member";
        const char *role_icon = strcmp(role, "owner") == 0 ? "👑" : 
                                 strcmp(role, "admin") == 0 ? "⚡" : "👤";
        
        printf("%s [%d] %s (Role: %s | Members: %d)", 
               role_icon,
               json_object_get_int(id_obj),
               json_object_get_string(name_obj),
               role,
               json_object_get_int(member_count_obj));
        
        if (strcmp(role, "owner") == 0) {
            printf(" ⚠️  Cannot leave - you are owner");
        }
        printf("\n");
    }
    print_separator();
    
    // Nhập group_id muốn rời
    int group_id;
    printf("\n➤ Enter Group ID to leave (0 to cancel): ");
    scanf("%d", &group_id);
    
    json_object_put(list_response);
    
    if (group_id == 0) {
        printf("\n❌ Cancelled.\n");
        wait_for_enter();
        return;
    }
    
    // Double confirmation vì đây là action quan trọng
    printf("\n⚠️  FINAL CONFIRMATION\n");
    printf("Are you absolutely sure you want to leave group ID %d?\n", group_id);
    printf("This will remove all your access to group files!\n");
    printf("Type 'LEAVE' to confirm: ");
    char confirm[20];
    scanf("%s", confirm);
    if (strcmp(confirm, "LEAVE") != 0) {
        printf("\n❌ Leave cancelled (confirmation failed).\n");
        wait_for_enter();
        return;
    }
    
    // Tạo leave request
    struct json_object *request = json_object_new_object();
    json_object_object_add(request, "command", json_object_new_string("LEAVE_GROUP"));
    
    struct json_object *data = json_object_new_object();
    json_object_object_add(data, "session_token", json_object_new_string(g_session_token));
    json_object_object_add(data, "group_id", json_object_new_int(group_id));
    json_object_object_add(request, "data", data);
    
    const char *json_str = json_object_to_json_string(request);
    send(sock, json_str, strlen(json_str), 0);
    
    json_object_put(request);
    
    // Nhận response
    char buffer[BUFFER_SIZE];
    int bytes = recv(sock, buffer, BUFFER_SIZE - 1, 0);
    buffer[bytes] = '\0';
    
    parse_and_display_response(buffer);
    wait_for_enter();
}

/**
 * Xóa thành viên khỏi nhóm (admin/owner)
 * @param sock: Socket đã kết nối tới server
 * 
 * Chỉ admin/owner mới có quyền remove members
 * Member bị xóa sẽ mất tất cả quyền truy cập vào group
 */
void send_remove_member_request(int sock) {
    clear_screen();
    printf("\n=== REMOVE MEMBER ===\n");
    printf("\n⚠️  Note: This function requires ADMIN or OWNER role\n");
    printf("⚠️  WARNING: Removed members lose all access to group files\n");
    print_separator();
    
    // Kiểm tra authentication
    if (strlen(g_session_token) == 0) {
        print_error("Please login first!");
        wait_for_enter();
        return;
    }
    
    // Bước 1: Hiển thị danh sách groups của user
    struct json_object *list_req = json_object_new_object();
    json_object_object_add(list_req, "command", json_object_new_string("LIST_MY_GROUPS"));
    
    struct json_object *list_data = json_object_new_object();
    json_object_object_add(list_data, "session_token", json_object_new_string(g_session_token));
    json_object_object_add(list_req, "data", list_data);
    
    const char *list_json = json_object_to_json_string(list_req);
    send(sock, list_json, strlen(list_json), 0);
    json_object_put(list_req);
    
    // Nhận danh sách groups
    char list_buffer[BUFFER_SIZE];
    int list_bytes = recv(sock, list_buffer, BUFFER_SIZE - 1, 0);
    list_buffer[list_bytes] = '\0';
    
    struct json_object *list_response = json_tokener_parse(list_buffer);
    if (!list_response) {
        print_error("Failed to get groups list");
        wait_for_enter();
        return;
    }
    
    struct json_object *status_obj, *payload_obj, *groups_obj;
    json_object_object_get_ex(list_response, "status", &status_obj);
    json_object_object_get_ex(list_response, "payload", &payload_obj);
    
    if (json_object_get_int(status_obj) != 200 || !payload_obj) {
        print_error("Failed to retrieve groups");
        json_object_put(list_response);
        wait_for_enter();
        return;
    }
    
    json_object_object_get_ex(payload_obj, "groups", &groups_obj);
    int group_count = json_object_array_length(groups_obj);
    
    if (group_count == 0) {
        printf("\n📭 No groups available.\n");
        json_object_put(list_response);
        wait_for_enter();
        return;
    }
    
    // Hiển thị danh sách groups (chỉ admin/owner)
    printf("\n👥 Your Groups (where you can remove members):\n");
    print_separator();
    int has_admin_group = 0;
    for (int i = 0; i < group_count; i++) {
        struct json_object *group = json_object_array_get_idx(groups_obj, i);
        struct json_object *id_obj, *name_obj, *role_obj, *member_count_obj;
        json_object_object_get_ex(group, "group_id", &id_obj);
        json_object_object_get_ex(group, "group_name", &name_obj);
        json_object_object_get_ex(group, "role", &role_obj);
        json_object_object_get_ex(group, "member_count", &member_count_obj);
        
        const char *role = role_obj ? json_object_get_string(role_obj) : "member";
        if (strcmp(role, "owner") == 0 || strcmp(role, "admin") == 0) {
            has_admin_group = 1;
            const char *role_icon = strcmp(role, "owner") == 0 ? "👑" : "⚡";
            printf("%s [%d] %s (Role: %s | Members: %d)\n", 
                   role_icon,
                   json_object_get_int(id_obj),
                   json_object_get_string(name_obj),
                   role,
                   json_object_get_int(member_count_obj));
        }
    }
    print_separator();
    
    if (!has_admin_group) {
        printf("\n⚠️  You don't have ADMIN or OWNER role in any group.\n");
        json_object_put(list_response);
        wait_for_enter();
        return;
    }
    
    // Nhập thông tin: group và user cần xóa
    int group_id;
    printf("\n➤ Enter Group ID (0 to cancel): ");
    scanf("%d", &group_id);
    
    json_object_put(list_response);
    
    if (group_id == 0) {
        printf("\n❌ Cancelled.\n");
        wait_for_enter();
        return;
    }
    
    printf("\n💡 Tip: Use LIST GROUP MEMBERS first to see member IDs\n");
    
    int target_user_id;
    printf("👤 Target User ID to remove: ");
    scanf("%d", &target_user_id);
    
    // Confirmation
    printf("\n⚠️  CONFIRMATION\n");
    printf("You are about to REMOVE user ID %d from group ID %d\n", target_user_id, group_id);
    printf("This user will lose all access to group files!\n");
    printf("❓ Are you sure? (yes/no): ");
    char confirm[10];
    scanf("%s", confirm);
    if (strcasecmp(confirm, "yes") != 0 && strcasecmp(confirm, "y") != 0) {
        printf("\n❌ Remove cancelled.\n");
        wait_for_enter();
        return;
    }
    
    // Tạo remove request
    struct json_object *request = json_object_new_object();
    json_object_object_add(request, "command", json_object_new_string("REMOVE_MEMBER"));
    
    struct json_object *data = json_object_new_object();
    json_object_object_add(data, "session_token", json_object_new_string(g_session_token));
    json_object_object_add(data, "group_id", json_object_new_int(group_id));
    json_object_object_add(data, "target_user_id", json_object_new_int(target_user_id));
    json_object_object_add(request, "data", data);
    
    const char *json_str = json_object_to_json_string(request);
    send(sock, json_str, strlen(json_str), 0);
    
    json_object_put(request);
    
    // Nhận response
    char buffer[BUFFER_SIZE];
    int bytes = recv(sock, buffer, BUFFER_SIZE - 1, 0);
    buffer[bytes] = '\0';
    
    parse_and_display_response(buffer);
    wait_for_enter();
}

// ============================================================================
// FOLDER/DIRECTORY OPERATIONS - QUẢN LÝ THƯ MỤC
// ============================================================================

/**
 * Tạo thư mục mới trong nhóm
 * @param sock: Socket đã kết nối tới server
 * 
 * Yêu cầu: group_id, directory_name, parent_path
 * Parent_path: đường dẫn thư mục cha (ví dụ: / hoặc /folder)
 */
void send_create_directory_request(int sock) {
    char directory_name[256], parent_path[512];
    int group_id;
    
    clear_screen();
    printf("\n=== CREATE DIRECTORY ===\n");
    
    // Kiểm tra authentication
    if (strlen(g_session_token) == 0) {
        print_error("Please login first!");
        wait_for_enter();
        return;
    }
    
    // Nhập thông tin thư mục
    printf("Group ID: ");
    scanf("%d", &group_id);
    getchar(); // consume newline after number input
    
    printf("Directory name: ");
    fgets(directory_name, sizeof(directory_name), stdin);
    directory_name[strcspn(directory_name, "\n")] = 0; // remove newline
    
    printf("Parent path (e.g., / or /folder): ");
    fgets(parent_path, sizeof(parent_path), stdin);
    parent_path[strcspn(parent_path, "\n")] = 0; // remove newline
    
    // Tạo request với thông tin directory
    struct json_object *request = json_object_new_object();
    json_object_object_add(request, "command", json_object_new_string("CREATE_DIRECTORY"));
    
    struct json_object *data = json_object_new_object();
    json_object_object_add(data, "session_token", json_object_new_string(g_session_token));
    json_object_object_add(data, "group_id", json_object_new_int(group_id));
    json_object_object_add(data, "directory_name", json_object_new_string(directory_name));
    json_object_object_add(data, "parent_path", json_object_new_string(parent_path));
    json_object_object_add(request, "data", data);
    
    const char *json_str = json_object_to_json_string(request);
    send(sock, json_str, strlen(json_str), 0);
    
    json_object_put(request);
    
    // Nhận response
    char buffer[BUFFER_SIZE];
    int bytes = recv(sock, buffer, BUFFER_SIZE - 1, 0);
    buffer[bytes] = '\0';
    
    parse_and_display_response(buffer);
    wait_for_enter();
}

/**
 * Đổi tên thư mục (chỉ admin)
 * @param sock: Socket đã kết nối tới server
 * 
 * Yêu cầu quyền admin để thực hiện
 * Nhập: directory_id và new_name
 */
void send_rename_directory_request(int sock) {
    char new_name[256];
    int directory_id;
    
    clear_screen();
    printf("\n=== RENAME DIRECTORY (Admin Only) ===\n");
    
    // Kiểm tra authentication
    if (strlen(g_session_token) == 0) {
        print_error("Please login first!");
        wait_for_enter();
        return;
    }
    
    // Nhập directory ID và tên mới
    printf("\n💡 Tip: Use LIST DIRECTORY first to see directory IDs\n");
    printf("\n📁 Directory ID: ");
    scanf("%d", &directory_id);
    getchar(); // consume newline
    
    if (directory_id == 0) {
        printf("\n❌ Cancelled.\n");
        wait_for_enter();
        return;
    }
    
    printf("📝 New name: ");
    scanf("%s", new_name);
    getchar(); // consume newline
    
    // Confirmation
    printf("\n❓ Confirm rename directory ID %d to '%s'? (yes/no): ", directory_id, new_name);
    char confirm[10];
    scanf("%s", confirm);
    if (strcasecmp(confirm, "yes") != 0 && strcasecmp(confirm, "y") != 0) {
        printf("\n❌ Rename cancelled.\n");
        wait_for_enter();
        return;
    }
    
    // Tạo rename request
    struct json_object *request = json_object_new_object();
    json_object_object_add(request, "command", json_object_new_string("RENAME_DIRECTORY"));
    
    struct json_object *data = json_object_new_object();
    json_object_object_add(data, "session_token", json_object_new_string(g_session_token));
    json_object_object_add(data, "directory_id", json_object_new_int(directory_id));
    json_object_object_add(data, "new_name", json_object_new_string(new_name));
    json_object_object_add(request, "data", data);
    
    const char *json_str = json_object_to_json_string(request);
    send(sock, json_str, strlen(json_str), 0);
    
    json_object_put(request);
    
    // Nhận response
    char buffer[BUFFER_SIZE];
    int bytes = recv(sock, buffer, BUFFER_SIZE - 1, 0);
    buffer[bytes] = '\0';
    
    parse_and_display_response(buffer);
    wait_for_enter();
}

/**
 * Xóa thư mục (chỉ admin)
 * @param sock: Socket đã kết nối tới server
 * 
 * Recursive: true = xóa cả nội dung bên trong, false = chỉ xóa nếu rỗng
 * Cẩn thận với recursive delete!
 */
void send_delete_directory_request(int sock) {
    char recursive_input[10];
    int directory_id, recursive;
    
    clear_screen();
    printf("\n=== DELETE DIRECTORY (Admin Only) ===\n");
    
    // Kiểm tra authentication
    if (strlen(g_session_token) == 0) {
        print_error("Please login first!");
        wait_for_enter();
        return;
    }
    
    // Nhập directory ID và recursive option
    printf("\n💡 Tip: Use LIST DIRECTORY first to see directory IDs\n");
    printf("\n📁 Directory ID: ");
    scanf("%d", &directory_id);
    getchar(); // consume newline
    
    if (directory_id == 0) {
        printf("\n❌ Cancelled.\n");
        wait_for_enter();
        return;
    }
    
    printf("🔄 Recursive delete (will delete all contents)? (yes/no): ");
    scanf("%s", recursive_input);
    getchar(); // consume newline
    recursive = (strcasecmp(recursive_input, "yes") == 0 || strcasecmp(recursive_input, "y") == 0);
    
    // Confirmation
    printf("\n⚠️  CONFIRMATION\n");
    printf("You are about to DELETE directory ID %d%s\n", directory_id, 
           recursive ? " and ALL its contents" : "");
    printf("This action cannot be undone!\n");
    printf("❓ Are you sure? (yes/no): ");
    char confirm[10];
    scanf("%s", confirm);
    if (strcasecmp(confirm, "yes") != 0 && strcasecmp(confirm, "y") != 0) {
        printf("\n❌ Delete cancelled.\n");
        wait_for_enter();
        return;
    }
    
    // Tạo delete request
    struct json_object *request = json_object_new_object();
    json_object_object_add(request, "command", json_object_new_string("DELETE_DIRECTORY"));
    
    struct json_object *data = json_object_new_object();
    json_object_object_add(data, "session_token", json_object_new_string(g_session_token));
    json_object_object_add(data, "directory_id", json_object_new_int(directory_id));
    json_object_object_add(data, "recursive", json_object_new_boolean(recursive));
    json_object_object_add(request, "data", data);
    
    const char *json_str = json_object_to_json_string(request);
    send(sock, json_str, strlen(json_str), 0);
    
    json_object_put(request);
    
    // Nhận response
    char buffer[BUFFER_SIZE];
    int bytes = recv(sock, buffer, BUFFER_SIZE - 1, 0);
    buffer[bytes] = '\0';
    
    parse_and_display_response(buffer);
    wait_for_enter();
}

/**
 * Sao chép thư mục sang vị trí khác (chỉ admin)
 * @param sock: Socket đã kết nối tới server
 * 
 * Copy toàn bộ nội dung thư mục sang destination_path
 * Thư mục gốc vẫn giữ nguyên
 */
void send_copy_directory_request(int sock) {
    char destination_path[512];
    int directory_id;
    
    clear_screen();
    printf("\n=== COPY DIRECTORY (Admin Only) ===\n");
    
    // Kiểm tra authentication
    if (strlen(g_session_token) == 0) {
        print_error("Please login first!");
        wait_for_enter();
        return;
    }
    
    // Nhập directory ID và đích đến
    printf("\n💡 Tip: Use LIST DIRECTORY first to see directory IDs\n");
    printf("\n📁 Directory ID to copy: ");
    scanf("%d", &directory_id);
    getchar(); // consume newline
    
    if (directory_id == 0) {
        printf("\n❌ Cancelled.\n");
        wait_for_enter();
        return;
    }
    
    printf("📍 Destination path (e.g., /newfolder or /): ");
    scanf("%s", destination_path);
    getchar(); // consume newline
    
    // Confirmation
    printf("\n❓ Confirm copy directory ID %d to '%s'? (yes/no): ", directory_id, destination_path);
    char confirm[10];
    scanf("%s", confirm);
    if (strcasecmp(confirm, "yes") != 0 && strcasecmp(confirm, "y") != 0) {
        printf("\n❌ Copy cancelled.\n");
        wait_for_enter();
        return;
    }
    
    // Tạo copy request
    struct json_object *request = json_object_new_object();
    json_object_object_add(request, "command", json_object_new_string("COPY_DIRECTORY"));
    
    struct json_object *data = json_object_new_object();
    json_object_object_add(data, "session_token", json_object_new_string(g_session_token));
    json_object_object_add(data, "directory_id", json_object_new_int(directory_id));
    json_object_object_add(data, "destination_path", json_object_new_string(destination_path));
    json_object_object_add(request, "data", data);
    
    const char *json_str = json_object_to_json_string(request);
    send(sock, json_str, strlen(json_str), 0);
    
    json_object_put(request);
    
    char buffer[BUFFER_SIZE];
    int bytes = recv(sock, buffer, BUFFER_SIZE - 1, 0);
    buffer[bytes] = '\0';
    
    parse_and_display_response(buffer);
    wait_for_enter();
}

/**
 * Di chuyển thư mục sang vị trí khác (chỉ admin)
 * @param sock: Socket đã kết nối tới server
 * 
 * Move toàn bộ nội dung sang destination_path
 * Thư mục gốc sẽ bị xóa sau khi move
 */
void send_move_directory_request(int sock) {
    char destination_path[512];
    int directory_id;
    
    clear_screen();
    printf("\n=== MOVE DIRECTORY (Admin Only) ===\n");
    
    // Kiểm tra authentication
    if (strlen(g_session_token) == 0) {
        print_error("Please login first!");
        wait_for_enter();
        return;
    }
    
    // Nhập directory ID và đích đến
    printf("\n💡 Tip: Use LIST DIRECTORY first to see directory IDs\n");
    printf("\n📁 Directory ID to move: ");
    scanf("%d", &directory_id);
    getchar(); // consume newline
    
    if (directory_id == 0) {
        printf("\n❌ Cancelled.\n");
        wait_for_enter();
        return;
    }
    
    printf("📍 Destination path (e.g., /newfolder or /): ");
    scanf("%s", destination_path);
    getchar(); // consume newline
    
    // Confirmation
    printf("\n⚠️  CONFIRMATION\n");
    printf("You are about to MOVE directory ID %d to '%s'\n", directory_id, destination_path);
    printf("The original directory will be removed after moving!\n");
    printf("❓ Are you sure? (yes/no): ");
    char confirm[10];
    scanf("%s", confirm);
    if (strcasecmp(confirm, "yes") != 0 && strcasecmp(confirm, "y") != 0) {
        printf("\n❌ Move cancelled.\n");
        wait_for_enter();
        return;
    }
    
    // Tạo move request
    struct json_object *request = json_object_new_object();
    json_object_object_add(request, "command", json_object_new_string("MOVE_DIRECTORY"));
    
    struct json_object *data = json_object_new_object();
    json_object_object_add(data, "session_token", json_object_new_string(g_session_token));
    json_object_object_add(data, "directory_id", json_object_new_int(directory_id));
    json_object_object_add(data, "destination_path", json_object_new_string(destination_path));
    json_object_object_add(request, "data", data);
    
    const char *json_str = json_object_to_json_string(request);
    send(sock, json_str, strlen(json_str), 0);
    
    json_object_put(request);
    
    // Nhận response
    char buffer[BUFFER_SIZE];
    int bytes = recv(sock, buffer, BUFFER_SIZE - 1, 0);
    buffer[bytes] = '\0';
    
    parse_and_display_response(buffer);
    wait_for_enter();
}

/**
 * Liệt kê nội dung thư mục (directories và files)
 * @param sock: Socket đã kết nối tới server
 * 
 * Quy trình:
 * 1. Hiển thị danh sách groups của user
 * 2. User chọn group
 * 3. Nhập directory path (mặc định là "/")
 * 4. Hiển thị nội dung thư mục
 */
void send_list_directory_request(int sock) {
    clear_screen();
    printf("\n=== LIST DIRECTORY CONTENTS ===\n");
    
    // Kiểm tra authentication
    if (strlen(g_session_token) == 0) {
        print_error("You must be logged in to list directory");
        wait_for_enter();
        return;
    }
    
    // BƯỚC 1: Lấy danh sách groups
    struct json_object *list_req = json_object_new_object();
    json_object_object_add(list_req, "command", json_object_new_string("LIST_MY_GROUPS"));
    
    struct json_object *list_data = json_object_new_object();
    json_object_object_add(list_data, "session_token", json_object_new_string(g_session_token));
    json_object_object_add(list_req, "data", list_data);
    
    const char *list_json = json_object_to_json_string(list_req);
    send(sock, list_json, strlen(list_json), 0);
    json_object_put(list_req);
    
    // Nhận danh sách groups
    char list_buffer[BUFFER_SIZE];
    int list_bytes = recv(sock, list_buffer, BUFFER_SIZE - 1, 0);
    list_buffer[list_bytes] = '\0';
    
    struct json_object *list_response = json_tokener_parse(list_buffer);
    if (!list_response) {
        print_error("Failed to get groups list");
        wait_for_enter();
        return;
    }
    
    struct json_object *status_obj, *payload_obj, *groups_obj;
    json_object_object_get_ex(list_response, "status", &status_obj);
    json_object_object_get_ex(list_response, "payload", &payload_obj);
    
    if (json_object_get_int(status_obj) != 200 || !payload_obj) {
        print_error("Failed to retrieve groups");
        json_object_put(list_response);
        wait_for_enter();
        return;
    }
    
    json_object_object_get_ex(payload_obj, "groups", &groups_obj);
    int group_count = json_object_array_length(groups_obj);
    
    if (group_count == 0) {
        printf("\n📭 No groups available. Create or join a group first!\n");
        json_object_put(list_response);
        wait_for_enter();
        return;
    }
    
    // BƯỚC 2: Hiển thị danh sách groups
    printf("\n👥 Your Groups:\n");
    print_separator();
    for (int i = 0; i < group_count; i++) {
        struct json_object *group = json_object_array_get_idx(groups_obj, i);
        struct json_object *id_obj, *name_obj, *role_obj, *member_count_obj;
        json_object_object_get_ex(group, "group_id", &id_obj);
        json_object_object_get_ex(group, "group_name", &name_obj);
        json_object_object_get_ex(group, "role", &role_obj);
        json_object_object_get_ex(group, "member_count", &member_count_obj);
        
        printf("[%d] %s (Role: %s | Members: %d)\n", 
               json_object_get_int(id_obj),
               json_object_get_string(name_obj),
               json_object_get_string(role_obj),
               json_object_get_int(member_count_obj));
    }
    print_separator();
    
    // BƯỚC 3: User chọn group
    int selected_group_id;
    printf("\n➤ Enter Group ID to browse (0 to cancel): ");
    scanf("%d", &selected_group_id);
    getchar(); // consume newline
    
    json_object_put(list_response);
    
    if (selected_group_id == 0) {
        printf("\n❌ Cancelled.\n");
        wait_for_enter();
        return;
    }
    
    // BƯỚC 4: Nhập directory path
    char directory_path[512];
    printf("\n📂 Enter directory path (press ENTER for root '/'): ");
    fgets(directory_path, sizeof(directory_path), stdin);
    directory_path[strcspn(directory_path, "\n")] = 0; // remove newline
    
    // Nếu user không nhập gì, dùng root "/"
    if (strlen(directory_path) == 0) {
        strcpy(directory_path, "/");
    }
    
    printf("\n🔍 Listing contents of '%s' in group %d...\n", directory_path, selected_group_id);
    
    // BƯỚC 5: Gửi request LIST_DIRECTORY
    struct json_object *request = json_object_new_object();
    json_object_object_add(request, "command", json_object_new_string("LIST_DIRECTORY"));
    
    struct json_object *data = json_object_new_object();
    json_object_object_add(data, "session_token", json_object_new_string(g_session_token));
    json_object_object_add(data, "group_id", json_object_new_int(selected_group_id));
    json_object_object_add(data, "directory_path", json_object_new_string(directory_path));
    json_object_object_add(request, "data", data);
    
    const char *json_str = json_object_to_json_string(request);
    send(sock, json_str, strlen(json_str), 0);
    
    json_object_put(request);
    
    // Nhận response
    char buffer[BUFFER_SIZE];
    int bytes = recv(sock, buffer, BUFFER_SIZE - 1, 0);
    buffer[bytes] = '\0';
    
    parse_and_display_response(buffer);
    wait_for_enter();
}

// ============================================================================
// FILE UPLOAD/DOWNLOAD - TẢI LÊN/TẢI XUỐNG FILE
// ============================================================================

/**
 * Upload file lên server với chunking và MD5 verification
 * @param sock: Socket đã kết nối tới server
 * 
 * Quy trình:
 * 1. START: Gửi thông tin file (name, size, path)
 * 2. CHUNK: Gửi từng chunk 512KB đã encode Base64
 * 3. COMPLETE: Hoàn tất và nhận MD5 checksum từ server
 * 4. VERIFY: So sánh MD5 local với server
 */
void send_upload_file_request(int sock) {
    char local_file_path[512], remote_file_path[512], file_name[256];
    int group_id;
    
    clear_screen();
    printf("\n=== UPLOAD FILE ===\n");
    
    // Kiểm tra authentication
    if (strlen(g_session_token) == 0) {
        print_error("Please login first!");
        wait_for_enter();
        return;
    }
    
    // Nhập thông tin file
    printf("Group ID: ");
    scanf("%d", &group_id);
    getchar();
    
    printf("Local file path (e.g., /home/user/document.pdf): ");
    fgets(local_file_path, sizeof(local_file_path), stdin);
    local_file_path[strcspn(local_file_path, "\n")] = 0;
    
    printf("File name on server: ");
    fgets(file_name, sizeof(file_name), stdin);
    file_name[strcspn(file_name, "\n")] = 0;
    
    printf("Remote path (e.g., /folder or /): ");
    fgets(remote_file_path, sizeof(remote_file_path), stdin);
    remote_file_path[strcspn(remote_file_path, "\n")] = 0;
    
    // Thêm file name vào remote path
    if (remote_file_path[strlen(remote_file_path) - 1] != '/') {
        strcat(remote_file_path, "/");
    }
    strcat(remote_file_path, file_name);
    
    // Mở file để đọc
    FILE *fp = fopen(local_file_path, "rb");
    if (!fp) {
        print_error("Cannot open file!");
        wait_for_enter();
        return;
    }
    
    // Lấy kích thước file
    fseek(fp, 0, SEEK_END);
    long long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    printf("\n📊 File info:\n");
    printf("  Size: %lld bytes (%.2f MB)\n", file_size, file_size / 1024.0 / 1024.0);
    printf("  Chunks: %lld\n", (file_size + CHUNK_SIZE - 1) / CHUNK_SIZE);
    
    // Tính MD5 của file local
    printf("\n🔐 Calculating MD5 checksum...\n");
    unsigned char local_md5[MD5_DIGEST_LENGTH];
    calculate_file_md5(local_file_path, local_md5);
    char local_md5_hex[MD5_DIGEST_LENGTH * 2 + 1];
    md5_to_hex(local_md5, local_md5_hex);
    printf("  Local MD5: %s\n", local_md5_hex);
    
    // STEP 1: START UPLOAD
    printf("\n📤 Starting upload...\n");
    struct json_object *start_req = json_object_new_object();
    json_object_object_add(start_req, "command", json_object_new_string("UPLOAD_FILE_START"));
    
    struct json_object *start_data = json_object_new_object();
    json_object_object_add(start_data, "session_token", json_object_new_string(g_session_token));
    json_object_object_add(start_data, "group_id", json_object_new_int(group_id));
    json_object_object_add(start_data, "file_name", json_object_new_string(file_name));
    json_object_object_add(start_data, "file_path", json_object_new_string(remote_file_path));
    json_object_object_add(start_data, "file_size", json_object_new_int64(file_size));
    json_object_object_add(start_req, "data", start_data);
    
    const char *start_json = json_object_to_json_string(start_req);
    
    // DEBUG: Print JSON before sending
    // printf("\n[DEBUG] Sending JSON:\n%s\n", start_json);
    // printf("[DEBUG] JSON length: %zu bytes\n", strlen(start_json));
    
    send(sock, start_json, strlen(start_json), 0);
    json_object_put(start_req);
    
    // Nhận response START
    char buffer[BUFFER_SIZE];
    memset(buffer, 0, BUFFER_SIZE);  // Clear buffer first
    int bytes = recv(sock, buffer, BUFFER_SIZE - 1, 0);
    buffer[bytes] = '\0';
    
    struct json_object *start_response = json_tokener_parse(buffer);
    struct json_object *status_obj, *payload_obj, *upload_id_obj;
    json_object_object_get_ex(start_response, "status", &status_obj);
    
    if (json_object_get_int(status_obj) != 200) {
        printf("\n❌ Upload start failed:\n");
        parse_and_display_response(buffer);
        fclose(fp);
        json_object_put(start_response);
        wait_for_enter();
        return;
    }
    
    json_object_object_get_ex(start_response, "payload", &payload_obj);
    json_object_object_get_ex(payload_obj, "upload_id", &upload_id_obj);
    int upload_id = json_object_get_int(upload_id_obj);
    json_object_put(start_response);
    
    printf("✓ Upload session created (ID: %d)\n", upload_id);
    
    // STEP 2: SEND CHUNKS
    printf("\n📦 Uploading chunks...\n");
    unsigned char chunk_buffer[CHUNK_SIZE];
    int chunk_index = 0;
    long long uploaded = 0;
    
    while (1) {
        size_t bytes_read = fread(chunk_buffer, 1, CHUNK_SIZE, fp);
        if (bytes_read == 0) break;
        
        // Encode chunk to Base64
        char *chunk_b64 = base64_encode(chunk_buffer, bytes_read);
        
        // Tạo CHUNK request
        struct json_object *chunk_req = json_object_new_object();
        json_object_object_add(chunk_req, "command", json_object_new_string("UPLOAD_FILE_CHUNK"));
        
        struct json_object *chunk_data = json_object_new_object();
        json_object_object_add(chunk_data, "session_token", json_object_new_string(g_session_token));
        json_object_object_add(chunk_data, "upload_id", json_object_new_int(upload_id));
        json_object_object_add(chunk_data, "chunk_index", json_object_new_int(chunk_index));
        json_object_object_add(chunk_data, "chunk_data", json_object_new_string(chunk_b64));
        json_object_object_add(chunk_req, "data", chunk_data);
        
        const char *chunk_json = json_object_to_json_string(chunk_req);
        
        // DEBUG: Print chunk info
        // printf("\n[DEBUG CHUNK %d] Binary size: %zu bytes\n", chunk_index, bytes_read);
        // printf("[DEBUG CHUNK %d] Base64 size: %zu bytes\n", chunk_index, strlen(chunk_b64));
        // printf("[DEBUG CHUNK %d] JSON size: %zu bytes\n", chunk_index, strlen(chunk_json));
        // printf("[DEBUG CHUNK %d] JSON preview (first 200 chars): %.200s...\n", chunk_index, chunk_json);
        
        send(sock, chunk_json, strlen(chunk_json), 0);
        json_object_put(chunk_req);
        free(chunk_b64);
        
        // Nhận response
        memset(buffer, 0, BUFFER_SIZE);  // Clear buffer
        bytes = recv(sock, buffer, BUFFER_SIZE - 1, 0);
        buffer[bytes] = '\0';
        
        struct json_object *chunk_response = json_tokener_parse(buffer);
        json_object_object_get_ex(chunk_response, "status", &status_obj);
        
        if (json_object_get_int(status_obj) != 200) {
            printf("\n❌ Chunk %d upload failed\n", chunk_index);
            parse_and_display_response(buffer);
            fclose(fp);
            json_object_put(chunk_response);
            wait_for_enter();
            return;
        }
        
        json_object_put(chunk_response);
        
        uploaded += bytes_read;
        chunk_index++;
        
        // Progress bar
        int progress = (int)((uploaded * 100) / file_size);
        printf("\r  Progress: [%3d%%] %lld/%lld bytes", progress, uploaded, file_size);
        fflush(stdout);
    }
    
    fclose(fp);
    printf("\n✓ All chunks uploaded\n");
    
    // STEP 3: COMPLETE UPLOAD
    printf("\n🔄 Finalizing upload...\n");
    struct json_object *complete_req = json_object_new_object();
    json_object_object_add(complete_req, "command", json_object_new_string("UPLOAD_FILE_COMPLETE"));
    
    struct json_object *complete_data = json_object_new_object();
    json_object_object_add(complete_data, "session_token", json_object_new_string(g_session_token));
    json_object_object_add(complete_data, "upload_id", json_object_new_int(upload_id));
    json_object_object_add(complete_req, "data", complete_data);
    
    const char *complete_json = json_object_to_json_string(complete_req);
    send(sock, complete_json, strlen(complete_json), 0);
    json_object_put(complete_req);
    
    // Nhận response COMPLETE
    bytes = recv(sock, buffer, BUFFER_SIZE - 1, 0);
    buffer[bytes] = '\0';
    
    struct json_object *complete_response = json_tokener_parse(buffer);
    json_object_object_get_ex(complete_response, "status", &status_obj);
    json_object_object_get_ex(complete_response, "payload", &payload_obj);
    
    if (json_object_get_int(status_obj) == 200 && payload_obj) {
        struct json_object *md5_obj;
        json_object_object_get_ex(payload_obj, "md5_checksum", &md5_obj);
        
        if (md5_obj) {
            const char *server_md5 = json_object_get_string(md5_obj);
            printf("\n🔐 MD5 Verification:\n");
            printf("  Local:  %s\n", local_md5_hex);
            printf("  Server: %s\n", server_md5);
            
            if (strcmp(local_md5_hex, server_md5) == 0) {
                printf("  ✓ MD5 MATCH - File integrity verified!\n");
            } else {
                printf("  ✗ MD5 MISMATCH - File may be corrupted!\n");
            }
        }
    }
    
    printf("\n📋 Upload Summary:\n");
    parse_and_display_response(buffer);
    json_object_put(complete_response);
    
    wait_for_enter();
}

/**
 * Download file từ server với chunking và MD5 verification
 * @param sock: Socket đã kết nối tới server
 * 
 * Quy trình:
 * 1. START: Gửi file_id, nhận file info
 * 2. CHUNK: Nhận từng chunk và decode Base64
 * 3. COMPLETE: Hoàn tất và verify MD5
 */
void send_download_file_request(int sock) {
    char local_file_path[512];
    int file_id;
    
    clear_screen();
    printf("\n=== DOWNLOAD FILE ===\n");
    
    // Kiểm tra authentication
    if (strlen(g_session_token) == 0) {
        print_error("Please login first!");
        wait_for_enter();
        return;
    }
    
    // Nhập thông tin
    printf("File ID: ");
    scanf("%d", &file_id);
    getchar();
    
    printf("Save to local path (e.g., /home/user/downloaded_file.pdf): ");
    fgets(local_file_path, sizeof(local_file_path), stdin);
    local_file_path[strcspn(local_file_path, "\n")] = 0;
    
    // STEP 1: START DOWNLOAD
    printf("\n📥 Starting download...\n");
    struct json_object *start_req = json_object_new_object();
    json_object_object_add(start_req, "command", json_object_new_string("DOWNLOAD_FILE_START"));
    
    struct json_object *start_data = json_object_new_object();
    json_object_object_add(start_data, "session_token", json_object_new_string(g_session_token));
    json_object_object_add(start_data, "file_id", json_object_new_int(file_id));
    json_object_object_add(start_req, "data", start_data);
    
    const char *start_json = json_object_to_json_string(start_req);
    send(sock, start_json, strlen(start_json), 0);
    json_object_put(start_req);
    
    // Nhận response START
    char buffer[BUFFER_SIZE];
    memset(buffer, 0, BUFFER_SIZE);
    int total_received = 0;
    int bytes;
    struct json_object *start_response = NULL;
    
    while (total_received < BUFFER_SIZE - 1) {
        bytes = recv(sock, buffer + total_received, BUFFER_SIZE - total_received - 1, 0);
        if (bytes <= 0) break;
        total_received += bytes;
        buffer[total_received] = '\0';
        
        start_response = json_tokener_parse(buffer);
        if (start_response != NULL) break;
    }
    
    if (!start_response) {
        printf("\n❌ Failed to parse START response\n");
        wait_for_enter();
        return;
    }
    struct json_object *status_obj, *payload_obj, *download_id_obj;
    struct json_object *file_name_obj, *file_size_obj;
    
    json_object_object_get_ex(start_response, "status", &status_obj);
    
    if (json_object_get_int(status_obj) != 200) {
        printf("\n❌ Download start failed:\n");
        parse_and_display_response(buffer);
        json_object_put(start_response);
        wait_for_enter();
        return;
    }
    
    json_object_object_get_ex(start_response, "payload", &payload_obj);
    json_object_object_get_ex(payload_obj, "download_id", &download_id_obj);
    json_object_object_get_ex(payload_obj, "file_name", &file_name_obj);
    json_object_object_get_ex(payload_obj, "file_size", &file_size_obj);
    
    int download_id = json_object_get_int(download_id_obj);
    const char *file_name = json_object_get_string(file_name_obj);
    long long file_size = json_object_get_int64(file_size_obj);
    
    printf("✓ Download session created (ID: %d)\n", download_id);
    printf("📊 File: %s (%.2f MB)\n", file_name, file_size / 1024.0 / 1024.0);
    
    json_object_put(start_response);
    
    // Mở file để ghi
    FILE *fp = fopen(local_file_path, "wb");
    if (!fp) {
        print_error("Cannot create file!");
        wait_for_enter();
        return;
    }
    
    // Khởi tạo MD5 context
    MD5_CTX md5_context;
    MD5_Init(&md5_context);
    
    // STEP 2: RECEIVE CHUNKS
    printf("\n📦 Downloading chunks...\n");
    int chunk_index = 0;
    long long downloaded = 0;
    int is_last = 0;
    
    while (!is_last) {
        // Tạo CHUNK request
        struct json_object *chunk_req = json_object_new_object();
        json_object_object_add(chunk_req, "command", json_object_new_string("DOWNLOAD_FILE_CHUNK"));
        
        struct json_object *chunk_data = json_object_new_object();
        json_object_object_add(chunk_data, "session_token", json_object_new_string(g_session_token));
        json_object_object_add(chunk_data, "download_id", json_object_new_int(download_id));
        json_object_object_add(chunk_data, "chunk_index", json_object_new_int(chunk_index));
        json_object_object_add(chunk_req, "data", chunk_data);
        
        const char *chunk_json = json_object_to_json_string(chunk_req);
        send(sock, chunk_json, strlen(chunk_json), 0);
        json_object_put(chunk_req);
        
        // Nhận response - có thể cần nhiều lần recv cho JSON lớn
        memset(buffer, 0, BUFFER_SIZE);
        int total_received = 0;
        struct json_object *chunk_response = NULL;
        
        while (total_received < BUFFER_SIZE - 1) {
            bytes = recv(sock, buffer + total_received, BUFFER_SIZE - total_received - 1, 0);
            if (bytes <= 0) break;
            total_received += bytes;
            buffer[total_received] = '\0';
            
            // Try to parse
            chunk_response = json_tokener_parse(buffer);
            if (chunk_response != NULL) break;  // Parse thành công
        }
        
        if (!chunk_response) {
            printf("\n❌ Failed to parse JSON response\n");
            fclose(fp);
            wait_for_enter();
            return;
        }
        
        json_object_object_get_ex(chunk_response, "status", &status_obj);
        
        if (json_object_get_int(status_obj) != 200) {
            printf("\n❌ Chunk %d download failed\n", chunk_index);
            parse_and_display_response(buffer);
            fclose(fp);
            json_object_put(chunk_response);
            wait_for_enter();
            return;
        }
        
        json_object_object_get_ex(chunk_response, "payload", &payload_obj);
        struct json_object *chunk_data_obj, *is_last_obj;
        json_object_object_get_ex(payload_obj, "chunk_data", &chunk_data_obj);
        json_object_object_get_ex(payload_obj, "is_last", &is_last_obj);
        
        const char *chunk_b64 = json_object_get_string(chunk_data_obj);
        is_last = json_object_get_boolean(is_last_obj);
        
        // Decode Base64
        size_t decoded_length;
        unsigned char *decoded_data = base64_decode(chunk_b64, &decoded_length);
        
        // Ghi vào file và update MD5
        fwrite(decoded_data, 1, decoded_length, fp);
        MD5_Update(&md5_context, decoded_data, decoded_length);
        
        free(decoded_data);
        json_object_put(chunk_response);
        
        downloaded += decoded_length;
        chunk_index++;
        
        // Progress bar
        int progress = (int)((downloaded * 100) / file_size);
        printf("\r  Progress: [%3d%%] %lld/%lld bytes", progress, downloaded, file_size);
        fflush(stdout);
    }
    
    fclose(fp);
    printf("\n✓ All chunks downloaded\n");
    
    // Finalize MD5
    unsigned char local_md5[MD5_DIGEST_LENGTH];
    MD5_Final(local_md5, &md5_context);
    char local_md5_hex[MD5_DIGEST_LENGTH * 2 + 1];
    md5_to_hex(local_md5, local_md5_hex);
    
    // STEP 3: COMPLETE DOWNLOAD
    printf("\n🔄 Finalizing download...\n");
    struct json_object *complete_req = json_object_new_object();
    json_object_object_add(complete_req, "command", json_object_new_string("DOWNLOAD_FILE_COMPLETE"));
    
    struct json_object *complete_data = json_object_new_object();
    json_object_object_add(complete_data, "session_token", json_object_new_string(g_session_token));
    json_object_object_add(complete_data, "download_id", json_object_new_int(download_id));
    json_object_object_add(complete_req, "data", complete_data);
    
    const char *complete_json = json_object_to_json_string(complete_req);
    send(sock, complete_json, strlen(complete_json), 0);
    json_object_put(complete_req);
    
    // Nhận response
    bytes = recv(sock, buffer, BUFFER_SIZE - 1, 0);
    buffer[bytes] = '\0';
    
    printf("\n🔐 Downloaded file MD5: %s\n", local_md5_hex);
    printf("\n📋 Download Summary:\n");
    parse_and_display_response(buffer);
    
    printf("\n✓ File saved to: %s\n", local_file_path);
    wait_for_enter();
}

// ============================================================================
// FILE OPERATIONS - THAO TÁC VỚI FILE
// ============================================================================

/**
 * Đổi tên file (chỉ admin/owner)
 * @param sock: Socket đã kết nối tới server
 * 
 * Yêu cầu quyền admin hoặc owner
 * Nhập: file_id, new_name
 */
void send_rename_file_request(int sock) {
    int file_id;
    char new_name[256];
    
    clear_screen();
    printf("\n=== RENAME FILE ===\n");
    
    // Kiểm tra authentication
    if (strlen(g_session_token) == 0) {
        print_error("You must login first!");
        wait_for_enter();
        return;
    }
    
    // Nhập thông tin file cần đổi tên
    printf("\n💡 Tip: Use LIST DIRECTORY first to see file IDs\n");
    printf("\n📄 File ID: ");
    scanf("%d", &file_id);
    getchar(); // consume newline
    
    if (file_id == 0) {
        printf("\n❌ Cancelled.\n");
        wait_for_enter();
        return;
    }
    
    printf("📝 New file name: ");
    fgets(new_name, 256, stdin);
    new_name[strcspn(new_name, "\n")] = 0;
    
    // Validation
    if (strlen(new_name) == 0) {
        print_error("File name cannot be empty!");
        wait_for_enter();
        return;
    }
    
    // Confirmation
    printf("\n❓ Confirm rename file ID %d to '%s'? (yes/no): ", file_id, new_name);
    char confirm[10];
    scanf("%s", confirm);
    if (strcasecmp(confirm, "yes") != 0 && strcasecmp(confirm, "y") != 0) {
        printf("\n❌ Rename cancelled.\n");
        wait_for_enter();
        return;
    }
    
    // Tạo request
    struct json_object *request = json_object_new_object();
    json_object_object_add(request, "command", json_object_new_string("RENAME_FILE"));
    
    struct json_object *data = json_object_new_object();
    json_object_object_add(data, "session_token", json_object_new_string(g_session_token));
    json_object_object_add(data, "file_id", json_object_new_int(file_id));
    json_object_object_add(data, "new_name", json_object_new_string(new_name));
    json_object_object_add(request, "data", data);
    
    const char *json_str = json_object_to_json_string(request);
    send(sock, json_str, strlen(json_str), 0);
    
    json_object_put(request);
    
    // Nhận response
    char buffer[BUFFER_SIZE];
    int bytes = recv(sock, buffer, BUFFER_SIZE - 1, 0);
    buffer[bytes] = '\0';
    
    parse_and_display_response(buffer);
    wait_for_enter();
}

/**
 * Xóa file (chỉ admin/owner)
 * @param sock: Socket đã kết nối tới server
 * 
 * Yêu cầu quyền admin hoặc owner
 * File sẽ bị xóa vĩnh viễn khỏi hệ thống
 */
void send_delete_file_request(int sock) {
    int file_id;
    
    clear_screen();
    printf("\n=== DELETE FILE ===\n");
    
    // Kiểm tra authentication
    if (strlen(g_session_token) == 0) {
        print_error("You must login first!");
        wait_for_enter();
        return;
    }
    
    // Nhập file_id cần xóa
    printf("\n💡 Tip: Use LIST DIRECTORY first to see file IDs\n");
    printf("\n📄 File ID: ");
    scanf("%d", &file_id);
    getchar(); // consume newline
    
    if (file_id == 0) {
        printf("\n❌ Cancelled.\n");
        wait_for_enter();
        return;
    }
    
    // Xác nhận xóa
    printf("\n⚠️  CONFIRMATION\n");
    printf("You are about to DELETE file ID %d\n", file_id);
    printf("This action cannot be undone!\n");
    printf("❓ Are you sure? (yes/no): ");
    char confirm[10];
    scanf("%s", confirm);
    
    if (strcasecmp(confirm, "yes") != 0 && strcasecmp(confirm, "y") != 0) {
        printf("\n❌ Delete cancelled.\n");
        wait_for_enter();
        return;
    }
    
    // Tạo request
    struct json_object *request = json_object_new_object();
    json_object_object_add(request, "command", json_object_new_string("DELETE_FILE"));
    
    struct json_object *data = json_object_new_object();
    json_object_object_add(data, "session_token", json_object_new_string(g_session_token));
    json_object_object_add(data, "file_id", json_object_new_int(file_id));
    json_object_object_add(request, "data", data);
    
    const char *json_str = json_object_to_json_string(request);
    send(sock, json_str, strlen(json_str), 0);
    
    json_object_put(request);
    
    // Nhận response
    char buffer[BUFFER_SIZE];
    int bytes = recv(sock, buffer, BUFFER_SIZE - 1, 0);
    buffer[bytes] = '\0';
    
    parse_and_display_response(buffer);
    wait_for_enter();
}

/**
 * Copy file sang thư mục khác
 * @param sock: Socket đã kết nối tới server
 * 
 * Tạo bản sao của file tại destination_path
 * File gốc vẫn được giữ nguyên
 */
void send_copy_file_request(int sock) {
    int file_id;
    char destination_path[512];
    
    clear_screen();
    printf("\n=== COPY FILE ===\n");
    
    // Kiểm tra authentication
    if (strlen(g_session_token) == 0) {
        print_error("You must login first!");
        wait_for_enter();
        return;
    }
    
    // Nhập thông tin
    printf("\n💡 Tip: Use LIST DIRECTORY first to see file IDs\n");
    printf("\n📄 File ID to copy: ");
    scanf("%d", &file_id);
    getchar(); // consume newline
    
    if (file_id == 0) {
        printf("\n❌ Cancelled.\n");
        wait_for_enter();
        return;
    }
    
    printf("📍 Destination path (e.g., /newfolder or /): ");
    fgets(destination_path, 512, stdin);
    destination_path[strcspn(destination_path, "\n")] = 0;
    
    // Confirmation
    printf("\n❓ Confirm copy file ID %d to '%s'? (yes/no): ", file_id, destination_path);
    char confirm[10];
    scanf("%s", confirm);
    if (strcasecmp(confirm, "yes") != 0 && strcasecmp(confirm, "y") != 0) {
        printf("\n❌ Copy cancelled.\n");
        wait_for_enter();
        return;
    }
    
    // Tạo request
    struct json_object *request = json_object_new_object();
    json_object_object_add(request, "command", json_object_new_string("COPY_FILE"));
    
    struct json_object *data = json_object_new_object();
    json_object_object_add(data, "session_token", json_object_new_string(g_session_token));
    json_object_object_add(data, "file_id", json_object_new_int(file_id));
    json_object_object_add(data, "destination_path", json_object_new_string(destination_path));
    json_object_object_add(request, "data", data);
    
    const char *json_str = json_object_to_json_string(request);
    send(sock, json_str, strlen(json_str), 0);
    
    json_object_put(request);
    
    // Nhận response
    char buffer[BUFFER_SIZE];
    int bytes = recv(sock, buffer, BUFFER_SIZE - 1, 0);
    buffer[bytes] = '\0';
    
    parse_and_display_response(buffer);
    wait_for_enter();
}

/**
 * Di chuyển file sang thư mục khác (chỉ admin/owner)
 * @param sock: Socket đã kết nối tới server
 * 
 * Yêu cầu quyền admin hoặc owner
 * File sẽ được chuyển từ vị trí cũ sang vị trí mới
 */
void send_move_file_request(int sock) {
    int file_id;
    char destination_path[512];
    
    clear_screen();
    printf("\n=== MOVE FILE ===\n");
    
    // Kiểm tra authentication
    if (strlen(g_session_token) == 0) {
        print_error("You must login first!");
        wait_for_enter();
        return;
    }
    
    // Nhập thông tin
    printf("\n💡 Tip: Use LIST DIRECTORY first to see file IDs\n");
    printf("\n📄 File ID to move: ");
    scanf("%d", &file_id);
    getchar(); // consume newline
    
    if (file_id == 0) {
        printf("\n❌ Cancelled.\n");
        wait_for_enter();
        return;
    }
    
    printf("📍 Destination path (e.g., /newfolder or /): ");
    fgets(destination_path, 512, stdin);
    destination_path[strcspn(destination_path, "\n")] = 0;
    
    // Confirmation
    printf("\n⚠️  CONFIRMATION\n");
    printf("You are about to MOVE file ID %d to '%s'\n", file_id, destination_path);
    printf("The file will be removed from its current location!\n");
    printf("❓ Are you sure? (yes/no): ");
    char confirm[10];
    scanf("%s", confirm);
    if (strcasecmp(confirm, "yes") != 0 && strcasecmp(confirm, "y") != 0) {
        printf("\n❌ Move cancelled.\n");
        wait_for_enter();
        return;
    }
    
    // Tạo request
    struct json_object *request = json_object_new_object();
    json_object_object_add(request, "command", json_object_new_string("MOVE_FILE"));
    
    struct json_object *data = json_object_new_object();
    json_object_object_add(data, "session_token", json_object_new_string(g_session_token));
    json_object_object_add(data, "file_id", json_object_new_int(file_id));
    json_object_object_add(data, "destination_path", json_object_new_string(destination_path));
    json_object_object_add(request, "data", data);
    
    const char *json_str = json_object_to_json_string(request);
    send(sock, json_str, strlen(json_str), 0);
    
    json_object_put(request);
    
    // Nhận response
    char buffer[BUFFER_SIZE];
    int bytes = recv(sock, buffer, BUFFER_SIZE - 1, 0);
    buffer[bytes] = '\0';
    
    parse_and_display_response(buffer);
    wait_for_enter();
}

// ============================================================================
// MENU SYSTEM - HỆ THỐNG MENU ĐIỀU HƯỚNG
// ============================================================================

// Forward declarations
void show_account_menu(int sock);
void show_group_menu(int sock);
void show_folder_menu(int sock);

/**
 * Hàm main - Điểm khởi đầu của chương trình client
 * 
 * Quy trình:
 * 1. Kết nối tới server (192.168.102.18:8080)
 * 2. Hiển thị main menu với 2 lựa chọn chính:
 *    - Account Management: Đăng ký, login, update profile
 *    - Group Management: Tạo nhóm, chia sẻ file, quản lý members
 * 3. Vòng lặp xử lý user input cho đến khi thoát
 * 4. Đóng kết nối khi thoát
 * 
 * @return: 0 nếu thành công, 1 nếu không kết nối được server
 */
int main() {
    // Kết nối tới server
    int sock = connect_to_server();
    if (sock < 0) {
        return 1;
    }
    
    // Vòng lặp main menu
    int choice;
    while (1) {
        clear_screen();
        printf("\n╔════════════════════════════════════════╗\n");
        printf("║     FILE SHARING SYSTEM - MAIN MENU    ║\n");
        printf("╚════════════════════════════════════════╝\n");
        
        if (strlen(g_session_token) > 0) {
            printf("  👤 Logged in as: %s (ID: %d)\n", g_username, g_user_id);
            print_separator();
        }
        
        printf("\n📋 MAIN CATEGORIES:\n");
        printf("  1. 👤 Account Management\n");
        printf("  2. 👥 Group Management\n");
        printf("  3. 📁 Folder Management\n");
        printf("  4. 🚪 Exit\n");
        printf("\nChoice: ");
        scanf("%d", &choice);
        
        switch (choice) {
            case 1:
                show_account_menu(sock);
                break;
            case 2:
                show_group_menu(sock);
                break;
            case 3:
                show_folder_menu(sock);
                break;
            case 4:
                printf("\n👋 Goodbye!\n");
                close(sock);
                return 0;
            default:
                printf("\n✗ Invalid choice!\n");
                wait_for_enter();
        }
    }
    
    return 0;
}

/**
 * Hiển thị menu quản lý tài khoản
 * @param sock: Socket đã kết nối tới server
 * 
 * Tính năng:
 * - Đăng ký tài khoản mới
 * - Đăng nhập/đăng xuất
 * - Cập nhật thông tin profile
 * - Đổi mật khẩu
 */
/**
 * Hiển thị menu quản lý tài khoản
 * @param sock: Socket đã kết nối tới server
 * 
 * Tính năng:
 * - Đăng ký tài khoản mới
 * - Đăng nhập/đăng xuất
 * - Cập nhật thông tin profile
 * - Đổi mật khẩu
 */
void show_account_menu(int sock) {
    int choice;
    while (1) {
        clear_screen();
        printf("\n╔════════════════════════════════════════╗\n");
        printf("║       👤 ACCOUNT MANAGEMENT           ║\n");
        printf("╚════════════════════════════════════════╝\n");
        
        printf("\n1. 📝 Register New Account\n");
        printf("2. 🔐 Login\n");
        printf("3. 🚪 Logout\n");
        // printf("4. ✓ Verify Session\n");
        printf("5. ✏️  Update Profile\n");
        printf("6. 🔑 Change Password\n");
        printf("7. 🔙 Back to Main Menu\n");
        printf("\nChoice: ");
        scanf("%d", &choice);
        
        switch (choice) {
            case 1:
                send_register_request(sock);
                break;
            case 2:
                send_login_request(sock);
                break;
            case 3:
                send_logout_request(sock);
                break;
            case 4:
                send_verify_session_request(sock);
                break;
            case 5:
                send_update_profile_request(sock);
                break;
            case 6:
                send_change_password_request(sock);
                break;
            case 7:
                return;
            default:
                printf("\n✗ Invalid choice!\n");
                wait_for_enter();
        }
    }
}


// ============================================================================
// NOTIFICATION MANAGEMENT - QUẢN LÝ THÔNG BÁO
// ============================================================================

/**
 * Lấy danh sách tất cả thông báo của user
 * @param sock: Socket đã kết nối tới server
 * 
 * Hiển thị: notification_id, message, created_at, is_read
 * Bao gồm thông báo về: join requests, invitations, group activities
 */
void send_get_notifications_request(int sock) {
    // Kiểm tra authentication
    if (strlen(g_session_token) == 0) {
        print_error("Please login first!");
        wait_for_enter();
        return;
    }
    
    print_separator();
    printf("=== GET NOTIFICATIONS ===\n");
    printf("Session token: %s\n\n", g_session_token);
    
    // Tạo request lấy notifications
    struct json_object *request = json_object_new_object();
    json_object_object_add(request, "command", json_object_new_string("GET_NOTIFICATIONS"));
    
    struct json_object *data = json_object_new_object();
    json_object_object_add(data, "session_token", json_object_new_string(g_session_token));
    json_object_object_add(request, "data", data);
    
    const char *json_str = json_object_to_json_string(request);
    send(sock, json_str, strlen(json_str), 0);
    json_object_put(request);
    
    // Nhận và hiển thị danh sách notifications
    char buffer[BUFFER_SIZE];
    int bytes = recv(sock, buffer, BUFFER_SIZE - 1, 0);
    if (bytes > 0) {
        buffer[bytes] = '\0';
        printf("\nResponse:\n");
        parse_and_display_response(buffer);
    }
    
    wait_for_enter();
}

/**
 * Đánh dấu một thông báo đã đọc
 * @param sock: Socket đã kết nối tới server
 * 
 * Cập nhật trạng thái is_read của notification từ false -> true
 * Giảm unread_count
 */
void send_mark_notification_read_request(int sock) {
    // Kiểm tra authentication
    if (strlen(g_session_token) == 0) {
        print_error("Please login first!");
        wait_for_enter();
        return;
    }
    
    print_separator();
    printf("=== MARK NOTIFICATION READ ===\n");
    printf("Session token: %s\n", g_session_token);
    
    // Nhập notification ID cần đánh dấu
    int notification_id;
    printf("Notification ID: ");
    scanf("%d", &notification_id);
    getchar();
    
    // Tạo mark read request
    struct json_object *request = json_object_new_object();
    json_object_object_add(request, "command", json_object_new_string("MARK_NOTIFICATION_READ"));
    
    struct json_object *data = json_object_new_object();
    json_object_object_add(data, "session_token", json_object_new_string(g_session_token));
    json_object_object_add(data, "notification_id", json_object_new_int(notification_id));
    json_object_object_add(request, "data", data);
    
    const char *json_str = json_object_to_json_string(request);
    send(sock, json_str, strlen(json_str), 0);
    json_object_put(request);
    
    // Nhận response
    char buffer[BUFFER_SIZE];
    int bytes = recv(sock, buffer, BUFFER_SIZE - 1, 0);
    if (bytes > 0) {
        buffer[bytes] = '\0';
        printf("\nResponse:\n");
        parse_and_display_response(buffer);
    }
    
    wait_for_enter();
}

/**
 * Đếm số thông báo chưa đọc
 * @param sock: Socket đã kết nối tới server
 * 
 * Trả về số lượng notifications với is_read = false
 * Sử dụng để hiển thị badge trong menu
 */
void send_get_unread_count_request(int sock) {
    // Kiểm tra authentication
    if (strlen(g_session_token) == 0) {
        print_error("Please login first!");
        wait_for_enter();
        return;
    }
    
    print_separator();
    printf("=== GET UNREAD NOTIFICATION COUNT ===\n");
    printf("Session token: %s\n\n", g_session_token);
    
    // Tạo request đếm unread
    struct json_object *request = json_object_new_object();
    json_object_object_add(request, "command", json_object_new_string("GET_UNREAD_COUNT"));
    
    struct json_object *data = json_object_new_object();
    json_object_object_add(data, "session_token", json_object_new_string(g_session_token));
    json_object_object_add(request, "data", data);
    
    const char *json_str = json_object_to_json_string(request);
    send(sock, json_str, strlen(json_str), 0);
    json_object_put(request);
    
    // Nhận và hiển thị số lượng
    char buffer[BUFFER_SIZE];
    int bytes = recv(sock, buffer, BUFFER_SIZE - 1, 0);
    if (bytes > 0) {
        buffer[bytes] = '\0';
        printf("\nResponse:\n");
        parse_and_display_response(buffer);
    }
    
    wait_for_enter();
}

/**
 * Hiển thị menu quản lý thư mục/file
 * @param sock: Socket đã kết nối tới server
 * 
 * Tính năng:
 * - Tạo thư mục
 * - Đổi tên thư mục
 * - Xóa thư mục
 * - Copy/Move thư mục
 */
void show_folder_menu(int sock) {
    int choice;
    while (1) {
        clear_screen();
        printf("\n=== FOLDER & FILE MANAGEMENT ===\n");
        print_separator();
        printf("Directory Operations:\n");
        printf("1. List Directory Contents\n");
        printf("2. Create Directory\n");
        printf("3. Rename Directory (Admin)\n");
        printf("4. Delete Directory (Admin)\n");
        printf("5. Copy Directory (Admin)\n");
        printf("6. Move Directory (Admin)\n");
        printf("\nFile Operations:\n");
        printf("7. Upload File\n");
        printf("8. Download File\n");
        printf("9. Rename File (Admin)\n");
        printf("10. Delete File (Admin)\n");
        printf("11. Copy File\n");
        printf("12. Move File (Admin)\n");
        printf("\n0. Back to Main Menu\n");
        print_separator();
        printf("Choice: ");
        scanf("%d", &choice);
        
        switch (choice) {
            case 1:
                send_list_directory_request(sock);
                break;
            case 2:
                send_create_directory_request(sock);
                break;
            case 3:
                send_rename_directory_request(sock);
                break;
            case 4:
                send_delete_directory_request(sock);
                break;
            case 5:
                send_copy_directory_request(sock);
                break;
            case 6:
                send_move_directory_request(sock);
                break;
            case 7:
                send_upload_file_request(sock);
                break;
            case 8:
                send_download_file_request(sock);
                break;
            case 9:
                send_rename_file_request(sock);
                break;
            case 10:
                send_delete_file_request(sock);
                break;
            case 11:
                send_copy_file_request(sock);
                break;
            case 12:
                send_move_file_request(sock);
                break;
            case 0:
                return;
            default:
                print_error("Invalid choice!");
                wait_for_enter();
        }
        
    }
}

// ============================================================================
// MENU SYSTEM - HỆ THỐNG MENU ĐIỀU HƯỚNG
// ============================================================================

/**
 * Hiển thị menu quản lý nhóm với thông báo real-time
 * @param sock: Socket đã kết nối tới server
 * 
 * Tính năng:
 * - Hiển thị số thông báo chưa đọc
 * - Quản lý nhóm (create, list, join, leave, etc.)
 * - Quản lý thành viên (invite, approve, remove)
 * - Xem và quản lý thông báo
 */
void show_group_menu(int sock) {
    while (1) {
        clear_screen();
        
        // Lấy số thông báo chưa đọc
        struct json_object *check_request = json_object_new_object();
        json_object_object_add(check_request, "command", json_object_new_string("GET_UNREAD_COUNT"));
        struct json_object *check_data = json_object_new_object();
        json_object_object_add(check_data, "session_token", json_object_new_string(g_session_token));
        json_object_object_add(check_request, "data", check_data);
        
        const char *check_json = json_object_to_json_string(check_request);
        send(sock, check_json, strlen(check_json), 0);
        
        char buffer[BUFFER_SIZE];
        int bytes = recv(sock, buffer, BUFFER_SIZE - 1, 0);
        buffer[bytes] = '\0';
        
        int unread_count = 0;
        struct json_object *check_response = json_tokener_parse(buffer);
        if (check_response) {
            struct json_object *payload, *count_obj;
            if (json_object_object_get_ex(check_response, "payload", &payload) &&
                json_object_object_get_ex(payload, "unread_count", &count_obj)) {
                unread_count = json_object_get_int(count_obj);
            }
            json_object_put(check_response);
        }
        json_object_put(check_request);
        
        print_separator();
        printf("👥 GROUP MANAGEMENT MENU\n");
        print_separator();
        printf("User: %s (ID: %d)\n", g_username, g_user_id);
        if (unread_count > 0) {
            printf("🔴 You have %d unread notification%s!\n", unread_count, unread_count > 1 ? "s" : "");
        }
        printf("\n");
        
        printf("1.  Create Group\n");
        printf("2.  List My Groups\n");
        printf("3.  List Group Members\n");
        printf("4.  Request Join Group\n");
        printf("5.  List Join Requests (Admin)\n");
        printf("6.  Approve/Reject Join Request (Admin)\n");
        printf("7.  Invite to Group (Admin)\n");
        printf("8.  List My Invitations\n");
        printf("9.  Respond to Invitation\n");
        printf("10. Leave Group\n");
        printf("11. Remove Member (Admin)\n");
        printf("12. 🔔 View All Notifications%s\n", unread_count > 0 ? " 🔴" : "");
        printf("13. Mark Notification as Read\n");
        printf("14. Mark All as Read\n");
        printf("0.  Back to Main Menu\n");
        print_separator();
        
        int choice;
        printf("Enter your choice: ");
        scanf("%d", &choice);
        getchar();
        
        switch (choice) {
            case 1: send_create_group_request(sock); break;
            case 2: send_list_my_groups_request(sock); break;
            case 3: send_list_group_members_request(sock); break;
            case 4: send_request_join_group_request(sock); break;
            case 5: send_list_join_requests_request(sock); break;
            case 6: send_approve_join_request_request(sock); break;
            case 7: send_invite_to_group_request(sock); break;
            case 8: send_list_my_invitations_request(sock); break;
            case 9: send_respond_invitation_request(sock); break;
            case 10: send_leave_group_request(sock); break;
            case 11: send_remove_member_request(sock); break;
            case 12: send_get_notifications_request(sock); break;
            case 13: send_mark_notification_read_request(sock); break;
            case 14: 
                // Mark all as read
                {
                    struct json_object *mark_all = json_object_new_object();
                    json_object_object_add(mark_all, "command", json_object_new_string("MARK_ALL_NOTIFICATIONS_READ"));
                    struct json_object *mark_data = json_object_new_object();
                    json_object_object_add(mark_data, "session_token", json_object_new_string(g_session_token));
                    json_object_object_add(mark_all, "data", mark_data);
                    
                    const char *mark_json = json_object_to_json_string(mark_all);
                    send(sock, mark_json, strlen(mark_json), 0);
                    json_object_put(mark_all);
                    
                    char resp[BUFFER_SIZE];
                    bytes = recv(sock, resp, BUFFER_SIZE - 1, 0);
                    resp[bytes] = '\0';
                    parse_and_display_response(resp);
                    wait_for_enter();
                }
                break;
            case 0: return;
            default:
                print_error("Invalid choice!");
                wait_for_enter();
        }
    }
}

