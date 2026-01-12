#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <openssl/sha.h>
#include <uuid/uuid.h>
#include <json-c/json.h>
#include "auth_handler.h"
#include "database.h"
#include "../common/protocol.h"

void send_error_response(int sock, int status, const char *code, const char *message) {
    struct json_object *response = json_object_new_object();
    json_object_object_add(response, "status", json_object_new_int(status));
    json_object_object_add(response, "code", json_object_new_string(code));
    json_object_object_add(response, "message", json_object_new_string(message));
    json_object_object_add(response, "payload", json_object_new_object());
    
    const char *json_str = json_object_to_json_string(response);
    send(sock, json_str, strlen(json_str), 0);
    
    json_object_put(response);
}

void hash_password(const char *password, char *hash_out) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)password, strlen(password), hash);
    
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hash_out + (i * 2), "%02x", hash[i]);
    }
    hash_out[64] = '\0';
}

void generate_session_token(char *token_out) {
    uuid_t uuid;
    uuid_generate(uuid);
    uuid_unparse(uuid, token_out);
}

void handle_register(int sock, struct json_object *request) {
    struct json_object *data_obj, *field;
    
    if (!json_object_object_get_ex(request, "data", &data_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing data field");
        return;
    }
    
    // Extract fields
    const char *username = NULL, *password = NULL, *email = NULL, *full_name = NULL;
    
    if (json_object_object_get_ex(data_obj, "username", &field))
        username = json_object_get_string(field);
    if (json_object_object_get_ex(data_obj, "password", &field))
        password = json_object_get_string(field);
    if (json_object_object_get_ex(data_obj, "email", &field))
        email = json_object_get_string(field);
    if (json_object_object_get_ex(data_obj, "full_name", &field))
        full_name = json_object_get_string(field);
    
    if (!username || !password || !email || !full_name) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing required fields");
        return;
    }
    
    // Hash password
    char hashed_password[65];
    hash_password(password, hashed_password);
    
    // Insert into database
    int user_id = db_create_user(username, hashed_password, email, full_name);
    
    if (user_id < 0) {
        if (user_id == -2) {
            send_error_response(sock, STATUS_CONFLICT, "ERROR_CONFLICT", "Username already exists");
        } else {
            send_error_response(sock, STATUS_INTERNAL_ERROR, "ERROR_INTERNAL_SERVER", "Failed to create user");
        }
        return;
    }
    
    // Get current timestamp
    time_t now = time(NULL);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));
    
    // Send success response
    struct json_object *response = json_object_new_object();
    json_object_object_add(response, "status", json_object_new_int(STATUS_CREATED));
    json_object_object_add(response, "code", json_object_new_string("SUCCESS_REGISTER"));
    json_object_object_add(response, "message", json_object_new_string("User registered successfully"));
    
    struct json_object *payload = json_object_new_object();
    json_object_object_add(payload, "user_id", json_object_new_int(user_id));
    json_object_object_add(payload, "username", json_object_new_string(username));
    json_object_object_add(payload, "created_at", json_object_new_string(timestamp));
    json_object_object_add(response, "payload", payload);
    
    const char *json_str = json_object_to_json_string(response);
    send(sock, json_str, strlen(json_str), 0);
    
    json_object_put(response);
}

void handle_login(int sock, struct json_object *request, const char *client_ip) {
    struct json_object *data_obj, *field;
    
    if (!json_object_object_get_ex(request, "data", &data_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing data field");
        return;
    }
    
    const char *username = NULL, *password = NULL;
    
    if (json_object_object_get_ex(data_obj, "username", &field))
        username = json_object_get_string(field);
    if (json_object_object_get_ex(data_obj, "password", &field))
        password = json_object_get_string(field);
    
    if (!username || !password) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing username or password");
        return;
    }
    
    // Hash password
    char hashed_password[65];
    hash_password(password, hashed_password);
    
    // Verify credentials
    UserInfo *user = db_verify_user(username, hashed_password);
    
    if (!user) {
        send_error_response(sock, STATUS_UNAUTHORIZED, "ERROR_UNAUTHORIZED", "Invalid username or password");
        return;
    }
    
    // Update last login time
    db_update_last_login(user->user_id);
    
    // Generate session token
    char session_token[37];
    generate_session_token(session_token);
    
    // Create session (expires in 24 hours)
    time_t expires_at = time(NULL) + 86400;
    if (!db_create_session(user->user_id, session_token, client_ip, expires_at)) {
        free(user);
        send_error_response(sock, STATUS_INTERNAL_ERROR, "ERROR_INTERNAL_SERVER", "Failed to create session");
        return;
    }
    
    // Format timestamps
    char expires_str[64];
    strftime(expires_str, sizeof(expires_str), "%Y-%m-%dT%H:%M:%SZ", gmtime(&expires_at));
    
    // Send success response
    struct json_object *response = json_object_new_object();
    json_object_object_add(response, "status", json_object_new_int(STATUS_OK));
    json_object_object_add(response, "code", json_object_new_string("SUCCESS_LOGIN"));
    json_object_object_add(response, "message", json_object_new_string("Login successful"));
    
    struct json_object *payload = json_object_new_object();
    json_object_object_add(payload, "user_id", json_object_new_int(user->user_id));
    json_object_object_add(payload, "username", json_object_new_string(user->username));
    json_object_object_add(payload, "session_token", json_object_new_string(session_token));
    json_object_object_add(payload, "role", json_object_new_string(user->role));
    json_object_object_add(payload, "expires_at", json_object_new_string(expires_str));
    json_object_object_add(response, "payload", payload);
    
    const char *json_str = json_object_to_json_string(response);
    send(sock, json_str, strlen(json_str), 0);
    
    free(user);
    json_object_put(response);
}

void handle_logout(int sock, struct json_object *request) {
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
    
    // Invalidate session
    if (!db_invalidate_session(session_token)) {
        send_error_response(sock, STATUS_INTERNAL_ERROR, "ERROR_INTERNAL_SERVER", "Failed to logout");
        return;
    }
    
    // Send success response
    struct json_object *response = json_object_new_object();
    json_object_object_add(response, "status", json_object_new_int(STATUS_OK));
    json_object_object_add(response, "code", json_object_new_string("SUCCESS_LOGOUT"));
    json_object_object_add(response, "message", json_object_new_string("Logout successful"));
    json_object_object_add(response, "payload", json_object_new_object());
    
    const char *json_str = json_object_to_json_string(response);
    send(sock, json_str, strlen(json_str), 0);
    
    json_object_put(response);
}

void handle_verify_session(int sock, struct json_object *request) {
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
    
    // Get session expiry time (need to query again for expires_at)
    // For now, we'll calculate it as 24 hours from now (simplified)
    time_t expires_at = time(NULL) + 86400;
    char expires_str[64];
    strftime(expires_str, sizeof(expires_str), "%Y-%m-%dT%H:%M:%SZ", gmtime(&expires_at));
    
    // Send success response
    struct json_object *response = json_object_new_object();
    json_object_object_add(response, "status", json_object_new_int(STATUS_OK));
    json_object_object_add(response, "code", json_object_new_string("SUCCESS_VERIFY_SESSION"));
    json_object_object_add(response, "message", json_object_new_string("Session is valid"));
    
    struct json_object *payload = json_object_new_object();
    json_object_object_add(payload, "user_id", json_object_new_int(user->user_id));
    json_object_object_add(payload, "username", json_object_new_string(user->username));
    json_object_object_add(payload, "expires_at", json_object_new_string(expires_str));
    json_object_object_add(response, "payload", payload);
    
    const char *json_str = json_object_to_json_string(response);
    send(sock, json_str, strlen(json_str), 0);
    
    free(user);
    json_object_put(response);
}

void handle_update_profile(int sock, struct json_object *request) {
    struct json_object *data_obj, *field;
    
    if (!json_object_object_get_ex(request, "data", &data_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing data field");
        return;
    }
    
    const char *session_token = NULL, *email = NULL, *full_name = NULL;
    
    if (json_object_object_get_ex(data_obj, "session_token", &field))
        session_token = json_object_get_string(field);
    if (json_object_object_get_ex(data_obj, "email", &field))
        email = json_object_get_string(field);
    if (json_object_object_get_ex(data_obj, "full_name", &field))
        full_name = json_object_get_string(field);
    
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
    
    // Update profile
    if (!db_update_profile(user->user_id, email, full_name)) {
        free(user);
        send_error_response(sock, STATUS_INTERNAL_ERROR, "ERROR_INTERNAL_SERVER", "Failed to update profile");
        return;
    }
    
    // Send success response
    struct json_object *response = json_object_new_object();
    json_object_object_add(response, "status", json_object_new_int(STATUS_OK));
    json_object_object_add(response, "code", json_object_new_string("SUCCESS_UPDATE"));
    json_object_object_add(response, "message", json_object_new_string("Profile updated successfully"));
    
    struct json_object *payload = json_object_new_object();
    json_object_object_add(payload, "user_id", json_object_new_int(user->user_id));
    json_object_object_add(payload, "username", json_object_new_string(user->username));
    json_object_object_add(payload, "email", json_object_new_string(email));
    json_object_object_add(payload, "full_name", json_object_new_string(full_name));
    json_object_object_add(response, "payload", payload);
    
    const char *json_str = json_object_to_json_string(response);
    send(sock, json_str, strlen(json_str), 0);
    
    free(user);
    json_object_put(response);
}

void handle_change_password(int sock, struct json_object *request) {
    struct json_object *data_obj, *field;
    
    if (!json_object_object_get_ex(request, "data", &data_obj)) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing data field");
        return;
    }
    
    const char *session_token = NULL, *old_password = NULL, *new_password = NULL;
    
    if (json_object_object_get_ex(data_obj, "session_token", &field))
        session_token = json_object_get_string(field);
    if (json_object_object_get_ex(data_obj, "old_password", &field))
        old_password = json_object_get_string(field);
    if (json_object_object_get_ex(data_obj, "new_password", &field))
        new_password = json_object_get_string(field);
    
    if (!session_token || !old_password || !new_password) {
        send_error_response(sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing required fields");
        return;
    }
    
    // Verify session
    UserInfo *user = db_verify_session(session_token);
    if (!user) {
        send_error_response(sock, STATUS_UNAUTHORIZED, "ERROR_UNAUTHORIZED", "Invalid session token or session expired");
        return;
    }
    
    // Verify old password
    char old_hash[65];
    hash_password(old_password, old_hash);
    
    UserInfo *verified = db_verify_user(user->username, old_hash);
    if (!verified) {
        free(user);
        send_error_response(sock, STATUS_UNAUTHORIZED, "ERROR_UNAUTHORIZED", "Old password is incorrect");
        return;
    }
    free(verified);
    
    // Hash new password
    char new_hash[65];
    hash_password(new_password, new_hash);
    
    // Update password
    if (!db_change_password(user->user_id, new_hash)) {
        free(user);
        send_error_response(sock, STATUS_INTERNAL_ERROR, "ERROR_INTERNAL_SERVER", "Failed to change password");
        return;
    }
    
    // Send success response
    struct json_object *response = json_object_new_object();
    json_object_object_add(response, "status", json_object_new_int(STATUS_OK));
    json_object_object_add(response, "code", json_object_new_string("SUCCESS_CHANGE_PASSWORD"));
    json_object_object_add(response, "message", json_object_new_string("Password changed successfully"));
    json_object_object_add(response, "payload", json_object_new_object());
    
    const char *json_str = json_object_to_json_string(response);
    send(sock, json_str, strlen(json_str), 0);
    
    free(user);
    json_object_put(response);
}
