#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <libpq-fe.h>
#include <json-c/json.h>
#include "../common/protocol.h"
#include "auth_handler.h"
#include "permission_handler.h"
#include "group_handler.h"
#include "folder_handler.h"
#include "file_handler.h"
#include "database.h"

typedef struct {
    int sock;
    char ip[46];
} ClientInfo;

void *handle_client(void *arg) {
    ClientInfo *client_info = (ClientInfo *)arg;
    int client_sock = client_info->sock;
    char *client_ip = client_info->ip;
    free(client_info);
    
    char buffer[BUFFER_SIZE];
    int bytes_received;
    int total_received = 0;
    
    while ((bytes_received = recv(client_sock, buffer + total_received, BUFFER_SIZE - total_received - 1, 0)) > 0) {
        total_received += bytes_received;
        buffer[total_received] = '\0';
        
        // Try to parse JSON
        struct json_object *request = json_tokener_parse(buffer);
        if (!request) {
            // Check if we might need more data
            if (total_received < BUFFER_SIZE - 1) {
                // Might be incomplete, try to receive more
                continue;
            }
            // Buffer full but still invalid JSON
            send_error_response(client_sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Invalid JSON format");
            total_received = 0;  // Reset for next message
            continue;
        }
        
        // Display received request
        printf("\n========================================\n");
        printf("Received from %s: [%d bytes]\n", client_ip, total_received);
        if (total_received > 500) {
            // For large requests (chunks), show preview only
            printf("Request preview (first 500 chars):\n%.500s...\n", buffer);
        } else {
            // Show full request for small messages
            printf("Request:\n%s\n", buffer);
        }
        printf("========================================\n");
        
        // Get command
        struct json_object *cmd_obj;
        if (!json_object_object_get_ex(request, "command", &cmd_obj)) {
            send_error_response(client_sock, STATUS_BAD_REQUEST, "ERROR_INVALID_REQUEST", "Missing command field");
            json_object_put(request);
            continue;
        }
        
        const char *command = json_object_get_string(cmd_obj);
        
        // Route to appropriate handler
        if (strcmp(command, "REGISTER") == 0) {
            handle_register(client_sock, request);
        } else if (strcmp(command, "LOGIN") == 0) {
            handle_login(client_sock, request, client_ip);
        } else if (strcmp(command, "LOGOUT") == 0) {
            handle_logout(client_sock, request);
        } else if (strcmp(command, "VERIFY_SESSION") == 0) {
            handle_verify_session(client_sock, request);
        } else if (strcmp(command, "UPDATE_PROFILE") == 0) {
            handle_update_profile(client_sock, request);
        } else if (strcmp(command, "CHANGE_PASSWORD") == 0) {
            handle_change_password(client_sock, request);
        } else if (strcmp(command, "GET_PERMISSIONS") == 0) {
            handle_get_permissions(client_sock, request);
        } else if (strcmp(command, "UPDATE_PERMISSIONS") == 0) {
            handle_update_permissions(client_sock, request);
        } else if (strcmp(command, "CREATE_GROUP") == 0) {
            handle_create_group(client_sock, request);
        } else if (strcmp(command, "LIST_MY_GROUPS") == 0) {
            handle_list_my_groups(client_sock, request);
        } else if (strcmp(command, "LIST_AVAILABLE_GROUPS") == 0) {
            handle_list_available_groups(client_sock, request);
        } else if (strcmp(command, "LIST_GROUP_MEMBERS") == 0) {
            handle_list_group_members(client_sock, request);
        } else if (strcmp(command, "REQUEST_JOIN_GROUP") == 0) {
            handle_request_join_group(client_sock, request);
        } else if (strcmp(command, "LIST_JOIN_REQUESTS") == 0) {
            handle_list_join_requests(client_sock, request);
        } else if (strcmp(command, "APPROVE_JOIN_REQUEST") == 0) {
            handle_approve_join_request(client_sock, request);
        } else if (strcmp(command, "INVITE_TO_GROUP") == 0) {
            handle_invite_to_group(client_sock, request);
        } else if (strcmp(command, "LIST_MY_INVITATIONS") == 0) {
            handle_list_my_invitations(client_sock, request);
        } else if (strcmp(command, "RESPOND_INVITATION") == 0) {
            handle_respond_invitation(client_sock, request);
        } else if (strcmp(command, "LEAVE_GROUP") == 0) {
            handle_leave_group(client_sock, request);
        } else if (strcmp(command, "REMOVE_MEMBER") == 0) {
            handle_remove_member(client_sock, request);
        } else if (strcmp(command, "GET_NOTIFICATIONS") == 0) {
            handle_get_notifications(client_sock, request);
        } else if (strcmp(command, "MARK_NOTIFICATION_READ") == 0) {
            handle_mark_notification_read(client_sock, request);
        } else if (strcmp(command, "MARK_ALL_NOTIFICATIONS_READ") == 0) {
            handle_mark_all_notifications_read(client_sock, request);
        } else if (strcmp(command, "GET_UNREAD_COUNT") == 0) {
            handle_get_unread_count(client_sock, request);
        } else if (strcmp(command, "CREATE_DIRECTORY") == 0) {
            handle_create_directory(client_sock, request);
        } else if (strcmp(command, "RENAME_DIRECTORY") == 0) {
            handle_rename_directory(client_sock, request);
        } else if (strcmp(command, "DELETE_DIRECTORY") == 0) {
            handle_delete_directory(client_sock, request);
        } else if (strcmp(command, "COPY_DIRECTORY") == 0) {
            handle_copy_directory(client_sock, request);
        } else if (strcmp(command, "MOVE_DIRECTORY") == 0) {
            handle_move_directory(client_sock, request);
        } else if (strcmp(command, "LIST_DIRECTORY") == 0) {
            handle_list_directory(client_sock, request);
        } else if (strcmp(command, "UPLOAD_FILE_START") == 0) {
            handle_upload_file_start(client_sock, request);
        } else if (strcmp(command, "UPLOAD_FILE_CHUNK") == 0) {
            handle_upload_file_chunk(client_sock, request);
        } else if (strcmp(command, "UPLOAD_FILE_COMPLETE") == 0) {
            handle_upload_file_complete(client_sock, request);
        } else if (strcmp(command, "DOWNLOAD_FILE_START") == 0) {
            handle_download_file_start(client_sock, request);
        } else if (strcmp(command, "DOWNLOAD_FILE_CHUNK") == 0) {
            handle_download_file_chunk(client_sock, request);
        } else if (strcmp(command, "DOWNLOAD_FILE_COMPLETE") == 0) {
            handle_download_file_complete(client_sock, request);
        } else if (strcmp(command, "RENAME_FILE") == 0) {
            handle_rename_file(client_sock, request);
        } else if (strcmp(command, "DELETE_FILE") == 0) {
            handle_delete_file(client_sock, request);
        } else if (strcmp(command, "COPY_FILE") == 0) {
            handle_copy_file(client_sock, request);
        } else if (strcmp(command, "MOVE_FILE") == 0) {
            handle_move_file(client_sock, request);
        } 
        else {
            send_error_response(client_sock, STATUS_BAD_REQUEST, "ERROR_INVALID_COMMAND", "Unknown command");
        }
        
        json_object_put(request);
        total_received = 0;  // Reset buffer for next message
        memset(buffer, 0, BUFFER_SIZE);  // Clear buffer
    }
    
    close(client_sock);
    printf("Client disconnected: %s\n", client_ip);
    return NULL;
}

int main() {
    int server_sock, *client_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    pthread_t thread_id;
    
    // Initialize database connection
    if (!init_database()) {
        fprintf(stderr, "Failed to initialize database\n");
        return 1;
    }
    
    // Create socket
    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("Socket creation failed");
        return 1;
    }
    
    // Set socket options
    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    // Bind
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    server_addr.sin_port = htons(PORT);
    
    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_sock);
        return 1;
    }
    
    // Listen
    if (listen(server_sock, 10) < 0) {
        perror("Listen failed");
        close(server_sock);
        return 1;
    }
    
    printf("Server listening on 192.168.102.18:%d\n", PORT);
    
    // Accept connections
    while (1) {
        client_sock = malloc(sizeof(int));
        *client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &client_len);
        
        if (*client_sock < 0) {
            perror("Accept failed");
            free(client_sock);
            continue;
        }
        
        // Prepare client info
        ClientInfo *client_info = malloc(sizeof(ClientInfo));
        client_info->sock = *client_sock;
        strncpy(client_info->ip, inet_ntoa(client_addr.sin_addr), 45);
        client_info->ip[45] = '\0';
        free(client_sock);
        
        printf("New client connected from %s:%d\n", 
               client_info->ip, 
               ntohs(client_addr.sin_port));
        
        if (pthread_create(&thread_id, NULL, handle_client, client_info) != 0) {
            perror("Thread creation failed");
            close(client_info->sock);
            free(client_info);
        }
        
        pthread_detach(thread_id);
    }
    
    close(server_sock);
    cleanup_database();
    return 0;
}
