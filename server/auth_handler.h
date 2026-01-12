#ifndef AUTH_HANDLER_H
#define AUTH_HANDLER_H

#include <json-c/json.h>

void send_error_response(int sock, int status, const char *code, const char *message);
void handle_register(int sock, struct json_object *request);
void handle_login(int sock, struct json_object *request, const char *client_ip);
void handle_logout(int sock, struct json_object *request);
void handle_verify_session(int sock, struct json_object *request);
void handle_update_profile(int sock, struct json_object *request);
void handle_change_password(int sock, struct json_object *request);

#endif
