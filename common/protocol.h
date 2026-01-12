#ifndef PROTOCOL_H
#define PROTOCOL_H

#define PORT 8080
#define BUFFER_SIZE 1048576  // 1MB - enough for base64 encoded 512KB chunks + JSON overhead
#define MAX_USERNAME 50
#define MAX_PASSWORD 100
#define MAX_EMAIL 100
#define MAX_FULLNAME 100
#define MAX_TOKEN 64

// Response status codes
#define STATUS_OK 200
#define STATUS_CREATED 201
#define STATUS_BAD_REQUEST 400
#define STATUS_UNAUTHORIZED 401
#define STATUS_FORBIDDEN 403
#define STATUS_NOT_FOUND 404
#define STATUS_CONFLICT 409
#define STATUS_INTERNAL_ERROR 500

#endif
