#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libpq-fe.h>
#include "database.h"

static PGconn *conn = NULL;

int init_database() {
    const char *conninfo = "host=localhost dbname=file_sharing_db user=postgres password=postgres";
    
    conn = PQconnectdb(conninfo);
    
    if (PQstatus(conn) != CONNECTION_OK) {
        fprintf(stderr, "Connection to database failed: %s", PQerrorMessage(conn));
        PQfinish(conn);
        conn = NULL;
        return 0;
    }
    
    printf("Connected to database successfully\n");
    return 1;
}

void cleanup_database() {
    if (conn) {
        PQfinish(conn);
        conn = NULL;
    }
}

int db_create_user(const char *username, const char *password_hash, const char *email, const char *full_name) {
    if (!conn) return -1;
    
    const char *paramValues[4] = {username, password_hash, email, full_name};
    
    PGresult *res = PQexecParams(conn,
        "INSERT INTO users (username, password_hash, email, full_name) VALUES ($1, $2, $3, $4) RETURNING user_id",
        4, NULL, paramValues, NULL, NULL, 0);
    
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "INSERT failed: %s", PQerrorMessage(conn));
        
        // Check for duplicate username
        if (strstr(PQerrorMessage(conn), "duplicate key") != NULL) {
            PQclear(res);
            return -2;
        }
        
        PQclear(res);
        return -1;
    }
    
    int user_id = atoi(PQgetvalue(res, 0, 0));
    PQclear(res);
    
    return user_id;
}

UserInfo* db_verify_user(const char *username, const char *password_hash) {
    if (!conn) return NULL;
    
    const char *paramValues[2] = {username, password_hash};
    
    PGresult *res = PQexecParams(conn,
        "SELECT user_id, username, role FROM users WHERE username = $1 AND password_hash = $2",
        2, NULL, paramValues, NULL, NULL, 0);
    
    if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        PQclear(res);
        return NULL;
    }
    
    UserInfo *user = (UserInfo*)malloc(sizeof(UserInfo));
    user->user_id = atoi(PQgetvalue(res, 0, 0));
    strncpy(user->username, PQgetvalue(res, 0, 1), 50);
    user->username[50] = '\0';
    strncpy(user->role, PQgetvalue(res, 0, 2), 20);
    user->role[20] = '\0';
    
    PQclear(res);
    
    return user;
}

int db_create_session(int user_id, const char *session_token, const char *ip_address, time_t expires_at) {
    if (!conn) return 0;
    
    char user_id_str[32], expires_str[32];
    sprintf(user_id_str, "%d", user_id);
    sprintf(expires_str, "%ld", expires_at);
    
    const char *paramValues[4] = {user_id_str, session_token, ip_address, expires_str};
    
    PGresult *res = PQexecParams(conn,
        "INSERT INTO sessions (user_id, session_token, ip_address, expires_at) VALUES ($1, $2, $3, to_timestamp($4))",
        4, NULL, paramValues, NULL, NULL, 0);
    
    int success = (PQresultStatus(res) == PGRES_COMMAND_OK);
    PQclear(res);
    
    return success;
}

int db_update_last_login(int user_id) {
    if (!conn) return 0;
    
    char user_id_str[32];
    sprintf(user_id_str, "%d", user_id);
    
    const char *paramValues[1] = {user_id_str};
    
    PGresult *res = PQexecParams(conn,
        "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE user_id = $1",
        1, NULL, paramValues, NULL, NULL, 0);
    
    int success = (PQresultStatus(res) == PGRES_COMMAND_OK);
    PQclear(res);
    
    return success;
}

UserInfo* db_verify_session(const char *session_token) {
    if (!conn) return NULL;
    
    const char *paramValues[1] = {session_token};
    
    PGresult *res = PQexecParams(conn,
        "SELECT s.user_id, u.username, u.role, s.expires_at FROM sessions s "
        "JOIN users u ON s.user_id = u.user_id "
        "WHERE s.session_token = $1 AND s.is_active = TRUE AND s.expires_at > CURRENT_TIMESTAMP",
        1, NULL, paramValues, NULL, NULL, 0);
    
    if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        PQclear(res);
        return NULL;
    }
    
    UserInfo *user = (UserInfo*)malloc(sizeof(UserInfo));
    user->user_id = atoi(PQgetvalue(res, 0, 0));
    strncpy(user->username, PQgetvalue(res, 0, 1), 50);
    user->username[50] = '\0';
    strncpy(user->role, PQgetvalue(res, 0, 2), 20);
    user->role[20] = '\0';
    
    PQclear(res);
    return user;
}

int db_invalidate_session(const char *session_token) {
    if (!conn) return 0;
    
    const char *paramValues[1] = {session_token};
    
    PGresult *res = PQexecParams(conn,
        "UPDATE sessions SET is_active = FALSE WHERE session_token = $1",
        1, NULL, paramValues, NULL, NULL, 0);
    
    int success = (PQresultStatus(res) == PGRES_COMMAND_OK);
    PQclear(res);
    
    return success;
}

int db_update_profile(int user_id, const char *email, const char *full_name) {
    if (!conn) return 0;
    
    char user_id_str[32];
    sprintf(user_id_str, "%d", user_id);
    
    const char *paramValues[3] = {user_id_str, email, full_name};
    
    PGresult *res = PQexecParams(conn,
        "UPDATE users SET email = $2, full_name = $3 WHERE user_id = $1",
        3, NULL, paramValues, NULL, NULL, 0);
    
    int success = (PQresultStatus(res) == PGRES_COMMAND_OK);
    PQclear(res);
    
    return success;
}

UserInfo* db_get_user_by_id(int user_id) {
    if (!conn) return NULL;
    
    char user_id_str[32];
    sprintf(user_id_str, "%d", user_id);
    
    const char *paramValues[1] = {user_id_str};
    
    PGresult *res = PQexecParams(conn,
        "SELECT user_id, username, role, email, full_name FROM users WHERE user_id = $1",
        1, NULL, paramValues, NULL, NULL, 0);
    
    if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        PQclear(res);
        return NULL;
    }
    
    UserInfo *user = (UserInfo*)malloc(sizeof(UserInfo));
    user->user_id = atoi(PQgetvalue(res, 0, 0));
    strncpy(user->username, PQgetvalue(res, 0, 1), 50);
    user->username[50] = '\0';
    strncpy(user->role, PQgetvalue(res, 0, 2), 20);
    user->role[20] = '\0';
    strncpy(user->email, PQgetvalue(res, 0, 3), 100);
    user->email[100] = '\0';
    strncpy(user->full_name, PQgetvalue(res, 0, 4), 100);
    user->full_name[100] = '\0';
    
    PQclear(res);
    return user;
}

int db_change_password(int user_id, const char *new_password_hash) {
    if (!conn) return 0;
    
    char user_id_str[32];
    sprintf(user_id_str, "%d", user_id);
    
    const char *paramValues[2] = {user_id_str, new_password_hash};
    
    PGresult *res = PQexecParams(conn,
        "UPDATE users SET password_hash = $2 WHERE user_id = $1",
        2, NULL, paramValues, NULL, NULL, 0);
    
    int success = (PQresultStatus(res) == PGRES_COMMAND_OK);
    PQclear(res);
    
    return success;
}

PermissionInfo* db_get_permissions(int user_id, int group_id) {
    if (!conn) return NULL;
    
    char user_id_str[32], group_id_str[32];
    sprintf(user_id_str, "%d", user_id);
    sprintf(group_id_str, "%d", group_id);
    
    const char *paramValues[2] = {user_id_str, group_id_str};
    
    PGresult *res = PQexecParams(conn,
        "SELECT permission_id, user_id, group_id, can_read, can_write, can_delete, can_manage "
        "FROM permissions WHERE user_id = $1 AND group_id = $2",
        2, NULL, paramValues, NULL, NULL, 0);
    
    if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        PQclear(res);
        return NULL;
    }
    
    PermissionInfo *perm = (PermissionInfo*)malloc(sizeof(PermissionInfo));
    perm->permission_id = atoi(PQgetvalue(res, 0, 0));
    perm->user_id = atoi(PQgetvalue(res, 0, 1));
    perm->group_id = atoi(PQgetvalue(res, 0, 2));
    perm->can_read = strcmp(PQgetvalue(res, 0, 3), "t") == 0 ? 1 : 0;
    perm->can_write = strcmp(PQgetvalue(res, 0, 4), "t") == 0 ? 1 : 0;
    perm->can_delete = strcmp(PQgetvalue(res, 0, 5), "t") == 0 ? 1 : 0;
    perm->can_manage = strcmp(PQgetvalue(res, 0, 6), "t") == 0 ? 1 : 0;
    
    PQclear(res);
    return perm;
}

int db_update_permissions(int user_id, int group_id, int can_read, int can_write, int can_delete, int can_manage) {
    if (!conn) return 0;
    
    char user_id_str[32], group_id_str[32];
    char can_read_str[10], can_write_str[10], can_delete_str[10], can_manage_str[10];
    
    sprintf(user_id_str, "%d", user_id);
    sprintf(group_id_str, "%d", group_id);
    sprintf(can_read_str, "%s", can_read ? "true" : "false");
    sprintf(can_write_str, "%s", can_write ? "true" : "false");
    sprintf(can_delete_str, "%s", can_delete ? "true" : "false");
    sprintf(can_manage_str, "%s", can_manage ? "true" : "false");
    
    const char *paramValues[6] = {user_id_str, group_id_str, can_read_str, can_write_str, can_delete_str, can_manage_str};
    
    // Check if permission exists
    PGresult *check_res = PQexecParams(conn,
        "SELECT permission_id FROM permissions WHERE user_id = $1 AND group_id = $2",
        2, NULL, paramValues, NULL, NULL, 0);
    
    int exists = (PQresultStatus(check_res) == PGRES_TUPLES_OK && PQntuples(check_res) > 0);
    PQclear(check_res);
    
    PGresult *res;
    if (exists) {
        // Update existing permission
        res = PQexecParams(conn,
            "UPDATE permissions SET can_read = $3, can_write = $4, can_delete = $5, can_manage = $6 "
            "WHERE user_id = $1 AND group_id = $2",
            6, NULL, paramValues, NULL, NULL, 0);
    } else {
        // Insert new permission
        res = PQexecParams(conn,
            "INSERT INTO permissions (user_id, group_id, can_read, can_write, can_delete, can_manage) "
            "VALUES ($1, $2, $3, $4, $5, $6)",
            6, NULL, paramValues, NULL, NULL, 0);
    }
    
    int success = (PQresultStatus(res) == PGRES_COMMAND_OK);
    PQclear(res);
    
    return success;
}

int db_is_group_admin(int user_id, int group_id) {
    if (!conn) return 0;
    
    char user_id_str[32], group_id_str[32];
    sprintf(user_id_str, "%d", user_id);
    sprintf(group_id_str, "%d", group_id);
    
    const char *paramValues[2] = {user_id_str, group_id_str};
    
    // Check if user is owner of the group
    PGresult *res = PQexecParams(conn,
        "SELECT group_id FROM groups WHERE group_id = $2 AND owner_id = $1",
        2, NULL, paramValues, NULL, NULL, 0);
    
    int is_owner = (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0);
    PQclear(res);
    
    if (is_owner) return 1;
    
    // Check if user is admin member of the group
    res = PQexecParams(conn,
        "SELECT member_id FROM group_members WHERE user_id = $1 AND group_id = $2 AND role = 'admin' AND status = 'approved'",
        2, NULL, paramValues, NULL, NULL, 0);
    
    int is_admin = (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0);
    PQclear(res);
    
    return is_admin;
}

int db_create_group(int owner_id, const char *group_name, const char *description) {
    if (!conn) return -1;
    
    char owner_id_str[32];
    sprintf(owner_id_str, "%d", owner_id);
    
    const char *paramValues[3] = {group_name, description ? description : "", owner_id_str};
    
    PGresult *res = PQexecParams(conn,
        "INSERT INTO groups (group_name, description, owner_id) VALUES ($1, $2, $3) RETURNING group_id",
        3, NULL, paramValues, NULL, NULL, 0);
    
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "INSERT group failed: %s", PQerrorMessage(conn));
        PQclear(res);
        return -1;
    }
    
    int group_id = atoi(PQgetvalue(res, 0, 0));
    PQclear(res);
    
    // Add owner as admin member
    char group_id_str[32];
    sprintf(group_id_str, "%d", group_id);
    const char *memberParams[2] = {group_id_str, owner_id_str};
    
    res = PQexecParams(conn,
        "INSERT INTO group_members (group_id, user_id, role, status) VALUES ($1, $2, 'admin', 'approved')",
        2, NULL, memberParams, NULL, NULL, 0);
    PQclear(res);
    
    // Create full permissions for owner (admin)
    const char *permParams[2] = {group_id_str, owner_id_str};
    res = PQexecParams(conn,
        "INSERT INTO permissions (group_id, user_id, can_read, can_write, can_delete, can_manage) "
        "VALUES ($1, $2, TRUE, TRUE, TRUE, TRUE)",
        2, NULL, permParams, NULL, NULL, 0);
    PQclear(res);
    
    return group_id;
}

int db_get_user_groups(int user_id, GroupInfo ***groups) {
    if (!conn) return 0;
    
    char user_id_str[32];
    sprintf(user_id_str, "%d", user_id);
    
    const char *paramValues[1] = {user_id_str};
    
    PGresult *res = PQexecParams(conn,
        "SELECT g.group_id, g.group_name, g.description, "
        "CASE WHEN g.owner_id = $1 THEN 'admin' ELSE COALESCE(gm.role, 'member') END as role, "
        "(SELECT COUNT(*) FROM group_members WHERE group_id = g.group_id AND status = 'approved') as member_count, "
        "g.created_at "
        "FROM groups g "
        "LEFT JOIN group_members gm ON g.group_id = gm.group_id AND gm.user_id = $1 "
        "WHERE g.owner_id = $1 OR (gm.user_id = $1 AND gm.status = 'approved') "
        "ORDER BY g.created_at DESC",
        1, NULL, paramValues, NULL, NULL, 0);
    
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        PQclear(res);
        return 0;
    }
    
    int count = PQntuples(res);
    if (count == 0) {
        PQclear(res);
        return 0;
    }
    
    *groups = (GroupInfo**)malloc(count * sizeof(GroupInfo*));
    
    for (int i = 0; i < count; i++) {
        (*groups)[i] = (GroupInfo*)malloc(sizeof(GroupInfo));
        (*groups)[i]->group_id = atoi(PQgetvalue(res, i, 0));
        strncpy((*groups)[i]->group_name, PQgetvalue(res, i, 1), 100);
        (*groups)[i]->group_name[100] = '\0';
        strncpy((*groups)[i]->description, PQgetvalue(res, i, 2), 255);
        (*groups)[i]->description[255] = '\0';
        strncpy((*groups)[i]->role, PQgetvalue(res, i, 3), 20);
        (*groups)[i]->role[20] = '\0';
        (*groups)[i]->member_count = atoi(PQgetvalue(res, i, 4));
        strncpy((*groups)[i]->created_at, PQgetvalue(res, i, 5), 63);
        (*groups)[i]->created_at[63] = '\0';
    }
    
    PQclear(res);
    return count;
}

int db_is_group_member(int user_id, int group_id) {
    if (!conn) return 0;
    
    char user_id_str[32], group_id_str[32];
    sprintf(user_id_str, "%d", user_id);
    sprintf(group_id_str, "%d", group_id);
    
    const char *paramValues[2] = {user_id_str, group_id_str};
    
    // Check if user is owner
    PGresult *res = PQexecParams(conn,
        "SELECT group_id FROM groups WHERE group_id = $2 AND owner_id = $1",
        2, NULL, paramValues, NULL, NULL, 0);
    
    int is_owner = (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0);
    PQclear(res);
    
    if (is_owner) return 1;
    
    // Check if user is approved member
    res = PQexecParams(conn,
        "SELECT member_id FROM group_members WHERE user_id = $1 AND group_id = $2 AND status = 'approved'",
        2, NULL, paramValues, NULL, NULL, 0);
    
    int is_member = (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0);
    PQclear(res);
    
    return is_member;
}

int db_get_group_members(int group_id, MemberInfo ***members) {
    if (!conn) return 0;
    
    char group_id_str[32];
    sprintf(group_id_str, "%d", group_id);
    
    const char *paramValues[1] = {group_id_str};
    
    PGresult *res = PQexecParams(conn,
        "SELECT u.user_id, u.username, u.full_name, gm.role, gm.status, gm.joined_at "
        "FROM group_members gm "
        "JOIN users u ON gm.user_id = u.user_id "
        "WHERE gm.group_id = $1 "
        "ORDER BY gm.joined_at ASC",
        1, NULL, paramValues, NULL, NULL, 0);
    
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        PQclear(res);
        return 0;
    }
    
    int count = PQntuples(res);
    if (count == 0) {
        PQclear(res);
        return 0;
    }
    
    *members = (MemberInfo**)malloc(count * sizeof(MemberInfo*));
    
    for (int i = 0; i < count; i++) {
        (*members)[i] = (MemberInfo*)malloc(sizeof(MemberInfo));
        (*members)[i]->user_id = atoi(PQgetvalue(res, i, 0));
        strncpy((*members)[i]->username, PQgetvalue(res, i, 1), 50);
        (*members)[i]->username[50] = '\0';
        strncpy((*members)[i]->full_name, PQgetvalue(res, i, 2), 100);
        (*members)[i]->full_name[100] = '\0';
        strncpy((*members)[i]->role, PQgetvalue(res, i, 3), 20);
        (*members)[i]->role[20] = '\0';
        strncpy((*members)[i]->status, PQgetvalue(res, i, 4), 20);
        (*members)[i]->status[20] = '\0';
        strncpy((*members)[i]->joined_at, PQgetvalue(res, i, 5), 63);
        (*members)[i]->joined_at[63] = '\0';
    }
    
    PQclear(res);
    return count;
}

int db_request_join_group(int user_id, int group_id) {
    if (!conn) return -1;
    
    char user_id_str[32], group_id_str[32];
    sprintf(user_id_str, "%d", user_id);
    sprintf(group_id_str, "%d", group_id);
    
    const char *paramValues[2] = {group_id_str, user_id_str};
    
    // Check if already a member
    PGresult *res = PQexecParams(conn,
        "SELECT member_id FROM group_members WHERE group_id = $1 AND user_id = $2",
        2, NULL, paramValues, NULL, NULL, 0);
    
    if (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0) {
        PQclear(res);
        return -2; // Already a member or request exists
    }
    PQclear(res);
    
    // Check if request already exists
    res = PQexecParams(conn,
        "SELECT request_id FROM join_requests WHERE group_id = $1 AND user_id = $2 AND status = 'pending'",
        2, NULL, paramValues, NULL, NULL, 0);
    
    if (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0) {
        PQclear(res);
        return -3; // Request already pending
    }
    PQclear(res);
    
    // Create join request
    res = PQexecParams(conn,
        "INSERT INTO join_requests (group_id, user_id, status) VALUES ($1, $2, 'pending') RETURNING request_id",
        2, NULL, paramValues, NULL, NULL, 0);
    
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "INSERT join_request failed: %s", PQerrorMessage(conn));
        PQclear(res);
        return -1;
    }
    
    int request_id = atoi(PQgetvalue(res, 0, 0));
    PQclear(res);
    
    return request_id;
}

int db_get_join_requests(int group_id, JoinRequestInfo ***requests) {
    if (!conn) return 0;
    
    char group_id_str[32];
    sprintf(group_id_str, "%d", group_id);
    
    const char *paramValues[1] = {group_id_str};
    
    PGresult *res = PQexecParams(conn,
        "SELECT jr.request_id, jr.group_id, jr.user_id, u.username, u.full_name, jr.status, jr.created_at "
        "FROM join_requests jr "
        "JOIN users u ON jr.user_id = u.user_id "
        "WHERE jr.group_id = $1 AND jr.status = 'pending' "
        "ORDER BY jr.created_at DESC",
        1, NULL, paramValues, NULL, NULL, 0);
    
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        PQclear(res);
        return 0;
    }
    
    int count = PQntuples(res);
    if (count == 0) {
        PQclear(res);
        return 0;
    }
    
    *requests = (JoinRequestInfo**)malloc(count * sizeof(JoinRequestInfo*));
    
    for (int i = 0; i < count; i++) {
        (*requests)[i] = (JoinRequestInfo*)malloc(sizeof(JoinRequestInfo));
        (*requests)[i]->request_id = atoi(PQgetvalue(res, i, 0));
        (*requests)[i]->group_id = atoi(PQgetvalue(res, i, 1));
        (*requests)[i]->user_id = atoi(PQgetvalue(res, i, 2));
        strncpy((*requests)[i]->username, PQgetvalue(res, i, 3), 50);
        (*requests)[i]->username[50] = '\0';
        strncpy((*requests)[i]->full_name, PQgetvalue(res, i, 4), 100);
        (*requests)[i]->full_name[100] = '\0';
        strncpy((*requests)[i]->status, PQgetvalue(res, i, 5), 20);
        (*requests)[i]->status[20] = '\0';
        strncpy((*requests)[i]->created_at, PQgetvalue(res, i, 6), 63);
        (*requests)[i]->created_at[63] = '\0';
    }
    
    PQclear(res);
    return count;
}

JoinRequestInfo* db_get_join_request_by_id(int request_id) {
    if (!conn) return NULL;
    
    char request_id_str[32];
    sprintf(request_id_str, "%d", request_id);
    
    const char *paramValues[1] = {request_id_str};
    
    PGresult *res = PQexecParams(conn,
        "SELECT jr.request_id, jr.group_id, jr.user_id, u.username, u.full_name, jr.status, jr.created_at "
        "FROM join_requests jr "
        "JOIN users u ON jr.user_id = u.user_id "
        "WHERE jr.request_id = $1",
        1, NULL, paramValues, NULL, NULL, 0);
    
    if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        PQclear(res);
        return NULL;
    }
    
    JoinRequestInfo *info = (JoinRequestInfo*)malloc(sizeof(JoinRequestInfo));
    info->request_id = atoi(PQgetvalue(res, 0, 0));
    info->group_id = atoi(PQgetvalue(res, 0, 1));
    info->user_id = atoi(PQgetvalue(res, 0, 2));
    strncpy(info->username, PQgetvalue(res, 0, 3), 50);
    info->username[50] = '\0';
    strncpy(info->full_name, PQgetvalue(res, 0, 4), 100);
    info->full_name[100] = '\0';
    strncpy(info->status, PQgetvalue(res, 0, 5), 20);
    info->status[20] = '\0';
    strncpy(info->created_at, PQgetvalue(res, 0, 6), 63);
    info->created_at[63] = '\0';
    
    PQclear(res);
    return info;
}

int db_approve_join_request(int request_id, int reviewer_id, const char *action) {
    if (!conn) return -1;
    
    char request_id_str[32], reviewer_id_str[32];
    sprintf(request_id_str, "%d", request_id);
    sprintf(reviewer_id_str, "%d", reviewer_id);
    
    // Get request info
    JoinRequestInfo *info = db_get_join_request_by_id(request_id);
    if (!info) return -1;
    
    int group_id = info->group_id;
    int user_id = info->user_id;
    
    // Update request status
    const char *status = (strcmp(action, "approve") == 0) ? "approved" : "rejected";
    const char *paramValues[3] = {status, reviewer_id_str, request_id_str};
    
    PGresult *res = PQexecParams(conn,
        "UPDATE join_requests SET status = $1, reviewed_at = CURRENT_TIMESTAMP, reviewed_by = $2 WHERE request_id = $3",
        3, NULL, paramValues, NULL, NULL, 0);
    
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "UPDATE join_request failed: %s", PQerrorMessage(conn));
        PQclear(res);
        free(info);
        return -1;
    }
    PQclear(res);
    
    // If approved, add to group_members
    if (strcmp(action, "approve") == 0) {
        char group_id_str[32], user_id_str[32];
        sprintf(group_id_str, "%d", group_id);
        sprintf(user_id_str, "%d", user_id);
        
        const char *memberParams[2] = {group_id_str, user_id_str};
        
        res = PQexecParams(conn,
            "INSERT INTO group_members (group_id, user_id, role, status) VALUES ($1, $2, 'member', 'approved')",
            2, NULL, memberParams, NULL, NULL, 0);
        PQclear(res);
        
        // Create default permissions
        res = PQexecParams(conn,
            "INSERT INTO permissions (group_id, user_id, can_read, can_write, can_delete, can_manage) "
            "VALUES ($1, $2, TRUE, FALSE, FALSE, FALSE)",
            2, NULL, memberParams, NULL, NULL, 0);
        PQclear(res);
    }
    
    free(info);
    return 0;
}

UserInfo* db_get_user_by_username(const char *username) {
    if (!conn) return NULL;
    
    const char *paramValues[1] = {username};
    
    PGresult *res = PQexecParams(conn,
        "SELECT user_id, username, role, email, full_name FROM users WHERE username = $1",
        1, NULL, paramValues, NULL, NULL, 0);
    
    if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        PQclear(res);
        return NULL;
    }
    
    UserInfo *user = (UserInfo*)malloc(sizeof(UserInfo));
    user->user_id = atoi(PQgetvalue(res, 0, 0));
    strncpy(user->username, PQgetvalue(res, 0, 1), 50);
    user->username[50] = '\0';
    strncpy(user->role, PQgetvalue(res, 0, 2), 20);
    user->role[20] = '\0';
    strncpy(user->email, PQgetvalue(res, 0, 3), 100);
    user->email[100] = '\0';
    strncpy(user->full_name, PQgetvalue(res, 0, 4), 100);
    user->full_name[100] = '\0';
    
    PQclear(res);
    return user;
}

int db_invite_to_group(int inviter_id, int group_id, const char *invitee_username) {
    if (!conn) return -1;
    
    // Get invitee user_id
    UserInfo *invitee = db_get_user_by_username(invitee_username);
    if (!invitee) return -2; // User not found
    
    int invitee_id = invitee->user_id;
    free(invitee);
    
    char inviter_id_str[32], group_id_str[32], invitee_id_str[32];
    sprintf(inviter_id_str, "%d", inviter_id);
    sprintf(group_id_str, "%d", group_id);
    sprintf(invitee_id_str, "%d", invitee_id);
    
    // Check if already a member
    const char *checkParams[2] = {group_id_str, invitee_id_str};
    PGresult *res = PQexecParams(conn,
        "SELECT member_id FROM group_members WHERE group_id = $1 AND user_id = $2",
        2, NULL, checkParams, NULL, NULL, 0);
    
    if (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0) {
        PQclear(res);
        return -3; // Already a member
    }
    PQclear(res);
    
    // Check if invitation already exists
    res = PQexecParams(conn,
        "SELECT invitation_id FROM group_invitations WHERE group_id = $1 AND invitee_id = $2 AND status = 'pending'",
        2, NULL, checkParams, NULL, NULL, 0);
    
    if (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0) {
        PQclear(res);
        return -4; // Invitation already pending
    }
    PQclear(res);
    
    // Create invitation
    const char *paramValues[3] = {group_id_str, inviter_id_str, invitee_id_str};
    res = PQexecParams(conn,
        "INSERT INTO group_invitations (group_id, inviter_id, invitee_id, status) VALUES ($1, $2, $3, 'pending') RETURNING invitation_id",
        3, NULL, paramValues, NULL, NULL, 0);
    
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "INSERT invitation failed: %s", PQerrorMessage(conn));
        PQclear(res);
        return -1;
    }
    
    int invitation_id = atoi(PQgetvalue(res, 0, 0));
    PQclear(res);
    
    return invitation_id;
}

int db_get_user_invitations(int user_id, InvitationInfo ***invitations) {
    if (!conn) return 0;
    
    char user_id_str[32];
    sprintf(user_id_str, "%d", user_id);
    
    const char *paramValues[1] = {user_id_str};
    
    PGresult *res = PQexecParams(conn,
        "SELECT gi.invitation_id, gi.group_id, g.group_name, gi.inviter_id, "
        "u.username, u.full_name, gi.invitee_id, gi.status, gi.created_at "
        "FROM group_invitations gi "
        "JOIN groups g ON gi.group_id = g.group_id "
        "JOIN users u ON gi.inviter_id = u.user_id "
        "WHERE gi.invitee_id = $1 AND gi.status = 'pending' "
        "ORDER BY gi.created_at DESC",
        1, NULL, paramValues, NULL, NULL, 0);
    
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        PQclear(res);
        return 0;
    }
    
    int count = PQntuples(res);
    if (count == 0) {
        PQclear(res);
        return 0;
    }
    
    *invitations = (InvitationInfo**)malloc(count * sizeof(InvitationInfo*));
    
    for (int i = 0; i < count; i++) {
        (*invitations)[i] = (InvitationInfo*)malloc(sizeof(InvitationInfo));
        (*invitations)[i]->invitation_id = atoi(PQgetvalue(res, i, 0));
        (*invitations)[i]->group_id = atoi(PQgetvalue(res, i, 1));
        strncpy((*invitations)[i]->group_name, PQgetvalue(res, i, 2), 100);
        (*invitations)[i]->group_name[100] = '\0';
        (*invitations)[i]->inviter_id = atoi(PQgetvalue(res, i, 3));
        strncpy((*invitations)[i]->inviter_username, PQgetvalue(res, i, 4), 50);
        (*invitations)[i]->inviter_username[50] = '\0';
        strncpy((*invitations)[i]->inviter_name, PQgetvalue(res, i, 5), 100);
        (*invitations)[i]->inviter_name[100] = '\0';
        (*invitations)[i]->invitee_id = atoi(PQgetvalue(res, i, 6));
        strncpy((*invitations)[i]->status, PQgetvalue(res, i, 7), 20);
        (*invitations)[i]->status[20] = '\0';
        strncpy((*invitations)[i]->created_at, PQgetvalue(res, i, 8), 63);
        (*invitations)[i]->created_at[63] = '\0';
    }
    
    PQclear(res);
    return count;
}

InvitationInfo* db_get_invitation_by_id(int invitation_id) {
    if (!conn) return NULL;
    
    char invitation_id_str[32];
    sprintf(invitation_id_str, "%d", invitation_id);
    
    const char *paramValues[1] = {invitation_id_str};
    
    PGresult *res = PQexecParams(conn,
        "SELECT gi.invitation_id, gi.group_id, g.group_name, gi.inviter_id, "
        "u.username, u.full_name, gi.invitee_id, gi.status, gi.created_at "
        "FROM group_invitations gi "
        "JOIN groups g ON gi.group_id = g.group_id "
        "JOIN users u ON gi.inviter_id = u.user_id "
        "WHERE gi.invitation_id = $1",
        1, NULL, paramValues, NULL, NULL, 0);
    
    if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        PQclear(res);
        return NULL;
    }
    
    InvitationInfo *info = (InvitationInfo*)malloc(sizeof(InvitationInfo));
    info->invitation_id = atoi(PQgetvalue(res, 0, 0));
    info->group_id = atoi(PQgetvalue(res, 0, 1));
    strncpy(info->group_name, PQgetvalue(res, 0, 2), 100);
    info->group_name[100] = '\0';
    info->inviter_id = atoi(PQgetvalue(res, 0, 3));
    strncpy(info->inviter_username, PQgetvalue(res, 0, 4), 50);
    info->inviter_username[50] = '\0';
    strncpy(info->inviter_name, PQgetvalue(res, 0, 5), 100);
    info->inviter_name[100] = '\0';
    info->invitee_id = atoi(PQgetvalue(res, 0, 6));
    strncpy(info->status, PQgetvalue(res, 0, 7), 20);
    info->status[20] = '\0';
    strncpy(info->created_at, PQgetvalue(res, 0, 8), 63);
    info->created_at[63] = '\0';
    
    PQclear(res);
    return info;
}

int db_respond_invitation(int invitation_id, const char *action) {
    if (!conn) return -1;
    
    // Get invitation info
    InvitationInfo *info = db_get_invitation_by_id(invitation_id);
    if (!info) return -1;
    
    int group_id = info->group_id;
    int user_id = info->invitee_id;
    
    // Update invitation status
    char invitation_id_str[32];
    sprintf(invitation_id_str, "%d", invitation_id);
    const char *status = (strcmp(action, "accept") == 0) ? "accepted" : "rejected";
    const char *paramValues[2] = {status, invitation_id_str};
    
    PGresult *res = PQexecParams(conn,
        "UPDATE group_invitations SET status = $1 WHERE invitation_id = $2",
        2, NULL, paramValues, NULL, NULL, 0);
    
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "UPDATE invitation failed: %s", PQerrorMessage(conn));
        PQclear(res);
        free(info);
        return -1;
    }
    PQclear(res);
    
    // If accepted, add to group_members
    if (strcmp(action, "accept") == 0) {
        char group_id_str[32], user_id_str[32];
        sprintf(group_id_str, "%d", group_id);
        sprintf(user_id_str, "%d", user_id);
        
        const char *memberParams[2] = {group_id_str, user_id_str};
        
        res = PQexecParams(conn,
            "INSERT INTO group_members (group_id, user_id, role, status) VALUES ($1, $2, 'member', 'approved')",
            2, NULL, memberParams, NULL, NULL, 0);
        PQclear(res);
        
        // Create default permissions
        res = PQexecParams(conn,
            "INSERT INTO permissions (group_id, user_id, can_read, can_write, can_delete, can_manage) "
            "VALUES ($1, $2, TRUE, FALSE, FALSE, FALSE)",
            2, NULL, memberParams, NULL, NULL, 0);
        PQclear(res);
    }
    
    free(info);
    return 0;
}

int db_leave_group(int user_id, int group_id) {
    if (!conn) return -1;
    
    char user_id_str[32], group_id_str[32];
    sprintf(user_id_str, "%d", user_id);
    sprintf(group_id_str, "%d", group_id);
    
    const char *paramValues[2] = {group_id_str, user_id_str};
    
    // Delete from group_members
    PGresult *res = PQexecParams(conn,
        "DELETE FROM group_members WHERE group_id = $1 AND user_id = $2",
        2, NULL, paramValues, NULL, NULL, 0);
    
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "DELETE member failed: %s", PQerrorMessage(conn));
        PQclear(res);
        return -1;
    }
    PQclear(res);
    
    // Delete permissions
    res = PQexecParams(conn,
        "DELETE FROM permissions WHERE group_id = $1 AND user_id = $2",
        2, NULL, paramValues, NULL, NULL, 0);
    PQclear(res);
    
    return 0;
}

int db_remove_member(int group_id, int target_user_id) {
    if (!conn) return -1;
    
    char group_id_str[32], target_user_id_str[32];
    sprintf(group_id_str, "%d", group_id);
    sprintf(target_user_id_str, "%d", target_user_id);
    
    const char *paramValues[2] = {group_id_str, target_user_id_str};
    
    // Delete from group_members
    PGresult *res = PQexecParams(conn,
        "DELETE FROM group_members WHERE group_id = $1 AND user_id = $2",
        2, NULL, paramValues, NULL, NULL, 0);
    
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "DELETE member failed: %s", PQerrorMessage(conn));
        PQclear(res);
        return -1;
    }
    PQclear(res);
    
    // Delete permissions
    res = PQexecParams(conn,
        "DELETE FROM permissions WHERE group_id = $1 AND user_id = $2",
        2, NULL, paramValues, NULL, NULL, 0);
    PQclear(res);
    
    return 0;
}

// Directory operations
int db_create_directory(int group_id, const char *directory_name, const char *parent_path, int created_by_user_id) {
    if (!conn || !directory_name || !parent_path) return -1;
    
    char group_id_str[32], user_id_str[32];
    sprintf(group_id_str, "%d", group_id);
    sprintf(user_id_str, "%d", created_by_user_id);
    
    // Build full directory path
    char directory_path[512];
    if (parent_path[strlen(parent_path) - 1] == '/') {
        sprintf(directory_path, "%s%s", parent_path, directory_name);
    } else {
        sprintf(directory_path, "%s/%s", parent_path, directory_name);
    }
    
    const char *paramValues[5] = {directory_name, directory_path, parent_path, group_id_str, user_id_str};
    
    PGresult *res = PQexecParams(conn,
        "INSERT INTO directories (directory_name, directory_path, parent_path, group_id, created_by) "
        "VALUES ($1, $2, $3, $4, $5) RETURNING directory_id",
        5, NULL, paramValues, NULL, NULL, 0);
    
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "INSERT directory failed: %s", PQerrorMessage(conn));
        PQclear(res);
        return -1;
    }
    
    int directory_id = atoi(PQgetvalue(res, 0, 0));
    PQclear(res);
    
    return directory_id;
}

DirectoryInfo* db_get_directory_by_id(int directory_id) {
    if (!conn) return NULL;
    
    char directory_id_str[32];
    sprintf(directory_id_str, "%d", directory_id);
    
    const char *paramValues[1] = {directory_id_str};
    
    PGresult *res = PQexecParams(conn,
        "SELECT d.directory_id, d.directory_name, d.directory_path, d.group_id, u.username, "
        "TO_CHAR(d.created_at, 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') "
        "FROM directories d "
        "LEFT JOIN users u ON d.created_by = u.user_id "
        "WHERE d.directory_id = $1",
        1, NULL, paramValues, NULL, NULL, 0);
    
    if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        PQclear(res);
        return NULL;
    }
    
    DirectoryInfo *dir = (DirectoryInfo*)malloc(sizeof(DirectoryInfo));
    dir->directory_id = atoi(PQgetvalue(res, 0, 0));
    strncpy(dir->directory_name, PQgetvalue(res, 0, 1), 255);
    strncpy(dir->directory_path, PQgetvalue(res, 0, 2), 511);
    dir->group_id = atoi(PQgetvalue(res, 0, 3));
    strncpy(dir->created_by, PQgetvalue(res, 0, 4), 50);
    strncpy(dir->created_at, PQgetvalue(res, 0, 5), 63);
    
    PQclear(res);
    return dir;
}

int db_rename_directory(int directory_id, const char *new_name) {
    if (!conn || !new_name) return -1;
    
    DirectoryInfo *old_dir = db_get_directory_by_id(directory_id);
    if (!old_dir) return -1;
    
    char parent_path[512];
    strcpy(parent_path, old_dir->directory_path);
    char *last_slash = strrchr(parent_path, '/');
    if (last_slash) *last_slash = '\0';
    else parent_path[0] = '\0';
    
    char new_path[512];
    if (strlen(parent_path) > 0) sprintf(new_path, "%s/%s", parent_path, new_name);
    else strcpy(new_path, new_name);
    
    char directory_id_str[32];
    sprintf(directory_id_str, "%d", directory_id);
    const char *paramValues[3] = {new_name, new_path, directory_id_str};
    
    PGresult *res = PQexecParams(conn,
        "UPDATE directories SET directory_name = $1, directory_path = $2 WHERE directory_id = $3",
        3, NULL, paramValues, NULL, NULL, 0);
    int success = (PQresultStatus(res) == PGRES_COMMAND_OK);
    PQclear(res);
    
    if (success) {
        char old_path_pattern[520];
        sprintf(old_path_pattern, "%s/%%", old_dir->directory_path);
        res = PQexecParams(conn,
            "UPDATE directories SET directory_path = $1 || SUBSTRING(directory_path FROM $2) "
            "WHERE directory_path LIKE $3",
            3, NULL, (const char*[]){new_path, "LENGTH($2) + 1", old_path_pattern}, NULL, NULL, 0);
        PQclear(res);
        
        res = PQexecParams(conn,
            "UPDATE files SET file_path = $1 || SUBSTRING(file_path FROM $2) WHERE file_path LIKE $3",
            3, NULL, (const char*[]){new_path, "LENGTH($2) + 1", old_path_pattern}, NULL, NULL, 0);
        PQclear(res);
    }
    
    free(old_dir);
    return success ? 0 : -1;
}

int db_delete_directory(int directory_id, int *deleted_files, int *deleted_subdirs) {
    if (!conn) return -1;
    
    DirectoryInfo *dir = db_get_directory_by_id(directory_id);
    if (!dir) return -1;
    
    char directory_id_str[32];
    sprintf(directory_id_str, "%d", directory_id);
    
    char path_pattern[520];
    sprintf(path_pattern, "%s/%%", dir->directory_path);
    
    PGresult *res = PQexecParams(conn,
        "SELECT COUNT(*) FROM files WHERE file_path LIKE $1 OR file_path = $2",
        2, NULL, (const char*[]){path_pattern, dir->directory_path}, NULL, NULL, 0);
    if (deleted_files) *deleted_files = (PQresultStatus(res) == PGRES_TUPLES_OK) ? atoi(PQgetvalue(res, 0, 0)) : 0;
    PQclear(res);
    
    res = PQexecParams(conn,
        "DELETE FROM files WHERE file_path LIKE $1 OR file_path = $2",
        2, NULL, (const char*[]){path_pattern, dir->directory_path}, NULL, NULL, 0);
    PQclear(res);
    
    res = PQexecParams(conn,
        "SELECT COUNT(*) FROM directories WHERE directory_path LIKE $1",
        1, NULL, (const char*[]){path_pattern}, NULL, NULL, 0);
    if (deleted_subdirs) *deleted_subdirs = (PQresultStatus(res) == PGRES_TUPLES_OK) ? atoi(PQgetvalue(res, 0, 0)) : 0;
    PQclear(res);
    
    res = PQexecParams(conn,
        "DELETE FROM directories WHERE directory_path LIKE $1 OR directory_id = $2",
        2, NULL, (const char*[]){path_pattern, directory_id_str}, NULL, NULL, 0);
    int success = (PQresultStatus(res) == PGRES_COMMAND_OK);
    PQclear(res);
    
    free(dir);
    return success ? 0 : -1;
}

int db_copy_directory(int directory_id, const char *destination_path, int user_id) {
    if (!conn || !destination_path) return -1;
    
    DirectoryInfo *source = db_get_directory_by_id(directory_id);
    if (!source) return -1;
    
    int new_dir_id = db_create_directory(source->group_id, source->directory_name, destination_path, user_id);
    free(source);
    return new_dir_id;
}

int db_move_directory(int directory_id, const char *destination_path, int *affected_files, int *affected_subdirs) {
    if (!conn || !destination_path) return -1;
    
    DirectoryInfo *dir = db_get_directory_by_id(directory_id);
    if (!dir) return -1;
    
    char old_path[512];
    strncpy(old_path, dir->directory_path, 511);
    old_path[511] = '\0';
    
    char new_path[512];
    if (destination_path[strlen(destination_path) - 1] == '/') {
        sprintf(new_path, "%s%s", destination_path, dir->directory_name);
    } else {
        sprintf(new_path, "%s/%s", destination_path, dir->directory_name);
    }
    
    char directory_id_str[32];
    sprintf(directory_id_str, "%d", directory_id);
    char old_path_pattern[520];
    sprintf(old_path_pattern, "%s/%%", dir->directory_path);
    
    // Update the main directory's path and parent_path
    PGresult *res = PQexecParams(conn,
        "UPDATE directories SET directory_path = $1, parent_path = $2 WHERE directory_id = $3",
        3, NULL, (const char*[]){new_path, destination_path, directory_id_str}, NULL, NULL, 0);
    
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "UPDATE directory failed: %s", PQerrorMessage(conn));
        PQclear(res);
        free(dir);
        return -1;
    }
    PQclear(res);
    
    // Update all subdirectories' paths and parent_paths
    res = PQexecParams(conn,
        "UPDATE directories SET "
        "directory_path = $1 || SUBSTRING(directory_path FROM LENGTH($2) + 1), "
        "parent_path = $1 || SUBSTRING(parent_path FROM LENGTH($2) + 1) "
        "WHERE directory_path LIKE $3",
        3, NULL, (const char*[]){new_path, old_path, old_path_pattern}, NULL, NULL, 0);
    PQclear(res);
    
    // Count affected subdirectories
    res = PQexecParams(conn,
        "SELECT COUNT(*) FROM directories WHERE directory_path LIKE $1",
        1, NULL, (const char*[]){old_path_pattern}, NULL, NULL, 0);
    if (affected_subdirs) *affected_subdirs = (PQresultStatus(res) == PGRES_TUPLES_OK) ? atoi(PQgetvalue(res, 0, 0)) : 0;
    PQclear(res);
    
    // Update all files' paths and parent_directory
    res = PQexecParams(conn,
        "UPDATE files SET "
        "file_path = $1 || SUBSTRING(file_path FROM LENGTH($2) + 1), "
        "parent_directory = $1 || SUBSTRING(parent_directory FROM LENGTH($2) + 1) "
        "WHERE file_path LIKE $3 OR file_path = $2",
        3, NULL, (const char*[]){new_path, old_path, old_path_pattern}, NULL, NULL, 0);
    PQclear(res);
    
    // Count affected files
    res = PQexecParams(conn,
        "SELECT COUNT(*) FROM files WHERE file_path LIKE $1 OR file_path = $2",
        2, NULL, (const char*[]){old_path_pattern, old_path}, NULL, NULL, 0);
    if (affected_files) *affected_files = (PQresultStatus(res) == PGRES_TUPLES_OK) ? atoi(PQgetvalue(res, 0, 0)) : 0;
    PQclear(res);
    
    free(dir);
    return 0;
}

// File operations
int db_create_file(int group_id, const char *file_name, const char *file_path, 
                   long long file_size, const char *file_type, 
                   const char *parent_directory, int uploaded_by) {
    if (!conn || !file_name || !file_path) return -1;
    
    char group_id_str[32], file_size_str[32], uploaded_by_str[32];
    sprintf(group_id_str, "%d", group_id);
    sprintf(file_size_str, "%lld", file_size);
    sprintf(uploaded_by_str, "%d", uploaded_by);
    
    const char *paramValues[7] = {
        group_id_str, file_name, file_path, file_size_str, 
        file_type, parent_directory, uploaded_by_str
    };
    
    PGresult *res = PQexecParams(conn,
        "INSERT INTO files (group_id, file_name, file_path, file_size, file_type, parent_directory, uploaded_by) "
        "VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING file_id",
        7, NULL, paramValues, NULL, NULL, 0);
    
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "INSERT file failed: %s", PQerrorMessage(conn));
        PQclear(res);
        return -1;
    }
    
    int file_id = atoi(PQgetvalue(res, 0, 0));
    PQclear(res);
    return file_id;
}

FileInfo* db_get_file_by_id(int file_id) {
    if (!conn) return NULL;
    
    char file_id_str[32];
    sprintf(file_id_str, "%d", file_id);
    
    PGresult *res = PQexecParams(conn,
        "SELECT file_id, group_id, file_name, file_path, file_size, file_type, uploaded_by, "
        "TO_CHAR(uploaded_at, 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), parent_directory "
        "FROM files WHERE file_id = $1",
        1, NULL, (const char*[]){file_id_str}, NULL, NULL, 0);
    
    if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        PQclear(res);
        return NULL;
    }
    
    FileInfo *file = (FileInfo*)malloc(sizeof(FileInfo));
    file->file_id = atoi(PQgetvalue(res, 0, 0));
    file->group_id = atoi(PQgetvalue(res, 0, 1));
    strncpy(file->file_name, PQgetvalue(res, 0, 2), 255);
    strncpy(file->file_path, PQgetvalue(res, 0, 3), 511);
    file->file_size = atoll(PQgetvalue(res, 0, 4));
    strncpy(file->file_type, PQgetvalue(res, 0, 5), 50);
    file->uploaded_by = atoi(PQgetvalue(res, 0, 6));
    strncpy(file->uploaded_at, PQgetvalue(res, 0, 7), 63);
    strncpy(file->parent_directory, PQgetvalue(res, 0, 8), 511);
    
    PQclear(res);
    return file;
}

int db_delete_file(int file_id) {
    if (!conn) return -1;
    
    char file_id_str[32];
    sprintf(file_id_str, "%d", file_id);
    
    PGresult *res = PQexecParams(conn,
        "DELETE FROM files WHERE file_id = $1",
        1, NULL, (const char*[]){file_id_str}, NULL, NULL, 0);
    
    int success = (PQresultStatus(res) == PGRES_COMMAND_OK);
    PQclear(res);
    return success ? 0 : -1;
}

int db_rename_file(int file_id, const char *new_name) {
    if (!conn || !new_name) return -1;
    
    FileInfo *file = db_get_file_by_id(file_id);
    if (!file) return -1;
    
    char new_path[512];
    strcpy(new_path, file->file_path);
    char *last_slash = strrchr(new_path, '/');
    if (last_slash) {
        *(last_slash + 1) = '\0';
        strcat(new_path, new_name);
    } else {
        strcpy(new_path, new_name);
    }
    
    char file_id_str[32];
    sprintf(file_id_str, "%d", file_id);
    
    PGresult *res = PQexecParams(conn,
        "UPDATE files SET file_name = $1, file_path = $2 WHERE file_id = $3",
        3, NULL, (const char*[]){new_name, new_path, file_id_str}, NULL, NULL, 0);
    
    int success = (PQresultStatus(res) == PGRES_COMMAND_OK);
    PQclear(res);
    free(file);
    return success ? 0 : -1;
}

int db_move_file(int file_id, const char *new_path) {
    if (!conn || !new_path) return -1;
    
    char file_id_str[32];
    sprintf(file_id_str, "%d", file_id);

    /* Derive new parent_directory from new_path */
    char parent_dir[512];
    strncpy(parent_dir, new_path, sizeof(parent_dir) - 1);
    parent_dir[sizeof(parent_dir) - 1] = '\0';
    char *last_slash = strrchr(parent_dir, '/');
    if (last_slash) {
        if (last_slash == parent_dir) {
            /* Root folder */
            *(last_slash + 1) = '\0';
        } else {
            *last_slash = '\0';
        }
    } else {
        /* No slash means root */
        strcpy(parent_dir, "/");
    }
    if (strlen(parent_dir) == 0) strcpy(parent_dir, "/");
    
    PGresult *res = PQexecParams(conn,
        "UPDATE files SET file_path = $1, parent_directory = $2 WHERE file_id = $3",
        3, NULL, (const char*[]){new_path, parent_dir, file_id_str}, NULL, NULL, 0);
    
    int success = (PQresultStatus(res) == PGRES_COMMAND_OK);
    PQclear(res);
    return success ? 0 : -1;
}

int db_copy_file(int file_id, const char *destination_path, int user_id) {
    if (!conn || !destination_path) return -1;
    
    FileInfo *source = db_get_file_by_id(file_id);
    if (!source) return -1;
    
    char new_path[512];
    if (destination_path[strlen(destination_path) - 1] == '/') {
        sprintf(new_path, "%s%s", destination_path, source->file_name);
    } else {
        sprintf(new_path, "%s/%s", destination_path, source->file_name);
    }
    
    int new_file_id = db_create_file(source->group_id, source->file_name, new_path,
                                      source->file_size, source->file_type,
                                      destination_path, user_id);
    free(source);
    return new_file_id;
}

char* db_get_group_name_by_id(int group_id) {
    const char *query = "SELECT group_name FROM groups WHERE group_id = $1";
    const char *params[1];
    char group_id_str[32];
    snprintf(group_id_str, sizeof(group_id_str), "%d", group_id);
    params[0] = group_id_str;
    
    PGresult *res = PQexecParams(conn, query, 1, NULL, params, NULL, NULL, 0);
    
    if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        PQclear(res);
        return NULL;
    }
    
    char *group_name = strdup(PQgetvalue(res, 0, 0));
    PQclear(res);
    return group_name;
}

char* db_get_username_by_id(int user_id) {
    const char *query = "SELECT username FROM users WHERE user_id = $1";
    const char *params[1];
    char user_id_str[32];
    snprintf(user_id_str, sizeof(user_id_str), "%d", user_id);
    params[0] = user_id_str;
    
    PGresult *res = PQexecParams(conn, query, 1, NULL, params, NULL, NULL, 0);
    
    if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        PQclear(res);
        return NULL;
    }
    
    char *username = strdup(PQgetvalue(res, 0, 0));
    PQclear(res);
    return username;
}

int db_get_group_admin_ids(int group_id, int **admin_ids) {
    const char *query = 
        "SELECT user_id FROM group_members "
        "WHERE group_id = $1 AND role = 'admin' AND status = 'approved'";
    
    const char *params[1];
    char group_id_str[32];
    snprintf(group_id_str, sizeof(group_id_str), "%d", group_id);
    params[0] = group_id_str;
    
    PGresult *res = PQexecParams(conn, query, 1, NULL, params, NULL, NULL, 0);
    
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        PQclear(res);
        return 0;
    }
    
    int count = PQntuples(res);
    if (count == 0) {
        PQclear(res);
        *admin_ids = NULL;
        return 0;
    }
    
    *admin_ids = malloc(sizeof(int) * count);
    for (int i = 0; i < count; i++) {
        (*admin_ids)[i] = atoi(PQgetvalue(res, i, 0));
    }
    
    PQclear(res);
    return count;
}

int db_create_notification(int user_id, const char *type, const char *title,
                          const char *message, const char *related_type,
                          int related_id) {
    const char *query = 
        "INSERT INTO notifications (user_id, type, title, message, related_type, related_id) "
        "VALUES ($1, $2, $3, $4, $5, $6) RETURNING notification_id";
    
    const char *params[6];
    char user_id_str[32], related_id_str[32];
    snprintf(user_id_str, sizeof(user_id_str), "%d", user_id);
    snprintf(related_id_str, sizeof(related_id_str), "%d", related_id);
    
    params[0] = user_id_str;
    params[1] = type;
    params[2] = title;
    params[3] = message;
    params[4] = related_type;
    params[5] = related_id_str;
    
    PGresult *res = PQexecParams(conn, query, 6, NULL, params, NULL, NULL, 0);
    
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "Create notification failed: %s\n", PQerrorMessage(conn));
        PQclear(res);
        return -1;
    }
    
    int notification_id = atoi(PQgetvalue(res, 0, 0));
    PQclear(res);
    return notification_id;
}

int db_get_user_notifications(int user_id, NotificationInfo ***notifications) {
    const char *query = 
        "SELECT notification_id, user_id, type, title, message, "
        "related_type, related_id, is_read, created_at "
        "FROM notifications "
        "WHERE user_id = $1 "
        "ORDER BY created_at DESC "
        "LIMIT 50";
    
    const char *params[1];
    char user_id_str[32];
    snprintf(user_id_str, sizeof(user_id_str), "%d", user_id);
    params[0] = user_id_str;
    
    PGresult *res = PQexecParams(conn, query, 1, NULL, params, NULL, NULL, 0);
    
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "Get notifications failed: %s\n", PQerrorMessage(conn));
        PQclear(res);
        return 0;
    }
    
    int count = PQntuples(res);
    if (count == 0) {
        PQclear(res);
        *notifications = NULL;
        return 0;
    }
    
    *notifications = malloc(sizeof(NotificationInfo*) * count);
    
    for (int i = 0; i < count; i++) {
        NotificationInfo *notif = malloc(sizeof(NotificationInfo));
        
        notif->notification_id = atoi(PQgetvalue(res, i, 0));
        notif->user_id = atoi(PQgetvalue(res, i, 1));
        strncpy(notif->type, PQgetvalue(res, i, 2), sizeof(notif->type) - 1);
        strncpy(notif->title, PQgetvalue(res, i, 3), sizeof(notif->title) - 1);
        strncpy(notif->message, PQgetvalue(res, i, 4), sizeof(notif->message) - 1);
        strncpy(notif->related_type, PQgetvalue(res, i, 5), sizeof(notif->related_type) - 1);
        notif->related_id = atoi(PQgetvalue(res, i, 6));
        notif->is_read = strcmp(PQgetvalue(res, i, 7), "t") == 0 ? 1 : 0;
        strncpy(notif->created_at, PQgetvalue(res, i, 8), sizeof(notif->created_at) - 1);
        
        (*notifications)[i] = notif;
    }
    
    PQclear(res);
    return count;
}

int db_mark_notification_read(int user_id, int notification_id) {
    const char *query = 
        "UPDATE notifications "
        "SET is_read = TRUE, read_at = CURRENT_TIMESTAMP "
        "WHERE notification_id = $1 AND user_id = $2";
    
    const char *params[2];
    char notification_id_str[32], user_id_str[32];
    snprintf(notification_id_str, sizeof(notification_id_str), "%d", notification_id);
    snprintf(user_id_str, sizeof(user_id_str), "%d", user_id);
    params[0] = notification_id_str;
    params[1] = user_id_str;
    
    PGresult *res = PQexecParams(conn, query, 2, NULL, params, NULL, NULL, 0);
    
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Mark notification read failed: %s\n", PQerrorMessage(conn));
        PQclear(res);
        return -1;
    }
    
    PQclear(res);
    return 0;
}

int db_mark_all_notifications_read(int user_id) {
    const char *query = 
        "UPDATE notifications "
        "SET is_read = TRUE, read_at = CURRENT_TIMESTAMP "
        "WHERE user_id = $1 AND is_read = FALSE";
    
    const char *params[1];
    char user_id_str[32];
    snprintf(user_id_str, sizeof(user_id_str), "%d", user_id);
    params[0] = user_id_str;
    
    PGresult *res = PQexecParams(conn, query, 1, NULL, params, NULL, NULL, 0);
    
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        PQclear(res);
        return -1;
    }
    
    PQclear(res);
    return 0;
}

int db_get_unread_notification_count(int user_id) {
    const char *query = 
        "SELECT COUNT(*) FROM notifications "
        "WHERE user_id = $1 AND is_read = FALSE";
    
    const char *params[1];
    char user_id_str[32];
    snprintf(user_id_str, sizeof(user_id_str), "%d", user_id);
    params[0] = user_id_str;
    
    PGresult *res = PQexecParams(conn, query, 1, NULL, params, NULL, NULL, 0);
    
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        PQclear(res);
        return 0;
    }
    
    int count = atoi(PQgetvalue(res, 0, 0));
    PQclear(res);
    return count;
}

int db_get_available_groups(int user_id, GroupInfo ***groups) {
    const char *query = 
        "SELECT g.group_id, g.group_name, g.description, g.created_at, "
        "       (SELECT COUNT(*) FROM group_members WHERE group_id = g.group_id AND status = 'approved') as member_count "
        "FROM groups g "
        "WHERE g.group_id NOT IN ( "
        "    SELECT group_id FROM group_members "
        "    WHERE user_id = $1 "
        "    AND status IN ('approved', 'pending') "
        ") "
        "AND g.group_id NOT IN ( "
        "    SELECT group_id FROM join_requests "
        "    WHERE user_id = $1 "
        "    AND status = 'pending' "
        ") "
        "AND g.group_id NOT IN ( "
        "    SELECT group_id FROM group_invitations "
        "    WHERE invitee_id = $1 "
        "    AND status = 'pending' "
        ") "
        "ORDER BY g.created_at DESC";
    
    const char *paramValues[1];
    char user_id_str[20];
    snprintf(user_id_str, sizeof(user_id_str), "%d", user_id);
    paramValues[0] = user_id_str;
    
    PGresult *res = PQexecParams(conn, query, 1, NULL, paramValues, NULL, NULL, 0);
    
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "Get available groups failed: %s\n", PQerrorMessage(conn));
        PQclear(res);
        return -1;
    }
    
    int count = PQntuples(res);
    if (count == 0) {
        *groups = NULL;
        PQclear(res);
        return 0;
    }
    
    *groups = malloc(sizeof(GroupInfo*) * count);
    
    for (int i = 0; i < count; i++) {
        (*groups)[i] = malloc(sizeof(GroupInfo));
        (*groups)[i]->group_id = atoi(PQgetvalue(res, i, 0));
        strncpy((*groups)[i]->group_name, PQgetvalue(res, i, 1), sizeof((*groups)[i]->group_name) - 1);
        strncpy((*groups)[i]->description, PQgetvalue(res, i, 2), sizeof((*groups)[i]->description) - 1);
        strncpy((*groups)[i]->created_at, PQgetvalue(res, i, 3), sizeof((*groups)[i]->created_at) - 1);
        (*groups)[i]->member_count = atoi(PQgetvalue(res, i, 4));
        strcpy((*groups)[i]->role, ""); // Not a member
    }
    
    PQclear(res);
    return count;
}

/**
 * List directories in a specific parent path
 * Returns number of directories found
 */
int db_list_directories(int group_id, const char *parent_path, DirectoryInfo ***directories) {
    if (!conn) return -1;
    
    char group_id_str[32];
    sprintf(group_id_str, "%d", group_id);
    
    const char *paramValues[2] = {group_id_str, parent_path};
    
    PGresult *res = PQexecParams(conn,
        "SELECT directory_id, directory_name, directory_path, created_by, "
        "TO_CHAR(created_at, 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') as created_at "
        "FROM directories "
        "WHERE group_id = $1 AND parent_path = $2 "
        "ORDER BY directory_name",
        2, NULL, paramValues, NULL, NULL, 0);
    
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "SELECT directories failed: %s", PQerrorMessage(conn));
        PQclear(res);
        return -1;
    }
    
    int count = PQntuples(res);
    if (count == 0) {
        *directories = NULL;
        PQclear(res);
        return 0;
    }
    
    *directories = malloc(sizeof(DirectoryInfo*) * count);
    
    for (int i = 0; i < count; i++) {
        (*directories)[i] = malloc(sizeof(DirectoryInfo));
        (*directories)[i]->directory_id = atoi(PQgetvalue(res, i, 0));
        strncpy((*directories)[i]->directory_name, PQgetvalue(res, i, 1), sizeof((*directories)[i]->directory_name) - 1);
        strncpy((*directories)[i]->directory_path, PQgetvalue(res, i, 2), sizeof((*directories)[i]->directory_path) - 1);
        (*directories)[i]->group_id = group_id;
        strncpy((*directories)[i]->created_by, PQgetvalue(res, i, 3), sizeof((*directories)[i]->created_by) - 1);
        strncpy((*directories)[i]->created_at, PQgetvalue(res, i, 4), sizeof((*directories)[i]->created_at) - 1);
    }
    
    PQclear(res);
    return count;
}

/**
 * List files in a specific parent directory
 * Returns number of files found
 */
int db_list_files(int group_id, const char *parent_directory, FileInfo ***files) {
    if (!conn) return -1;
    
    char group_id_str[32];
    sprintf(group_id_str, "%d", group_id);
    
    const char *paramValues[2] = {group_id_str, parent_directory};
    
    PGresult *res = PQexecParams(conn,
        "SELECT file_id, file_name, file_path, file_size, file_type, uploaded_by, "
        "TO_CHAR(uploaded_at, 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') as uploaded_at, parent_directory "
        "FROM files "
        "WHERE group_id = $1 AND parent_directory = $2 "
        "ORDER BY file_name",
        2, NULL, paramValues, NULL, NULL, 0);
    
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "SELECT files failed: %s", PQerrorMessage(conn));
        PQclear(res);
        return -1;
    }
    
    int count = PQntuples(res);
    if (count == 0) {
        *files = NULL;
        PQclear(res);
        return 0;
    }
    
    *files = malloc(sizeof(FileInfo*) * count);
    
    for (int i = 0; i < count; i++) {
        (*files)[i] = malloc(sizeof(FileInfo));
        (*files)[i]->file_id = atoi(PQgetvalue(res, i, 0));
        strncpy((*files)[i]->file_name, PQgetvalue(res, i, 1), sizeof((*files)[i]->file_name) - 1);
        strncpy((*files)[i]->file_path, PQgetvalue(res, i, 2), sizeof((*files)[i]->file_path) - 1);
        (*files)[i]->file_size = atoll(PQgetvalue(res, i, 3));
        strncpy((*files)[i]->file_type, PQgetvalue(res, i, 4), sizeof((*files)[i]->file_type) - 1);
        (*files)[i]->uploaded_by = atoi(PQgetvalue(res, i, 5));
        strncpy((*files)[i]->uploaded_at, PQgetvalue(res, i, 6), sizeof((*files)[i]->uploaded_at) - 1);
        strncpy((*files)[i]->parent_directory, PQgetvalue(res, i, 7), sizeof((*files)[i]->parent_directory) - 1);
        (*files)[i]->group_id = group_id;
    }
    
    PQclear(res);
    return count;
}
