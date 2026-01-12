1. Đăng ký và quản lý tài khoản (2 điểm)
   1.1 Đăng ký tài khoản
   Request:
   {
   "command": "REGISTER",
   "data": {
   "username": "user123",
   "password": "securepass123",
   "email": "user@example.com",
   "full_name": "Nguyen Van A"
   }
   }
   Response (Thành công):
   {
   "status": 201,
   "code": "SUCCESS_REGISTER",
   "message": "User registered successfully",
   "payload": {
   "user_id": 1,
   "username": "user123",
   "created_at": "2025-11-24T10:30:00Z"
   }
   }
   
   Error responses:
   {
   "status": 400,
   "code": "ERROR_INVALID_USERNAME",
   "message": "Username is invalid or too short (minimum 3 characters)",
   "payload": {}
   }
   {
   "status": 400,
   "code": "ERROR_INVALID_EMAIL",
   "message": "Email format is invalid",
   "payload": {}
   }
   {
   "status": 400,
   "code": "ERROR_WEAK_PASSWORD",
   "message": "Password is too weak (minimum 8 characters, must contain numbers and special characters)",
   "payload": {}
   }
   {
   "status": 409,
   "code": "ERROR_USERNAME_EXIST",
   "message": "Username already exists",
   "payload": {}
   }
   {
   "status": 409,
   "code": "ERROR_EMAIL_EXIST",
   "message": "Email already registered",
   "payload": {}
   }
   {
   "status": 500,
   "code": "ERROR_DATABASE_FAIL",
   "message": "Failed to save user to database",
   "payload": {}
   }
   
   1.2 Cập nhật thông tin tài khoản
   Request:
   {
   "command": "UPDATE_PROFILE",
   "data": {
   "session_token": "abc123xyz",
   "email": "newemail@example.com",
   "full_name": "Nguyen Van B"
   }
   }
   Response (Thành công):
   {
   "status": 200,
   "code": "SUCCESS_UPDATE",
   "message": "Profile updated successfully",
   "payload": {
   "user_id": 1,
   "username": "user123",
   "email": "newemail@example.com",
   "full_name": "Nguyen Van B"
   }
   }
   
   Error responses:
   {
   "status": 401,
   "code": "ERROR_SESSION_EXPIRED",
   "message": "Session has expired, please login again",
   "payload": {}
   }
   {
   "status": 400,
   "code": "ERROR_INVALID_EMAIL",
   "message": "Email format is invalid",
   "payload": {}
   }
   {
   "status": 409,
   "code": "ERROR_EMAIL_EXIST",
   "message": "Email is already used by another account",
   "payload": {}
   }
   {
   "status": 400,
   "code": "ERROR_INVALID_FULL_NAME",
   "message": "Full name is too short or contains invalid characters",
   "payload": {}
   }
   {
   "status": 500,
   "code": "ERROR_UPDATE_FAILED",
   "message": "Failed to update profile information",
   "payload": {}
   }
   
   1.3 Đổi mật khẩu
   Request:
   {
   "command": "CHANGE_PASSWORD",
   "data": {
   "session_token": "abc123xyz",
   "old_password": "securepass123",
   "new_password": "newsecurepass456"
   }
   }
   Response (Thành công):
   {
   "status": 200,
   "code": "SUCCESS_CHANGE_PASSWORD",
   "message": "Password changed successfully",
   "payload": {}
   }
   
   Error responses:
   {
   "status": 401,
   "code": "ERROR_SESSION_EXPIRED",
   "message": "Session has expired, please login again",
   "payload": {}
   }
   {
   "status": 400,
   "code": "ERROR_WRONG_OLD_PASSWORD",
   "message": "Current password is incorrect",
   "payload": {}
   }
   {
   "status": 400,
   "code": "ERROR_WEAK_PASSWORD",
   "message": "New password is too weak (minimum 8 characters, must contain numbers and special characters)",
   "payload": {}
   }
   {
   "status": 400,
   "code": "ERROR_SAME_PASSWORD",
   "message": "New password cannot be the same as current password",
   "payload": {}
   }
   {
   "status": 500,
   "code": "ERROR_UPDATE_FAILED",
   "message": "Failed to update password",
   "payload": {}
   }
   
   1.4 Xóa tài khoản
   Request:
   {
   "command": "DELETE_ACCOUNT",
   "data": {
   "session_token": "abc123xyz",
   "password": "securepass123"
   }
   }
   Response (Thành công):
   {
   "status": 200,
   "code": "SUCCESS_DELETE_ACCOUNT",
   "message": "Account deleted successfully",
   "payload": {
   "user_id": 1,
   "deleted_at": "2025-11-24T12:00:00Z"
   }
   }
   
   Error responses:
   {
   "status": 401,
   "code": "ERROR_SESSION_EXPIRED",
   "message": "Session has expired, please login again",
   "payload": {}
   }
   {
   "status": 400,
   "code": "ERROR_WRONG_PASSWORD",
   "message": "Password is incorrect",
   "payload": {}
   }
   {
   "status": 403,
   "code": "ERROR_CANNOT_DELETE_OWNER",
   "message": "Cannot delete account while you are the owner of active groups",
   "payload": {"groups": [{"group_id": 10, "group_name": "Project Team"}]}
   }
   {
   "status": 500,
   "code": "ERROR_DELETE_FAILED",
   "message": "Failed to delete account",
   "payload": {}
   }

2. Đăng nhập và quản lý phiên (2 điểm)
   2.1 Đăng nhập
   Request:
   {
   "command": "LOGIN",
   "data": {
   "username": "user123",
   "password": "securepass123"
   }
   }
   Response (Thành công):
   {
   "status": 200,
   "code": "SUCCESS_LOGIN",
   "message": "Login successful",
   "payload": {
   "user_id": 1,
   "username": "user123",
   "session_token": "abc123xyz",
   "role": "user",
   "expires_at": "2025-11-25T10:30:00Z"
   }
   }
   
   Error responses:
   {
   "status": 400,
   "code": "ERROR_MISSING_CREDENTIALS",
   "message": "Username and password are required",
   "payload": {}
   }
   {
   "status": 401,
   "code": "ERROR_INVALID_CREDENTIALS",
   "message": "Username or password is incorrect",
   "payload": {}
   }
   {
   "status": 403,
   "code": "ERROR_ACCOUNT_LOCKED",
   "message": "Account is locked due to too many failed login attempts",
   "payload": {"unlock_time": "2025-11-24T12:30:00Z"}
   }
   {
   "status": 403,
   "code": "ERROR_ACCOUNT_DISABLED",
   "message": "Account has been disabled by administrator",
   "payload": {}
   }
   {
   "status": 500,
   "code": "ERROR_LOGIN_FAILED",
   "message": "Login failed, please try again later",
   "payload": {}
   }
   
   2.2 Đăng xuất
   Request:
   {
   "command": "LOGOUT",
   "data": {
   "session_token": "abc123xyz"
   }
   }
   Response (Thành công):
   {
   "status": 200,
   "code": "SUCCESS_LOGOUT",
   "message": "Logout successful",
   "payload": {}
   }
   
   Error responses:
   {
   "status": 400,
   "code": "ERROR_INVALID_TOKEN",
   "message": "Session token is missing or invalid",
   "payload": {}
   }
   {
   "status": 401,
   "code": "ERROR_SESSION_EXPIRED",
   "message": "Session has already expired",
   "payload": {}
   }
   {
   "status": 500,
   "code": "ERROR_LOGOUT_FAILED",
   "message": "Failed to logout, please try again",
   "payload": {}
   }
   
   2.3 Kiểm tra phiên
   Request:
   {
   "command": "VERIFY_SESSION",
   "data": {
   "session_token": "abc123xyz"
   }
   }
   Response (Thành công):
   {
   "status": 200,
   "code": "SUCCESS_VERIFY_SESSION",
   "message": "Session is valid",
   "payload": {
   "user_id": 1,
   "username": "user123",
   "expires_at": "2025-11-25T10:30:00Z"
   }
   }
   
   Error responses:
   {
   "status": 400,
   "code": "ERROR_MISSING_TOKEN",
   "message": "Session token is required",
   "payload": {}
   }
   {
   "status": 401,
   "code": "ERROR_INVALID_TOKEN",
   "message": "Session token is invalid or malformed",
   "payload": {}
   }
   {
   "status": 401,
   "code": "ERROR_SESSION_EXPIRED",
   "message": "Session has expired, please login again",
   "payload": {}
   }
   {
   "status": 403,
   "code": "ERROR_TOKEN_REVOKED",
   "message": "Session token has been revoked",
   "payload": {}
   }
   {
   "status": 500,
   "code": "ERROR_VERIFY_FAILED",
   "message": "Failed to verify session",
   "payload": {}
   }
3. Kiểm soát quyền truy cập (2 điểm)
   3.1 Lấy quyền của user trong nhóm
   Request:
   {
   "command": "GET_PERMISSIONS",
   "data": {
   "session_token": "abc123xyz",
   "group_id": 10
   }
   }
   Response (Thành công):
   {
   "status": 200,
   "code": "SUCCESS_GET_PERMISSIONS",
   "message": "Permissions retrieved successfully",
   "payload": {
   "user_id": 1,
   "group_id": 10,
   "can_read": true,
   "can_write": true,
   "can_delete": false,
   "can_manage": false
   }
   }
   
   Error responses:
   {
   "status": 401,
   "code": "ERROR_UNAUTHORIZED",
   "message": "Invalid session token or session expired",
   "payload": {}
   }
   {
   "status": 404,
   "code": "ERROR_GROUP_NOT_FOUND",
   "message": "Group not found",
   "payload": {}
   }
   {
   "status": 403,
   "code": "ERROR_NOT_GROUP_MEMBER",
   "message": "You are not a member of this group",
   "payload": {}
   }
   {
   "status": 500,
   "code": "ERROR_PERMISSION_FETCH_FAILED",
   "message": "Failed to retrieve permissions",
   "payload": {}
   }
   
   3.2 Cập nhật quyền (dành cho admin nhóm)
   Request:
   {
   "command": "UPDATE_PERMISSIONS",
   "data": {
   "session_token": "abc123xyz",
   "group_id": 10,
   "target_user_id": 5,
   "can_read": true,
   "can_write": true,
   "can_delete": true,
   "can_manage": false
   }
   }
   Response (Thành công):
   {
   "status": 200,
   "code": "SUCCESS_UPDATE_PERMISSIONS",
   "message": "Permissions updated successfully",
   "payload": {
   "user_id": 5,
   "group_id": 10,
   "can_read": true,
   "can_write": true,
   "can_delete": true,
   "can_manage": false
   }
   }
   
   Error responses:
   {
   "status": 401,
   "code": "ERROR_UNAUTHORIZED",
   "message": "Invalid session token or session expired",
   "payload": {}
   }
   {
   "status": 403,
   "code": "ERROR_FORBIDDEN",
   "message": "Only group admin or owner can update permissions",
   "payload": {}
   }
   {
   "status": 404,
   "code": "ERROR_GROUP_NOT_FOUND",
   "message": "Group not found",
   "payload": {}
   }
   {
   "status": 404,
   "code": "ERROR_USER_NOT_IN_GROUP",
   "message": "Target user is not a member of this group",
   "payload": {}
   }
   {
   "status": 400,
   "code": "ERROR_INVALID_PERMISSIONS",
   "message": "Invalid permission configuration",
   "payload": {}
   }
   {
   "status": 500,
   "code": "ERROR_UPDATE_FAILED",
   "message": "Failed to update permissions",
   "payload": {}
   }
4. Tạo nhóm chia sẻ (1 điểm)
   Request:
   {
   "command": "CREATE_GROUP",
   "data": {
   "session_token": "abc123xyz",
   "group_name": "Project Team",
   "description": "Team for sharing project files"
   }
   }
   Response (Thành công):
   {
   "status": 201,
   "code": "SUCCESS_CREATE_GROUP",
   "message": "Group created successfully",
   "payload": {
   "group_id": 10,
   "group_name": "Project Team",
   "description": "Team for sharing project files",
   "owner_id": 1,
   "created_at": "2025-11-24T10:30:00Z"
   }
   }
   
   Error responses:
   {
   "status": 401,
   "code": "ERROR_UNAUTHORIZED",
   "message": "Invalid session token or session expired",
   "payload": {}
   }
   {
   "status": 400,
   "code": "ERROR_MISSING_GROUP_NAME",
   "message": "Group name is required",
   "payload": {}
   }
   {
   "status": 400,
   "code": "ERROR_INVALID_GROUP_NAME",
   "message": "Group name is too short (minimum 3 characters) or contains invalid characters",
   "payload": {}
   }
   {
   "status": 409,
   "code": "ERROR_GROUP_NAME_EXIST",
   "message": "A group with this name already exists",
   "payload": {}
   }
   {
   "status": 400,
   "code": "ERROR_MAX_GROUPS_REACHED",
   "message": "You have reached the maximum number of groups you can create",
   "payload": {}
   }
   {
   "status": 500,
   "code": "ERROR_CREATE_GROUP_FAILED",
   "message": "Failed to create group",
   "payload": {}
   }
5. Liệt kê danh sách nhóm (1 điểm)
   5.1 Lấy danh sách nhóm của user
   Request:
   {
   "command": "LIST_MY_GROUPS",
   "data": {
   "session_token": "abc123xyz"
   }
   }
   Response (Thành công):
   {
   "status": 200,
   "code": "SUCCESS_LIST_GROUPS",
   "message": "Groups retrieved successfully",
   "payload": {
   "groups": [
   {
   "group_id": 10,
   "group_name": "Project Team",
   "description": "Team for sharing project files",
   "role": "admin",
   "member_count": 5,
   "created_at": "2025-11-24T10:30:00Z"
   },
   {
   "group_id": 15,
   "group_name": "Study Group",
   "description": "Group for study materials",
   "role": "member",
   "member_count": 10,
   "created_at": "2025-11-20T09:00:00Z"
   }
   ]
   }
   }
   
   Error responses:
   {
   "status": 401,
   "code": "ERROR_UNAUTHORIZED",
   "message": "Invalid session token or session expired",
   "payload": {}
   }
   {
   "status": 500,
   "code": "ERROR_LIST_GROUPS_FAILED",
   "message": "Failed to retrieve groups",
   "payload": {}
   }
   
   5.2 Tìm kiếm nhóm
   Request:
   {
   "command": "SEARCH_GROUPS",
   "data": {
   "session_token": "abc123xyz",
   "keyword": "project"
   }
   }
   Response (Thành công):
   {
   "status": 200,
   "code": "SUCCESS_SEARCH_GROUPS",
   "message": "Search completed",
   "payload": {
   "groups": [
   {
   "group_id": 10,
   "group_name": "Project Team",
   "description": "Team for sharing project files",
   "owner_name": "Nguyen Van A",
   "member_count": 5
   }
   ]
   }
   }
   
   Error responses:
   {
   "status": 401,
   "code": "ERROR_UNAUTHORIZED",
   "message": "Invalid session token or session expired",
   "payload": {}
   }
   {
   "status": 400,
   "code": "ERROR_EMPTY_KEYWORD",
   "message": "Search keyword is required",
   "payload": {}
   }
   {
   "status": 400,
   "code": "ERROR_INVALID_KEYWORD",
   "message": "Search keyword is too short (minimum 1 character)",
   "payload": {}
   }
   {
   "status": 500,
   "code": "ERROR_SEARCH_FAILED",
   "message": "Failed to search groups",
   "payload": {}
   }
6. Liệt kê danh sách thành viên trong nhóm (1 điểm)
   Request:
   {
   "command": "LIST_GROUP_MEMBERS",
   "data": {
   "session_token": "abc123xyz",
   "group_id": 10
   }
   }
   Response (Thành công):
   {
   "status": 200,
   "code": "SUCCESS_LIST_MEMBERS",
   "message": "Members retrieved successfully",
   "payload": {
   "group_id": 10,
   "members": [
   {
   "user_id": 1,
   "username": "user123",
   "full_name": "Nguyen Van A",
   "role": "admin",
   "status": "approved",
   "joined_at": "2025-11-24T10:30:00Z"
   },
   {
   "user_id": 5,
   "username": "user456",
   "full_name": "Tran Thi B",
   "role": "member",
   "status": "approved",
   "joined_at": "2025-11-24T11:00:00Z"
   }
   ]
   }
   }
   
   Error responses:
   {
   "status": 401,
   "code": "ERROR_UNAUTHORIZED",
   "message": "Invalid session token or session expired",
   "payload": {}
   }
   {
   "status": 404,
   "code": "ERROR_GROUP_NOT_FOUND",
   "message": "Group not found",
   "payload": {}
   }
   {
   "status": 403,
   "code": "ERROR_NOT_GROUP_MEMBER",
   "message": "You are not a member of this group",
   "payload": {}
   }
   {
   "status": 500,
   "code": "ERROR_LIST_MEMBERS_FAILED",
   "message": "Failed to retrieve group members",
   "payload": {}
   }
7. Yêu cầu tham gia một nhóm và phê duyệt (2 điểm)
   7.1 Gửi yêu cầu tham gia
   Request:
   {
   "command": "REQUEST_JOIN_GROUP",
   "data": {
   "session_token": "abc123xyz",
   "group_id": 10
   }
   }
   Response (Thành công):
   {
   "status": 201,
   "code": "SUCCESS_REQUEST_JOIN",
   "message": "Join request sent successfully",
   "payload": {
   "request_id": 100,
   "group_id": 10,
   "user_id": 1,
   "status": "pending",
   "created_at": "2025-11-24T10:30:00Z"
   }
   }
   
   Error responses:
   {
   "status": 401,
   "code": "ERROR_UNAUTHORIZED",
   "message": "Invalid session token or session expired",
   "payload": {}
   }
   {
   "status": 404,
   "code": "ERROR_GROUP_NOT_FOUND",
   "message": "Group not found",
   "payload": {}
   }
   {
   "status": 409,
   "code": "ERROR_ALREADY_MEMBER",
   "message": "You are already a member of this group",
   "payload": {}
   }
   {
   "status": 409,
   "code": "ERROR_REQUEST_PENDING",
   "message": "You have already sent a pending request to join this group",
   "payload": {}
   }
   {
   "status": 403,
   "code": "ERROR_BANNED_FROM_GROUP",
   "message": "You have been banned from this group",
   "payload": {}
   }
   {
   "status": 500,
   "code": "ERROR_REQUEST_FAILED",
   "message": "Failed to send join request",
   "payload": {}
   }
   
   7.2 Liệt kê yêu cầu tham gia (admin)
   Request:
   {
   "command": "LIST_JOIN_REQUESTS",
   "data": {
   "session_token": "abc123xyz",
   "group_id": 10
   }
   }
   Response (Thành công):
   {
   "status": 200,
   "code": "SUCCESS_LIST_REQUESTS",
   "message": "Join requests retrieved successfully",
   "payload": {
   "group_id": 10,
   "requests": [
   {
   "request_id": 100,
   "user_id": 1,
   "username": "user123",
   "full_name": "Nguyen Van A",
   "status": "pending",
   "requested_at": "2025-11-24T10:30:00Z"
   }
   ]
   }
   }
   
   Error responses:
   {
   "status": 401,
   "code": "ERROR_UNAUTHORIZED",
   "message": "Invalid session token or session expired",
   "payload": {}
   }
   {
   "status": 403,
   "code": "ERROR_FORBIDDEN",
   "message": "Only group admin or owner can view join requests",
   "payload": {}
   }
   {
   "status": 404,
   "code": "ERROR_GROUP_NOT_FOUND",
   "message": "Group not found",
   "payload": {}
   }
   {
   "status": 500,
   "code": "ERROR_LIST_REQUESTS_FAILED",
   "message": "Failed to retrieve join requests",
   "payload": {}
   }
   
   7.3 Phê duyệt/Từ chối yêu cầu
   Request:
   {
   "command": "APPROVE_JOIN_REQUEST",
   "data": {
   "session_token": "abc123xyz",
   "request_id": 100,
   "action": "approve"
   }
   }
   Response (Thành công):
   {
   "status": 200,
   "code": "SUCCESS_APPROVE_REQUEST",
   "message": "Join request approved successfully",
   "payload": {
   "request_id": 100,
   "user_id": 5,
   "group_id": 10,
   "status": "approved",
   "reviewed_at": "2025-11-24T11:00:00Z"
   }
   }
   
   Error responses:
   {
   "status": 401,
   "code": "ERROR_UNAUTHORIZED",
   "message": "Invalid session token or session expired",
   "payload": {}
   }
   {
   "status": 403,
   "code": "ERROR_FORBIDDEN",
   "message": "Only group admin or owner can approve/reject requests",
   "payload": {}
   }
   {
   "status": 404,
   "code": "ERROR_REQUEST_NOT_FOUND",
   "message": "Join request not found",
   "payload": {}
   }
   {
   "status": 409,
   "code": "ERROR_REQUEST_ALREADY_PROCESSED",
   "message": "This request has already been processed",
   "payload": {}
   }
   {
   "status": 400,
   "code": "ERROR_INVALID_ACTION",
   "message": "Action must be either 'approve' or 'reject'",
   "payload": {}
   }
   {
   "status": 500,
   "code": "ERROR_PROCESS_FAILED",
   "message": "Failed to process join request",
   "payload": {}
   }
8. Mời tham gia vào nhóm và phê duyệt (2 điểm)
   8.1 Gửi lời mời
   Request:
   {
   "command": "INVITE_TO_GROUP",
   "data": {
   "session_token": "abc123xyz",
   "group_id": 10,
   "invitee_username": "user789"
   }
   }
   Response (Thành công):
   {
   "status": 201,
   "code": "SUCCESS_SEND_INVITATION",
   "message": "Invitation sent successfully",
   "payload": {
   "invitation_id": 200,
   "group_id": 10,
   "inviter_id": 1,
   "invitee_id": 7,
   "status": "pending",
   "created_at": "2025-11-24T10:30:00Z"
   }
   }
   
   Error responses:
   {
   "status": 401,
   "code": "ERROR_UNAUTHORIZED",
   "message": "Invalid session token or session expired",
   "payload": {}
   }
   {
   "status": 403,
   "code": "ERROR_FORBIDDEN",
   "message": "Only group admin or owner can send invitations",
   "payload": {}
   }
   {
   "status": 404,
   "code": "ERROR_GROUP_NOT_FOUND",
   "message": "Group not found",
   "payload": {}
   }
   {
   "status": 404,
   "code": "ERROR_USER_NOT_FOUND",
   "message": "User to invite not found",
   "payload": {}
   }
   {
   "status": 409,
   "code": "ERROR_ALREADY_MEMBER",
   "message": "User is already a member of this group",
   "payload": {}
   }
   {
   "status": 409,
   "code": "ERROR_INVITATION_PENDING",
   "message": "An invitation to this user is already pending",
   "payload": {}
   }
   {
   "status": 500,
   "code": "ERROR_SEND_INVITATION_FAILED",
   "message": "Failed to send invitation",
   "payload": {}
   }
   
   8.2 Liệt kê lời mời của user
   Request:
   {
   "command": "LIST_MY_INVITATIONS",
   "data": {
   "session_token": "abc123xyz"
   }
   }
   Response (Thành công):
   {
   "status": 200,
   "code": "SUCCESS_LIST_INVITATIONS",
   "message": "Invitations retrieved successfully",
   "payload": {
   "invitations": [
   {
   "invitation_id": 200,
   "group_id": 10,
   "group_name": "Project Team",
   "inviter_username": "user123",
   "inviter_name": "Nguyen Van A",
   "status": "pending",
   "created_at": "2025-11-24T10:30:00Z"
   }
   ]
   }
   }
   
   Error responses:
   {
   "status": 401,
   "code": "ERROR_UNAUTHORIZED",
   "message": "Invalid session token or session expired",
   "payload": {}
   }
   {
   "status": 500,
   "code": "ERROR_LIST_INVITATIONS_FAILED",
   "message": "Failed to retrieve invitations",
   "payload": {}
   }
   
   8.3 Chấp nhận/Từ chối lời mời
   Request:
   {
   "command": "RESPOND_INVITATION",
   "data": {
   "session_token": "abc123xyz",
   "invitation_id": 200,
   "action": "accept"
   }
   }
   Response (Thành công):
   {
   "status": 200,
   "code": "SUCCESS_ACCEPT_INVITATION",
   "message": "Invitation accepted successfully",
   "payload": {
   "invitation_id": 200,
   "group_id": 10,
   "status": "accepted",
   "responded_at": "2025-11-24T11:00:00Z"
   }
   }
   
   Error responses:
   {
   "status": 401,
   "code": "ERROR_UNAUTHORIZED",
   "message": "Invalid session token or session expired",
   "payload": {}
   }
   {
   "status": 404,
   "code": "ERROR_INVITATION_NOT_FOUND",
   "message": "Invitation not found",
   "payload": {}
   }
   {
   "status": 409,
   "code": "ERROR_INVITATION_ALREADY_PROCESSED",
   "message": "This invitation has already been responded to",
   "payload": {}
   }
   {
   "status": 409,
   "code": "ERROR_INVITATION_EXPIRED",
   "message": "This invitation has expired",
   "payload": {}
   }
   {
   "status": 400,
   "code": "ERROR_INVALID_ACTION",
   "message": "Action must be either 'accept' or 'reject'",
   "payload": {}
   }
   {
   "status": 500,
   "code": "ERROR_RESPOND_FAILED",
   "message": "Failed to respond to invitation",
   "payload": {}
   }
9. Rời nhóm (1 điểm)
   Request:
   {
   "command": "LEAVE_GROUP",
   "data": {
   "session_token": "abc123xyz",
   "group_id": 10
   }
   }
   Response (Thành công):
   {
   "status": 200,
   "code": "SUCCESS_LEAVE_GROUP",
   "message": "Left group successfully",
   "payload": {
   "group_id": 10,
   "user_id": 1,
   "left_at": "2025-11-24T11:00:00Z"
   }
   }
   
   Error responses:
   {
   "status": 401,
   "code": "ERROR_UNAUTHORIZED",
   "message": "Invalid session token or session expired",
   "payload": {}
   }
   {
   "status": 404,
   "code": "ERROR_GROUP_NOT_FOUND",
   "message": "Group not found",
   "payload": {}
   }
   {
   "status": 403,
   "code": "ERROR_NOT_GROUP_MEMBER",
   "message": "You are not a member of this group",
   "payload": {}
   }
   {
   "status": 403,
   "code": "ERROR_OWNER_CANNOT_LEAVE",
   "message": "Group owner cannot leave the group. Please transfer ownership or delete the group first",
   "payload": {}
   }
   {
   "status": 500,
   "code": "ERROR_LEAVE_FAILED",
   "message": "Failed to leave group",
   "payload": {}
   }
10. Xóa thành viên khỏi nhóm (1 điểm)
    Request:
    {
    "command": "REMOVE_MEMBER",
    "data": {
    "session_token": "abc123xyz",
    "group_id": 10,
    "target_user_id": 5
    }
    }
    Response (Thành công):
    {
    "status": 200,
    "code": "SUCCESS_REMOVE_MEMBER",
    "message": "Member removed successfully",
    "payload": {
    "group_id": 10,
    "removed_user_id": 5,
    "removed_at": "2025-11-24T11:00:00Z"
    }
    }
    
    Error responses:
    {
    "status": 401,
    "code": "ERROR_UNAUTHORIZED",
    "message": "Invalid session token or session expired",
    "payload": {}
    }
    {
    "status": 403,
    "code": "ERROR_FORBIDDEN",
    "message": "Only group admin or owner can remove members",
    "payload": {}
    }
    {
    "status": 404,
    "code": "ERROR_GROUP_NOT_FOUND",
    "message": "Group not found",
    "payload": {}
    }
    {
    "status": 404,
    "code": "ERROR_USER_NOT_IN_GROUP",
    "message": "User is not a member of this group",
    "payload": {}
    }
    {
    "status": 409,
    "code": "ERROR_CANNOT_REMOVE_OWNER",
    "message": "Cannot remove the group owner",
    "payload": {}
    }
    {
    "status": 500,
    "code": "ERROR_REMOVE_FAILED",
    "message": "Failed to remove member",
    "payload": {}
    }
11. Liệt kê nội dung thư mục (2 điểm)
    Request:
    {
    "command": "LIST_DIRECTORY",
    "data": {
    "session_token": "abc123xyz",
    "group_id": 10,
    "directory_path": "/project/docs"
    }
    }
    Response (Thành công):
    {
    "status": 200,
    "code": "SUCCESS_LIST_DIRECTORY",
    "message": "Directory contents retrieved successfully",
    "payload": {
    "group_id": 10,
    "current_path": "/project/docs",
    "directories": [
    {
    "directory_id": 50,
    "directory_name": "reports",
    "directory_path": "/project/docs/reports",
    "created_by": "user123",
    "created_at": "2025-11-20T09:00:00Z"
    }
    ],
    "files": [
    {
    "file_id": 500,
    "file_name": "document.pdf",
    "file_path": "/project/docs/document.pdf",
    "file_size": 2048576,
    "file_type": "application/pdf",
    "uploaded_by": "user123",
    "uploaded_at": "2025-11-24T10:00:00Z"
    }
    ]
    }
    }
    
    Error responses:
    {
    "status": 401,
    "code": "ERROR_UNAUTHORIZED",
    "message": "Invalid session token or session expired",
    "payload": {}
    }
    {
    "status": 403,
    "code": "ERROR_FORBIDDEN",
    "message": "You don't have permission to read this directory",
    "payload": {}
    }
    {
    "status": 404,
    "code": "ERROR_GROUP_NOT_FOUND",
    "message": "Group not found",
    "payload": {}
    }
    {
    "status": 404,
    "code": "ERROR_DIRECTORY_NOT_FOUND",
    "message": "Directory not found",
    "payload": {}
    }
    {
    "status": 400,
    "code": "ERROR_INVALID_PATH",
    "message": "Invalid directory path",
    "payload": {}
    }
    {
    "status": 500,
    "code": "ERROR_LIST_DIRECTORY_FAILED",
    "message": "Failed to list directory contents",
    "payload": {}
    }
12. Upload/Download file (2 điểm)
    12.1 Bắt đầu upload file
    Request:
    {
    "command": "UPLOAD_FILE_START",
    "data": {
    "session_token": "abc123xyz",
    "group_id": 10,
    "file_name": "document.pdf",
    "file_size": 2048576,
    "file_type": "application/pdf",
    "directory_path": "/project/docs",
    "chunk_size": 65536
    }
    }
    Response (Thành công):
    {
    "status": 200,
    "code": "SUCCESS_UPLOAD_START",
    "message": "Ready to receive file",
    "payload": {
    "upload_id": "upload_123abc",
    "file_id": 500,
    "total_chunks": 32,
    "chunk_size": 65536
    }
    }
    
    Error responses:
    {
    "status": 401,
    "code": "ERROR_UNAUTHORIZED",
    "message": "Invalid session token or session expired",
    "payload": {}
    }
    {
    "status": 403,
    "code": "ERROR_FORBIDDEN",
    "message": "You don't have permission to upload files to this group",
    "payload": {}
    }
    {
    "status": 404,
    "code": "ERROR_GROUP_NOT_FOUND",
    "message": "Group not found",
    "payload": {}
    }
    {
    "status": 400,
    "code": "ERROR_FILE_NAME_EMPTY",
    "message": "File name is required",
    "payload": {}
    }
    {
    "status": 400,
    "code": "ERROR_INVALID_FILE_NAME",
    "message": "File name contains invalid characters",
    "payload": {}
    }
    {
    "status": 400,
    "code": "ERROR_FILE_SIZE_INVALID",
    "message": "File size must be greater than 0",
    "payload": {}
    }
    {
    "status": 413,
    "code": "ERROR_FILE_TOO_LARGE",
    "message": "File size exceeds the maximum limit (5GB)",
    "payload": {}
    }
    {
    "status": 404,
    "code": "ERROR_DIRECTORY_NOT_FOUND",
    "message": "Target directory not found",
    "payload": {}
    }
    {
    "status": 409,
    "code": "ERROR_FILE_NAME_EXISTS",
    "message": "A file with this name already exists in the directory",
    "payload": {}
    }
    {
    "status": 500,
    "code": "ERROR_UPLOAD_START_FAILED",
    "message": "Failed to start file upload",
    "payload": {}
    }
    
    12.2 Upload chunk
    Request:
    {
    "command": "UPLOAD_FILE_CHUNK",
    "data": {
    "session_token": "abc123xyz",
    "upload_id": "upload_123abc",
    "chunk_index": 0,
    "chunk_data": "base64_encoded_data..."
    }
    }
    Response (Thành công):
    {
    "status": 200,
    "code": "SUCCESS_UPLOAD_CHUNK",
    "message": "Chunk received",
    "payload": {
    "upload_id": "upload_123abc",
    "chunk_index": 0,
    "chunks_received": 1,
    "total_chunks": 32
    }
    }
    
    Error responses:
    {
    "status": 401,
    "code": "ERROR_UNAUTHORIZED",
    "message": "Invalid session token or session expired",
    "payload": {}
    }
    {
    "status": 404,
    "code": "ERROR_UPLOAD_NOT_FOUND",
    "message": "Upload session not found",
    "payload": {}
    }
    {
    "status": 400,
    "code": "ERROR_INVALID_CHUNK_INDEX",
    "message": "Invalid chunk index or chunk already received",
    "payload": {}
    }
    {
    "status": 400,
    "code": "ERROR_INVALID_CHUNK_DATA",
    "message": "Chunk data is empty or invalid",
    "payload": {}
    }
    {
    "status": 409,
    "code": "ERROR_UPLOAD_TIMEOUT",
    "message": "Upload session has expired",
    "payload": {}
    }
    {
    "status": 507,
    "code": "ERROR_INSUFFICIENT_STORAGE",
    "message": "Server storage is full",
    "payload": {}
    }
    {
    "status": 500,
    "code": "ERROR_UPLOAD_CHUNK_FAILED",
    "message": "Failed to save chunk data",
    "payload": {}
    }
    
    12.3 Hoàn thành upload
    Request:
    {
    "command": "UPLOAD_FILE_COMPLETE",
    "data": {
    "session_token": "abc123xyz",
    "upload_id": "upload_123abc"
    }
    }
    Response (Thành công):
    {
    "status": 200,
    "code": "SUCCESS_UPLOAD_COMPLETE",
    "message": "File uploaded successfully",
    "payload": {
    "file_id": 500,
    "file_name": "document.pdf",
    "file_path": "/project/docs/document.pdf",
    "file_size": 2048576,
    "uploaded_at": "2025-11-24T10:30:00Z"
    }
    }
    
    Error responses:
    {
    "status": 401,
    "code": "ERROR_UNAUTHORIZED",
    "message": "Invalid session token or session expired",
    "payload": {}
    }
    {
    "status": 404,
    "code": "ERROR_UPLOAD_NOT_FOUND",
    "message": "Upload session not found",
    "payload": {}
    }
    {
    "status": 400,
    "code": "ERROR_INCOMPLETE_UPLOAD",
    "message": "Not all chunks have been received yet",
    "payload": {"chunks_received": 15, "total_chunks": 32}
    }
    {
    "status": 409,
    "code": "ERROR_UPLOAD_TIMEOUT",
    "message": "Upload session has expired",
    "payload": {}
    }
    {
    "status": 500,
    "code": "ERROR_UPLOAD_COMPLETE_FAILED",
    "message": "Failed to complete file upload",
    "payload": {}
    }
    
    12.4 Bắt đầu download file
    Request:
    {
    "command": "DOWNLOAD_FILE_START",
    "data": {
    "session_token": "abc123xyz",
    "file_id": 500,
    "chunk_size": 65536
    }
    }
    Response (Thành công):
    {
    "status": 200,
    "code": "SUCCESS_DOWNLOAD_START",
    "message": "Ready to send file",
    "payload": {
    "download_id": "download_456def",
    "file_id": 500,
    "file_name": "document.pdf",
    "file_size": 2048576,
    "total_chunks": 32,
    "chunk_size": 65536
    }
    }
    
    Error responses:
    {
    "status": 401,
    "code": "ERROR_UNAUTHORIZED",
    "message": "Invalid session token or session expired",
    "payload": {}
    }
    {
    "status": 403,
    "code": "ERROR_FORBIDDEN",
    "message": "You don't have permission to download this file",
    "payload": {}
    }
    {
    "status": 404,
    "code": "ERROR_FILE_NOT_FOUND",
    "message": "File not found",
    "payload": {}
    }
    {
    "status": 400,
    "code": "ERROR_INVALID_CHUNK_SIZE",
    "message": "Chunk size must be between 1KB and 10MB",
    "payload": {}
    }
    {
    "status": 500,
    "code": "ERROR_DOWNLOAD_START_FAILED",
    "message": "Failed to start file download",
    "payload": {}
    }
    
    12.5 Download chunk
    Request:
    {
    "command": "DOWNLOAD_FILE_CHUNK",
    "data": {
    "session_token": "abc123xyz",
    "download_id": "download_456def",
    "chunk_index": 0
    }
    }
    Response (Thành công):
    {
    "status": 200,
    "code": "SUCCESS_DOWNLOAD_CHUNK",
    "message": "Chunk sent",
    "payload": {
    "download_id": "download_456def",
    "chunk_index": 0,
    "chunk_data": "base64_encoded_data...",
    "chunks_sent": 1,
    "total_chunks": 32
    }
    }
    
    Error responses:
    {
    "status": 401,
    "code": "ERROR_UNAUTHORIZED",
    "message": "Invalid session token or session expired",
    "payload": {}
    }
    {
    "status": 404,
    "code": "ERROR_DOWNLOAD_NOT_FOUND",
    "message": "Download session not found",
    "payload": {}
    }
    {
    "status": 400,
    "code": "ERROR_INVALID_CHUNK_INDEX",
    "message": "Invalid chunk index",
    "payload": {}
    }
    {
    "status": 409,
    "code": "ERROR_DOWNLOAD_TIMEOUT",
    "message": "Download session has expired",
    "payload": {}
    }
    {
    "status": 500,
    "code": "ERROR_DOWNLOAD_CHUNK_FAILED",
    "message": "Failed to send chunk data",
    "payload": {}
    }
    
    12.6 Hoàn thành download
    Request:
    {
    "command": "DOWNLOAD_FILE_COMPLETE",
    "data": {
    "session_token": "abc123xyz",
    "download_id": "download_456def"
    }
    }
    Response (Thành công):
    {
    "status": 200,
    "code": "SUCCESS_DOWNLOAD_COMPLETE",
    "message": "File downloaded successfully",
    "payload": {
    "file_id": 500,
    "download_id": "download_456def"
    }
    }
    
    Error responses:
    {
    "status": 401,
    "code": "ERROR_UNAUTHORIZED",
    "message": "Invalid session token or session expired",
    "payload": {}
    }
    {
    "status": 404,
    "code": "ERROR_DOWNLOAD_NOT_FOUND",
    "message": "Download session not found",
    "payload": {}
    }
    {
    "status": 500,
    "code": "ERROR_DOWNLOAD_COMPLETE_FAILED",
    "message": "Failed to complete download",
    "payload": {}
    }
13. Thao tác với file (2 điểm)
    **Lưu ý: Upload file (12.1-12.3) - Tất cả thành viên nhóm có quyền. Đổi tên/Xóa/Copy/Di chuyển (13.1-13.4) - Chỉ admin/owner nhóm có quyền.**

    13.1 Đổi tên file (chỉ admin/owner)
    Request:
    {
    "command": "RENAME_FILE",
    "data": {
    "session_token": "abc123xyz",
    "file_id": 500,
    "new_name": "new_document.pdf"
    }
    }
    Response (Thành công):
    {
    "status": 200,
    "code": "SUCCESS_RENAME_FILE",
    "message": "File renamed successfully",
    "payload": {
    "file_id": 500,
    "old_name": "document.pdf",
    "new_name": "new_document.pdf",
    "updated_at": "2025-11-24T11:00:00Z"
    }
    }
    
    Error responses:
    {
    "status": 401,
    "code": "ERROR_UNAUTHORIZED",
    "message": "Invalid session token or session expired",
    "payload": {}
    }
    {
    "status": 403,
    "code": "ERROR_FORBIDDEN",
    "message": "Only group admin or owner can rename files",
    "payload": {}
    }
    {
    "status": 404,
    "code": "ERROR_FILE_NOT_FOUND",
    "message": "File not found",
    "payload": {}
    }
    {
    "status": 400,
    "code": "ERROR_INVALID_FILE_NAME",
    "message": "New file name is invalid or contains invalid characters",
    "payload": {}
    }
    {
    "status": 409,
    "code": "ERROR_FILE_NAME_EXISTS",
    "message": "A file with this name already exists in the directory",
    "payload": {}
    }
    {
    "status": 500,
    "code": "ERROR_RENAME_FAILED",
    "message": "Failed to rename file",
    "payload": {}
    }
    
    13.2 Xóa file (chỉ admin/owner)
    Request:
    {
    "command": "DELETE_FILE",
    "data": {
    "session_token": "abc123xyz",
    "file_id": 500
    }
    }
    Response (Thành công):
    {
    "status": 200,
    "code": "SUCCESS_DELETE_FILE",
    "message": "File deleted successfully",
    "payload": {
    "file_id": 500,
    "deleted_at": "2025-11-24T11:00:00Z"
    }
    }
    
    Error responses:
    {
    "status": 401,
    "code": "ERROR_UNAUTHORIZED",
    "message": "Invalid session token or session expired",
    "payload": {}
    }
    {
    "status": 403,
    "code": "ERROR_FORBIDDEN",
    "message": "Only group admin or owner can delete files",
    "payload": {}
    }
    {
    "status": 404,
    "code": "ERROR_FILE_NOT_FOUND",
    "message": "File not found",
    "payload": {}
    }
    {
    "status": 500,
    "code": "ERROR_DELETE_FAILED",
    "message": "Failed to delete file",
    "payload": {}
    }
    
    13.3 Copy file (chỉ admin/owner)
    Request:
    {
    "command": "COPY_FILE",
    "data": {
    "session_token": "abc123xyz",
    "file_id": 500,
    "destination_path": "/project/backup"
    }
    }
    Response (Thành công):
    {
    "status": 200,
    "code": "SUCCESS_COPY_FILE",
    "message": "File copied successfully",
    "payload": {
    "source_file_id": 500,
    "new_file_id": 501,
    "new_file_path": "/project/backup/document.pdf",
    "copied_at": "2025-11-24T11:00:00Z"
    }
    }
    
    Error responses:
    {
    "status": 401,
    "code": "ERROR_UNAUTHORIZED",
    "message": "Invalid session token or session expired",
    "payload": {}
    }
    {
    "status": 403,
    "code": "ERROR_FORBIDDEN",
    "message": "Only group admin or owner can copy files",
    "payload": {}
    }
    {
    "status": 404,
    "code": "ERROR_FILE_NOT_FOUND",
    "message": "Source file not found",
    "payload": {}
    }
    {
    "status": 404,
    "code": "ERROR_DESTINATION_NOT_FOUND",
    "message": "Destination directory not found",
    "payload": {}
    }
    {
    "status": 400,
    "code": "ERROR_INVALID_DESTINATION",
    "message": "Invalid destination path",
    "payload": {}
    }
    {
    "status": 507,
    "code": "ERROR_INSUFFICIENT_STORAGE",
    "message": "Insufficient storage space to copy file",
    "payload": {}
    }
    {
    "status": 500,
    "code": "ERROR_COPY_FAILED",
    "message": "Failed to copy file",
    "payload": {}
    }
    
    13.4 Di chuyển file (chỉ admin/owner)
    Request:
    {
    "command": "MOVE_FILE",
    "data": {
    "session_token": "abc123xyz",
    "file_id": 500,
    "destination_path": "/project/archive"
    }
    }
    Response (Thành công):
    {
    "status": 200,
    "code": "SUCCESS_MOVE_FILE",
    "message": "File moved successfully",
    "payload": {
    "file_id": 500,
    "old_path": "/project/docs/document.pdf",
    "new_path": "/project/archive/document.pdf",
    "moved_at": "2025-11-24T11:00:00Z"
    }
    }
    
    Error responses:
    {
    "status": 401,
    "code": "ERROR_UNAUTHORIZED",
    "message": "Invalid session token or session expired",
    "payload": {}
    }
    {
    "status": 403,
    "code": "ERROR_FORBIDDEN",
    "message": "Only group admin or owner can move files",
    "payload": {}
    }
    {
    "status": 404,
    "code": "ERROR_FILE_NOT_FOUND",
    "message": "File not found",
    "payload": {}
    }
    {
    "status": 404,
    "code": "ERROR_DESTINATION_NOT_FOUND",
    "message": "Destination directory not found",
    "payload": {}
    }
    {
    "status": 400,
    "code": "ERROR_INVALID_DESTINATION",
    "message": "Invalid destination path",
    "payload": {}
    }
    {
    "status": 500,
    "code": "ERROR_MOVE_FAILED",
    "message": "Failed to move file",
    "payload": {}
    }

14. Thao tác với thư mục (2 điểm)
    **Lưu ý: Tạo thư mục (14.1) - Tất cả thành viên nhóm có quyền. Đổi tên/Xóa/Copy/Di chuyển (14.2-14.5) - Chỉ admin/owner nhóm có quyền.**

    14.1 Tạo thư mục (tất cả thành viên)
    Request:
    {
    "command": "CREATE_DIRECTORY",
    "data": {
    "session_token": "abc123xyz",
    "group_id": 10,
    "directory_name": "reports",
    "parent_path": "/project/docs"
    }
    }
    Response (Thành công):
    {
    "status": 201,
    "code": "SUCCESS_CREATE_DIRECTORY",
    "message": "Directory created successfully",
    "payload": {
    "directory_id": 50,
    "directory_name": "reports",
    "directory_path": "/project/docs/reports",
    "created_at": "2025-11-24T10:30:00Z"
    }
    }
    
    Error responses:
    {
    "status": 401,
    "code": "ERROR_UNAUTHORIZED",
    "message": "Invalid session token or session expired",
    "payload": {}
    }
    {
    "status": 403,
    "code": "ERROR_FORBIDDEN",
    "message": "You don't have permission to create directories in this group",
    "payload": {}
    }
    {
    "status": 404,
    "code": "ERROR_GROUP_NOT_FOUND",
    "message": "Group not found",
    "payload": {}
    }
    {
    "status": 404,
    "code": "ERROR_PARENT_DIRECTORY_NOT_FOUND",
    "message": "Parent directory not found",
    "payload": {}
    }
    {
    "status": 400,
    "code": "ERROR_INVALID_DIRECTORY_NAME",
    "message": "Directory name is invalid or contains invalid characters",
    "payload": {}
    }
    {
    "status": 409,
    "code": "ERROR_DIRECTORY_NAME_EXISTS",
    "message": "A directory with this name already exists",
    "payload": {}
    }
    {
    "status": 500,
    "code": "ERROR_CREATE_DIRECTORY_FAILED",
    "message": "Failed to create directory",
    "payload": {}
    }
    
    14.2 Đổi tên thư mục (chỉ admin/owner)
    Request:
    {
    "command": "RENAME_DIRECTORY",
    "data": {
    "session_token": "abc123xyz",
    "directory_id": 50,
    "new_name": "monthly_reports"
    }
    }
    Response (Thành công):
    {
    "status": 200,
    "code": "SUCCESS_RENAME_DIRECTORY",
    "message": "Directory renamed successfully",
    "payload": {
    "directory_id": 50,
    "old_name": "reports",
    "new_name": "monthly_reports",
    "old_path": "/project/docs/reports",
    "new_path": "/project/docs/monthly_reports",
    "updated_at": "2025-11-24T11:00:00Z"
    }
    }
    
    Error responses:
    {
    "status": 401,
    "code": "ERROR_UNAUTHORIZED",
    "message": "Invalid session token or session expired",
    "payload": {}
    }
    {
    "status": 403,
    "code": "ERROR_FORBIDDEN",
    "message": "Only group admin or owner can rename directories",
    "payload": {}
    }
    {
    "status": 404,
    "code": "ERROR_DIRECTORY_NOT_FOUND",
    "message": "Directory not found",
    "payload": {}
    }
    {
    "status": 400,
    "code": "ERROR_INVALID_DIRECTORY_NAME",
    "message": "New directory name is invalid or contains invalid characters",
    "payload": {}
    }
    {
    "status": 409,
    "code": "ERROR_DIRECTORY_NAME_EXISTS",
    "message": "A directory with this name already exists",
    "payload": {}
    }
    {
    "status": 500,
    "code": "ERROR_RENAME_DIRECTORY_FAILED",
    "message": "Failed to rename directory",
    "payload": {}
    }
    
    14.3 Xóa thư mục (chỉ admin/owner)
    Request:
    {
    "command": "DELETE_DIRECTORY",
    "data": {
    "session_token": "abc123xyz",
    "directory_id": 50,
    "recursive": true
    }
    }
    Response (Thành công):
    {
    "status": 200,
    "code": "SUCCESS_DELETE_DIRECTORY",
    "message": "Directory deleted successfully",
    "payload": {
    "directory_id": 50,
    "deleted_files": 5,
    "deleted_subdirectories": 2,
    "deleted_at": "2025-11-24T11:00:00Z"
    }
    }
    
    Error responses:
    {
    "status": 401,
    "code": "ERROR_UNAUTHORIZED",
    "message": "Invalid session token or session expired",
    "payload": {}
    }
    {
    "status": 403,
    "code": "ERROR_FORBIDDEN",
    "message": "Only group admin or owner can delete directories",
    "payload": {}
    }
    {
    "status": 404,
    "code": "ERROR_DIRECTORY_NOT_FOUND",
    "message": "Directory not found",
    "payload": {}
    }
    {
    "status": 400,
    "code": "ERROR_DIRECTORY_NOT_EMPTY",
    "message": "Directory is not empty and recursive flag is not set",
    "payload": {}
    }
    {
    "status": 500,
    "code": "ERROR_DELETE_DIRECTORY_FAILED",
    "message": "Failed to delete directory",
    "payload": {}
    }
    
    14.4 Copy thư mục (chỉ admin/owner)
    Request:
    {
    "command": "COPY_DIRECTORY",
    "data": {
    "session_token": "abc123xyz",
    "directory_id": 50,
    "destination_path": "/project/backup"
    }
    }
    Response (Thành công):
    {
    "status": 200,
    "code": "SUCCESS_COPY_DIRECTORY",
    "message": "Directory copied successfully",
    "payload": {
    "source_directory_id": 50,
    "new_directory_id": 51,
    "new_directory_path": "/project/backup/reports",
    "copied_files": 5,
    "copied_subdirectories": 2,
    "copied_at": "2025-11-24T11:00:00Z"
    }
    }
    
    Error responses:
    {
    "status": 401,
    "code": "ERROR_UNAUTHORIZED",
    "message": "Invalid session token or session expired",
    "payload": {}
    }
    {
    "status": 403,
    "code": "ERROR_FORBIDDEN",
    "message": "Only group admin or owner can copy directories",
    "payload": {}
    }
    {
    "status": 404,
    "code": "ERROR_DIRECTORY_NOT_FOUND",
    "message": "Source directory not found",
    "payload": {}
    }
    {
    "status": 404,
    "code": "ERROR_DESTINATION_NOT_FOUND",
    "message": "Destination directory not found",
    "payload": {}
    }
    {
    "status": 400,
    "code": "ERROR_INVALID_DESTINATION",
    "message": "Invalid destination path",
    "payload": {}
    }
    {
    "status": 507,
    "code": "ERROR_INSUFFICIENT_STORAGE",
    "message": "Insufficient storage space to copy directory",
    "payload": {}
    }
    {
    "status": 500,
    "code": "ERROR_COPY_DIRECTORY_FAILED",
    "message": "Failed to copy directory",
    "payload": {}
    }
    
    14.5 Di chuyển thư mục (chỉ admin/owner)
    Request:
    {
    "command": "MOVE_DIRECTORY",
    "data": {
    "session_token": "abc123xyz",
    "directory_id": 50,
    "destination_path": "/project/archive"
    }
    }
    Response (Thành công):
    {
    "status": 200,
    "code": "SUCCESS_MOVE_DIRECTORY",
    "message": "Directory moved successfully",
    "payload": {
    "directory_id": 50,
    "old_path": "/project/docs/reports",
    "new_path": "/project/archive/reports",
    "affected_files": 5,
    "affected_subdirectories": 2,
    "moved_at": "2025-11-24T11:00:00Z"
    }
    }
    
    Error responses:
    {
    "status": 401,
    "code": "ERROR_UNAUTHORIZED",
    "message": "Invalid session token or session expired",
    "payload": {}
    }
    {
    "status": 403,
    "code": "ERROR_FORBIDDEN",
    "message": "Only group admin or owner can move directories",
    "payload": {}
    }
    {
    "status": 404,
    "code": "ERROR_DIRECTORY_NOT_FOUND",
    "message": "Directory not found",
    "payload": {}
    }
    {
    "status": 404,
    "code": "ERROR_DESTINATION_NOT_FOUND",
    "message": "Destination directory not found",
    "payload": {}
    }
    {
    "status": 400,
    "code": "ERROR_INVALID_DESTINATION",
    "message": "Invalid destination path",
    "payload": {}
    }
    {
    "status": 400,
    "code": "ERROR_CIRCULAR_DEPENDENCY",
    "message": "Cannot move directory to its own subdirectory",
    "payload": {}
    }
    {
    "status": 500,
    "code": "ERROR_MOVE_DIRECTORY_FAILED",
    "message": "Failed to move directory",
    "payload": {}
    }

15. Ghi log hoạt động (1 điểm)
    15.1 Lấy log hoạt động của user
    Request:
    {
    "command": "GET_USER_LOGS",
    "data": {
    "session_token": "abc123xyz",
    "start_date": "2025-11-20T00:00:00Z",
    "end_date": "2025-11-24T23:59:59Z",
    "limit": 50,
    "offset": 0
    }
    }
    Response (Thành công):
    {
    "status": 200,
    "code": "SUCCESS_GET_LOGS",
    "message": "Logs retrieved successfully",
    "payload": {
    "logs": [
    {
    "log_id": 1000,
    "user_id": 1,
    "action": "LOGIN",
    "target_type": null,
    "target_id": null,
    "details": "Logged in from 192.168.102.24",
    "ip_address": "192.168.102.24",
    "created_at": "2025-11-24T10:30:00Z"
    },
    {
    "log_id": 1001,
    "user_id": 1,
    "action": "UPLOAD",
    "target_type": "FILE",
    "target_id": 500,
    "details": "Uploaded document.pdf to /project/docs",
    "ip_address": "192.168.102.24",
    "created_at": "2025-11-24T10:35:00Z"
    }
    ],
    "total_count": 125
    }
    }
    
    Error responses:
    {
    "status": 401,
    "code": "ERROR_UNAUTHORIZED",
    "message": "Invalid session token or session expired",
    "payload": {}
    }
    {
    "status": 400,
    "code": "ERROR_INVALID_DATE_RANGE",
    "message": "Invalid date range or end_date is before start_date",
    "payload": {}
    }
    {
    "status": 400,
    "code": "ERROR_INVALID_PAGINATION",
    "message": "Invalid limit or offset value",
    "payload": {}
    }
    {
    "status": 500,
    "code": "ERROR_GET_LOGS_FAILED",
    "message": "Failed to retrieve user logs",
    "payload": {}
    }
    
    15.2 Lấy log hoạt động của nhóm (admin)
    Request:
    {
    "command": "GET_GROUP_LOGS",
    "data": {
    "session_token": "abc123xyz",
    "group_id": 10,
    "start_date": "2025-11-20T00:00:00Z",
    "end_date": "2025-11-24T23:59:59Z",
    "limit": 50,
    "offset": 0
    }
    }
    Response (Thành công):
    {
    "status": 200,
    "code": "SUCCESS_GET_GROUP_LOGS",
    "message": "Group logs retrieved successfully",
    "payload": {
    "group_id": 10,
    "logs": [
    {
    "log_id": 2000,
    "user_id": 1,
    "username": "user123",
    "action": "CREATE_GROUP",
    "target_type": "GROUP",
    "target_id": 10,
    "details": "Created group Project Team",
    "ip_address": "192.168.102.24",
    "created_at": "2025-11-20T09:00:00Z"
    },
    {
    "log_id": 2001,
    "user_id": 5,
    "username": "user456",
    "action": "JOIN_GROUP",
    "target_type": "GROUP",
    "target_id": 10,
    "details": "Joined group Project Team",
    "ip_address": "192.168.102.25",
    "created_at": "2025-11-20T10:00:00Z"
    }
    ],
    "total_count": 50
    }
    }
    
    Error responses:
    {
    "status": 401,
    "code": "ERROR_UNAUTHORIZED",
    "message": "Invalid session token or session expired",
    "payload": {}
    }
    {
    "status": 403,
    "code": "ERROR_FORBIDDEN",
    "message": "Only group admin or owner can view group logs",
    "payload": {}
    }
    {
    "status": 404,
    "code": "ERROR_GROUP_NOT_FOUND",
    "message": "Group not found",
    "payload": {}
    }
    {
    "status": 400,
    "code": "ERROR_INVALID_DATE_RANGE",
    "message": "Invalid date range or end_date is before start_date",
    "payload": {}
    }
    {
    "status": 400,
    "code": "ERROR_INVALID_PAGINATION",
    "message": "Invalid limit or offset value",
    "payload": {}
    }
    {
    "status": 500,
    "code": "ERROR_GET_GROUP_LOGS_FAILED",
    "message": "Failed to retrieve group logs",
    "payload": {}
    }

## Các mã lỗi chung (Common Error Codes)

Các lỗi này có thể xảy ra với bất kỳ request nào:

{
"status": 400,
"code": "ERROR_INVALID_REQUEST",
"message": "Invalid request format or missing required fields",
"payload": {}
}

{
"status": 400,
"code": "ERROR_MALFORMED_JSON",
"message": "Request body is not valid JSON format",
"payload": {}
}

{
"status": 401,
"code": "ERROR_UNAUTHORIZED",
"message": "Invalid session token or session expired",
"payload": {}
}

{
"status": 403,
"code": "ERROR_FORBIDDEN",
"message": "You don't have permission to perform this action",
"payload": {}
}

{
"status": 404,
"code": "ERROR_NOT_FOUND",
"message": "Resource not found",
"payload": {}
}

{
"status": 409,
"code": "ERROR_CONFLICT",
"message": "Resource already exists or operation conflicts with current state",
"payload": {}
}

{
"status": 413,
"code": "ERROR_REQUEST_ENTITY_TOO_LARGE",
"message": "Request body is too large",
"payload": {}
}

{
"status": 429,
"code": "ERROR_RATE_LIMIT_EXCEEDED",
"message": "Too many requests. Please wait before trying again",
"payload": {"retry_after": 60}
}

{
"status": 500,
"code": "ERROR_INTERNAL_SERVER",
"message": "Internal server error. Please try again later",
"payload": {}
}

{
"status": 502,
"code": "ERROR_BAD_GATEWAY",
"message": "Service temporarily unavailable",
"payload": {}
}

{
"status": 503,
"code": "ERROR_SERVICE_UNAVAILABLE",
"message": "Service is undergoing maintenance",
"payload": {}
}