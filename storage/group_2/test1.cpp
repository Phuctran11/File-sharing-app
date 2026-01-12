#include <iostream>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <nlohmann/json.hpp>
#include <fstream>
#include <vector>
#include <cmath>
#include <iomanip>

#pragma comment(lib, "ws2_32.lib")

using json = nlohmann::json;

class FileShareClient {
private:
    SOCKET sock;
    std::string session_id;
    std::string user_id;
    std::string current_role;
    bool connected;

public:
    FileShareClient() : sock(INVALID_SOCKET), connected(false) {
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            std::cerr << "WSAStartup failed" << std::endl;
            exit(1);
        }
    }

    ~FileShareClient() {
        disconnect();
        WSACleanup();
    }

    bool connectToServer(const std::string& host, int port) {
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == INVALID_SOCKET) {
            std::cerr << "Socket creation failed" << std::endl;
            return false;
        }

        sockaddr_in serverAddr;
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(port);
        inet_pton(AF_INET, host.c_str(), &serverAddr.sin_addr);

        if (connect(sock, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
            std::cerr << "Connection failed" << std::endl;
            closesocket(sock);
            return false;
        }

        connected = true;
        std::cout << "Connected to server!" << std::endl;
        return true;
    }

    void disconnect() {
        if (connected) {
            closesocket(sock);
            connected = false;
        }
    }

    json sendRequest(const json& request) {
        std::string requestStr = request.dump() + "\n";
        
        if (send(sock, requestStr.c_str(), requestStr.length(), 0) == SOCKET_ERROR) {
            std::cerr << "Send failed" << std::endl;
            return {{"success", false}, {"message", "Send failed"}};
        }

        char buffer[65536];
        int bytesReceived = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (bytesReceived <= 0) {
            std::cerr << "Receive failed" << std::endl;
            return {{"success", false}, {"message", "Receive failed"}};
        }

        buffer[bytesReceived] = '\0';
        return json::parse(buffer);
    }

    // ========== AUTHENTICATION ==========
    bool registerUser(const std::string& username, const std::string& email, const std::string& password) {
        json request = {
            {"action", "register"},
            {"username", username},
            {"email", email},
            {"password", password}
        };

        json response = sendRequest(request);
        std::cout << "Response: " << response.dump(2) << std::endl;
        return response["success"];
    }

    bool login(const std::string& username, const std::string& password) {
        json request = {
            {"action", "login"},
            {"username", username},
            {"password", password}
        };

        json response = sendRequest(request);
        std::cout << "Response: " << response.dump(2) << std::endl;
        
        if (response["success"]) {
            session_id = response["session_id"];
            user_id = response["user_id"];
            current_role = response["role"];
            return true;
        }
        return false;
    }

    void logout() {
        json request = {
            {"action", "logout"},
            {"session_id", session_id}
        };

        json response = sendRequest(request);
        std::cout << "Response: " << response.dump(2) << std::endl;
        
        if (response["success"]) {
            session_id.clear();
            user_id.clear();
            current_role.clear();
        }
    }

    void getUserInfo() {
        json request = {
            {"action", "get_user_info"},
            {"session_id", session_id}
        };

        json response = sendRequest(request);
        std::cout << "User Info: " << response.dump(2) << std::endl;
    }

    void updateUser(const std::string& email, const std::string& newPassword) {
        json request = {
            {"action", "update_user"},
            {"session_id", session_id}
        };

        if (!email.empty()) request["email"] = email;
        if (!newPassword.empty()) request["password"] = newPassword;

        json response = sendRequest(request);
        std::cout << "Response: " << response.dump(2) << std::endl;
    }

    // ========== GROUP MANAGEMENT ==========
    std::string createGroup(const std::string& groupName) {
        json request = {
            {"action", "create_group"},
            {"session_id", session_id},
            {"group_name", groupName}
        };

        json response = sendRequest(request);
        std::cout << "Response: " << response.dump(2) << std::endl;
        
        if (response["success"]) {
            return response["group_id"];
        }
        return "";
    }

    void listGroups() {
        json request = {
            {"action", "list_groups"},
            {"session_id", session_id}
        };

        json response = sendRequest(request);
        std::cout << "Groups: " << response.dump(2) << std::endl;
    }

    void getGroupInfo(const std::string& groupId) {
        json request = {
            {"action", "get_group_info"},
            {"session_id", session_id},
            {"group_id", groupId}
        };

        json response = sendRequest(request);
        std::cout << "Group Info: " << response.dump(2) << std::endl;
    }

    void listGroupMembers(const std::string& groupId) {
        json request = {
            {"action", "list_group_members"},
            {"session_id", session_id},
            {"group_id", groupId}
        };

        json response = sendRequest(request);
        std::cout << "Members: " << response.dump(2) << std::endl;
    }

    void requestJoinGroup(const std::string& groupId) {
        json request = {
            {"action", "request_join_group"},
            {"session_id", session_id},
            {"group_id", groupId}
        };

        json response = sendRequest(request);
        std::cout << "Response: " << response.dump(2) << std::endl;
    }

    void approveJoinRequest(const std::string& groupId, const std::string& userId) {
        json request = {
            {"action", "approve_join_request"},
            {"session_id", session_id},
            {"group_id", groupId},
            {"user_id", userId}
        };

        json response = sendRequest(request);
        std::cout << "Response: " << response.dump(2) << std::endl;
    }

    void rejectJoinRequest(const std::string& groupId, const std::string& userId) {
        json request = {
            {"action", "reject_join_request"},
            {"session_id", session_id},
            {"group_id", groupId},
            {"user_id", userId}
        };

        json response = sendRequest(request);
        std::cout << "Response: " << response.dump(2) << std::endl;
    }

    void inviteToGroup(const std::string& groupId, const std::string& username) {
        json request = {
            {"action", "invite_to_group"},
            {"session_id", session_id},
            {"group_id", groupId},
            {"username", username}
        };

        json response = sendRequest(request);
        std::cout << "Response: " << response.dump(2) << std::endl;
    }

    void acceptInvite(const std::string& groupId) {
        json request = {
            {"action", "accept_invite"},
            {"session_id", session_id},
            {"group_id", groupId}
        };

        json response = sendRequest(request);
        std::cout << "Response: " << response.dump(2) << std::endl;
    }

    void rejectInvite(const std::string& groupId) {
        json request = {
            {"action", "reject_invite"},
            {"session_id", session_id},
            {"group_id", groupId}
        };

        json response = sendRequest(request);
        std::cout << "Response: " << response.dump(2) << std::endl;
    }

    void leaveGroup(const std::string& groupId) {
        json request = {
            {"action", "leave_group"},
            {"session_id", session_id},
            {"group_id", groupId}
        };

        json response = sendRequest(request);
        std::cout << "Response: " << response.dump(2) << std::endl;
    }

    void removeMember(const std::string& groupId, const std::string& userId) {
        json request = {
            {"action", "remove_member"},
            {"session_id", session_id},
            {"group_id", groupId},
            {"user_id", userId}
        };

        json response = sendRequest(request);
        std::cout << "Response: " << response.dump(2) << std::endl;
    }

    // ========== FOLDER OPERATIONS ==========
    std::string createFolder(const std::string& groupId, const std::string& parentId, const std::string& folderName) {
        json request = {
            {"action", "create_folder"},
            {"session_id", session_id},
            {"group_id", groupId},
            {"folder_name", folderName}
        };

        if (!parentId.empty()) {
            request["parent_id"] = parentId;
        }

        json response = sendRequest(request);
        std::cout << "Response: " << response.dump(2) << std::endl;
        
        if (response["success"]) {
            return response["folder_id"];
        }
        return "";
    }

    void listFolderContent(const std::string& folderId) {
        json request = {
            {"action", "list_folder_content"},
            {"session_id", session_id},
            {"folder_id", folderId}
        };

        json response = sendRequest(request);
        std::cout << "Folder Content: " << response.dump(2) << std::endl;
    }

    void renameFolder(const std::string& folderId, const std::string& newName) {
        json request = {
            {"action", "rename_folder"},
            {"session_id", session_id},
            {"folder_id", folderId},
            {"new_name", newName}
        };

        json response = sendRequest(request);
        std::cout << "Response: " << response.dump(2) << std::endl;
    }

    void deleteFolder(const std::string& folderId) {
        json request = {
            {"action", "delete_folder"},
            {"session_id", session_id},
            {"folder_id", folderId}
        };

        json response = sendRequest(request);
        std::cout << "Response: " << response.dump(2) << std::endl;
    }

    void copyFolder(const std::string& folderId, const std::string& targetFolderId) {
        json request = {
            {"action", "copy_folder"},
            {"session_id", session_id},
            {"folder_id", folderId},
            {"target_folder_id", targetFolderId}
        };

        json response = sendRequest(request);
        std::cout << "Response: " << response.dump(2) << std::endl;
    }

    void moveFolder(const std::string& folderId, const std::string& targetFolderId) {
        json request = {
            {"action", "move_folder"},
            {"session_id", session_id},
            {"folder_id", folderId},
            {"target_folder_id", targetFolderId}
        };

        json response = sendRequest(request);
        std::cout << "Response: " << response.dump(2) << std::endl;
    }

    // ========== FILE OPERATIONS ==========
    bool uploadFile(const std::string& groupId, const std::string& folderId, std::string filePath) {
        // Remove quotes if present
        if (filePath.length() >= 2 && filePath.front() == '"' && filePath.back() == '"') {
            filePath = filePath.substr(1, filePath.length() - 2);
        }

        std::ifstream file(filePath, std::ios::binary);
        if (!file) {
            std::cerr << "Cannot open file: " << filePath << std::endl;
            return false;
        }

        // Get file size
        file.seekg(0, std::ios::end);
        size_t fileSize = file.tellg();
        file.seekg(0, std::ios::beg);

        // Extract filename
        std::string fileName = filePath.substr(filePath.find_last_of("/\\") + 1);

        // Step 1: Initialize upload
        json initRequest = {
            {"action", "upload_file"},
            {"session_id", session_id},
            {"group_id", groupId},
            {"folder_id", folderId},
            {"file_name", fileName},
            {"upload_mode", "init"},
            {"file_size", fileSize},
            {"mime_type", "application/octet-stream"}
        };

        json response = sendRequest(initRequest);
        std::cout << "Init Response: " << response.dump(2) << std::endl;

        if (!response["success"]) {
            return false;
        }

        std::string fileId = response["file_id"];

        // Step 2: Upload chunks
        const size_t CHUNK_SIZE = 1048576; // 1MB
        std::vector<char> buffer(CHUNK_SIZE);
        int chunkIndex = 0;
        size_t totalUploaded = 0;

        while (file.read(buffer.data(), CHUNK_SIZE) || file.gcount() > 0) {
            size_t bytesRead = file.gcount();
            totalUploaded += bytesRead;
            
            // Base64 encode
            std::string base64Data = base64Encode(buffer.data(), bytesRead);

            json chunkRequest = {
                {"action", "upload_file"},
                {"session_id", session_id},
                {"upload_mode", "chunk"},
                {"file_id", fileId},
                {"chunk_index", chunkIndex},
                {"data", base64Data}
            };

            response = sendRequest(chunkRequest);
            
            double progress = (double)totalUploaded / fileSize * 100;
            std::cout << "Chunk " << chunkIndex << " uploaded (" 
                      << std::fixed << std::setprecision(2) << progress << "%)" << std::endl;

            if (!response["success"]) {
                return false;
            }

            chunkIndex++;
        }

        // Step 3: Complete upload
        json completeRequest = {
            {"action", "upload_file"},
            {"session_id", session_id},
            {"upload_mode", "complete"},
            {"file_id", fileId}
        };

        response = sendRequest(completeRequest);
        std::cout << "Complete Response: " << response.dump(2) << std::endl;

        return response["success"];
    }

    bool downloadFile(const std::string& fileId, const std::string& savePath) {
        // Step 1: Get file info
        json infoRequest = {
            {"action", "download_file"},
            {"session_id", session_id},
            {"file_id", fileId},
            {"download_mode", "info"}
        };

        json response = sendRequest(infoRequest);
        std::cout << "File Info: " << response.dump(2) << std::endl;

        if (!response["success"]) {
            return false;
        }

        size_t fileSize = response["file_size"];
        std::string fileName = response["file_name"];

        // Open output file
        std::ofstream outFile(savePath, std::ios::binary);
        if (!outFile) {
            std::cerr << "Cannot create file: " << savePath << std::endl;
            return false;
        }

        // Step 2: Download chunks
        const size_t CHUNK_SIZE = 1048576; // 1MB
        size_t offset = 0;
        size_t totalDownloaded = 0;

        while (offset < fileSize) {
            size_t chunkSize = std::min(CHUNK_SIZE, fileSize - offset);

            json chunkRequest = {
                {"action", "download_file"},
                {"session_id", session_id},
                {"file_id", fileId},
                {"download_mode", "chunk"},
                {"offset", offset},
                {"size", chunkSize}
            };

            response = sendRequest(chunkRequest);

            if (!response["success"]) {
                outFile.close();
                return false;
            }

            // Decode base64 data
            std::string base64Data = response["data"];
            std::vector<unsigned char> decodedData = base64Decode(base64Data);

            outFile.write(reinterpret_cast<char*>(decodedData.data()), decodedData.size());

            totalDownloaded += decodedData.size();
            offset += chunkSize;

            double progress = (double)totalDownloaded / fileSize * 100;
            std::cout << "Downloaded: " << std::fixed << std::setprecision(2) 
                      << progress << "%" << std::endl;
        }

        outFile.close();
        std::cout << "File downloaded successfully: " << savePath << std::endl;
        return true;
    }

    void listFiles(const std::string& groupId) {
        json request = {
            {"action", "list_files"},
            {"session_id", session_id},
            {"group_id", groupId}
        };

        json response = sendRequest(request);
        std::cout << "Files: " << response.dump(2) << std::endl;
    }

    void renameFile(const std::string& fileId, const std::string& newName) {
        json request = {
            {"action", "rename_file"},
            {"session_id", session_id},
            {"file_id", fileId},
            {"new_name", newName}
        };

        json response = sendRequest(request);
        std::cout << "Response: " << response.dump(2) << std::endl;
    }

    void deleteFile(const std::string& fileId) {
        json request = {
            {"action", "delete_file"},
            {"session_id", session_id},
            {"file_id", fileId}
        };

        json response = sendRequest(request);
        std::cout << "Response: " << response.dump(2) << std::endl;
    }

    void copyFile(const std::string& fileId, const std::string& targetFolderId) {
        json request = {
            {"action", "copy_file"},
            {"session_id", session_id},
            {"file_id", fileId},
            {"target_folder_id", targetFolderId}
        };

        json response = sendRequest(request);
        std::cout << "Response: " << response.dump(2) << std::endl;
    }

    void moveFile(const std::string& fileId, const std::string& targetFolderId) {
        json request = {
            {"action", "move_file"},
            {"session_id", session_id},
            {"file_id", fileId},
            {"target_folder_id", targetFolderId}
        };

        json response = sendRequest(request);
        std::cout << "Response: " << response.dump(2) << std::endl;
    }

    bool isLoggedIn() const {
        return !session_id.empty();
    }

private:
    std::string base64Encode(const char* data, size_t len) {
        static const char* base64_chars = 
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz"
            "0123456789+/";

        std::string ret;
        int i = 0;
        unsigned char char_array_3[3];
        unsigned char char_array_4[4];

        while (len--) {
            char_array_3[i++] = *(data++);
            if (i == 3) {
                char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
                char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
                char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
                char_array_4[3] = char_array_3[2] & 0x3f;

                for(i = 0; i < 4; i++)
                    ret += base64_chars[char_array_4[i]];
                i = 0;
            }
        }

        if (i) {
            for(int j = i; j < 3; j++)
                char_array_3[j] = '\0';

            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);

            for (int j = 0; j < i + 1; j++)
                ret += base64_chars[char_array_4[j]];

            while(i++ < 3)
                ret += '=';
        }

        return ret;
    }

    std::vector<unsigned char> base64Decode(const std::string& encoded_string) {
        static const std::string base64_chars = 
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz"
            "0123456789+/";

        int in_len = encoded_string.size();
        int i = 0;
        int j = 0;
        int in_ = 0;
        unsigned char char_array_4[4], char_array_3[3];
        std::vector<unsigned char> ret;

        while (in_len-- && (encoded_string[in_] != '=') && 
               (isalnum(encoded_string[in_]) || (encoded_string[in_] == '+') || (encoded_string[in_] == '/'))) {
            char_array_4[i++] = encoded_string[in_]; in_++;
            if (i == 4) {
                for (i = 0; i < 4; i++)
                    char_array_4[i] = base64_chars.find(char_array_4[i]);

                char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
                char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
                char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

                for (i = 0; i < 3; i++)
                    ret.push_back(char_array_3[i]);
                i = 0;
            }
        }

        if (i) {
            for (j = 0; j < i; j++)
                char_array_4[j] = base64_chars.find(char_array_4[j]);

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);

            for (j = 0; j < i - 1; j++)
                ret.push_back(char_array_3[j]);
        }

        return ret;
    }
};

void showMainMenu() {
    std::cout << "\n========== FILE SHARE CLIENT ==========\n";
    std::cout << "1.  Register\n";
    std::cout << "2.  Login\n";
    std::cout << "3.  Logout\n";
    std::cout << "4.  Get User Info\n";
    std::cout << "5.  Update User\n";
    std::cout << "6.  Create Group\n";
    std::cout << "7.  List Groups\n";
    std::cout << "8.  Get Group Info\n";
    std::cout << "9.  List Group Members\n";
    std::cout << "10. Request Join Group\n";
    std::cout << "11. Approve Join Request\n";
    std::cout << "12. Reject Join Request\n";
    std::cout << "13. Invite to Group\n";
    std::cout << "14. Accept Invite\n";
    std::cout << "15. Reject Invite\n";
    std::cout << "16. Leave Group\n";
    std::cout << "17. Remove Member\n";
    std::cout << "18. Create Folder\n";
    std::cout << "19. List Folder Content\n";
    std::cout << "20. Rename Folder\n";
    std::cout << "21. Delete Folder\n";
    std::cout << "22. Copy Folder\n";
    std::cout << "23. Move Folder\n";
    std::cout << "24. Upload File\n";
    std::cout << "25. Download File\n";
    std::cout << "26. List Files\n";
    std::cout << "27. Rename File\n";
    std::cout << "28. Delete File\n";
    std::cout << "29. Copy File\n";
    std::cout << "30. Move File\n";
    std::cout << "0.  Exit\n";
    std::cout << "=======================================\n";
    std::cout << "Choice: ";
}

int main() {
    FileShareClient client;

    std::string host;
    int port;
    
    std::cout << "Enter server IP (default: 192.168.56.101): ";
    std::getline(std::cin, host);
    if (host.empty()) host = "192.168.56.101";
    
    std::cout << "Enter server port (default: 8080): ";
    std::string portStr;
    std::getline(std::cin, portStr);
    port = portStr.empty() ? 8080 : std::stoi(portStr);

    if (!client.connectToServer(host, port)) {
        return 1;
    }

    int choice;
    std::string username, password, email, groupName, groupId, folderId, 
                filePath, userId, newName, targetId, fileId, savePath, folderName;

    while (true) {
        showMainMenu();
        std::cin >> choice;
        std::cin.ignore();

        switch (choice) {
            case 1: // Register
                std::cout << "Username: "; std::getline(std::cin, username);
                std::cout << "Email: "; std::getline(std::cin, email);
                std::cout << "Password: "; std::getline(std::cin, password);
                client.registerUser(username, email, password);
                break;

            case 2: // Login
                std::cout << "Username: "; std::getline(std::cin, username);
                std::cout << "Password: "; std::getline(std::cin, password);
                client.login(username, password);
                break;

            case 3: // Logout
                client.logout();
                break;

            case 4: // Get User Info
                client.getUserInfo();
                break;

            case 5: // Update User
                std::cout << "New Email (leave empty to skip): "; std::getline(std::cin, email);
                std::cout << "New Password (leave empty to skip): "; std::getline(std::cin, password);
                client.updateUser(email, password);
                break;

            case 6: // Create Group
                std::cout << "Group Name: "; std::getline(std::cin, groupName);
                client.createGroup(groupName);
                break;

            case 7: // List Groups
                client.listGroups();
                break;

            case 8: // Get Group Info
                std::cout << "Group ID: "; std::getline(std::cin, groupId);
                client.getGroupInfo(groupId);
                break;

            case 9: // List Group Members
                std::cout << "Group ID: "; std::getline(std::cin, groupId);
                client.listGroupMembers(groupId);
                break;

            case 10: // Request Join Group
                std::cout << "Group ID: "; std::getline(std::cin, groupId);
                client.requestJoinGroup(groupId);
                break;

            case 11: // Approve Join Request
                std::cout << "Group ID: "; std::getline(std::cin, groupId);
                std::cout << "User ID: "; std::getline(std::cin, userId);
                client.approveJoinRequest(groupId, userId);
                break;

            case 12: // Reject Join Request
                std::cout << "Group ID: "; std::getline(std::cin, groupId);
                std::cout << "User ID: "; std::getline(std::cin, userId);
                client.rejectJoinRequest(groupId, userId);
                break;

            case 13: // Invite to Group
                std::cout << "Group ID: "; std::getline(std::cin, groupId);
                std::cout << "Username to invite: "; std::getline(std::cin, username);
                client.inviteToGroup(groupId, username);
                break;

            case 14: // Accept Invite
                std::cout << "Group ID: "; std::getline(std::cin, groupId);
                client.acceptInvite(groupId);
                break;

            case 15: // Reject Invite
                std::cout << "Group ID: "; std::getline(std::cin, groupId);
                client.rejectInvite(groupId);
                break;

            case 16: // Leave Group
                std::cout << "Group ID: "; std::getline(std::cin, groupId);
                client.leaveGroup(groupId);
                break;

            case 17: // Remove Member
                std::cout << "Group ID: "; std::getline(std::cin, groupId);
                std::cout << "User ID: "; std::getline(std::cin, userId);
                client.removeMember(groupId, userId);
                break;

            case 18: // Create Folder
                std::cout << "Group ID: "; std::getline(std::cin, groupId);
                std::cout << "Parent Folder ID (leave empty for root): "; std::getline(std::cin, folderId);
                std::cout << "Folder Name: "; std::getline(std::cin, folderName);
                client.createFolder(groupId, folderId, folderName);
                break;

            case 19: // List Folder Content
                std::cout << "Folder ID: "; std::getline(std::cin, folderId);
                client.listFolderContent(folderId);
                break;

            case 20: // Rename Folder
                std::cout << "Folder ID: "; std::getline(std::cin, folderId);
                std::cout << "New Name: "; std::getline(std::cin, newName);
                client.renameFolder(folderId, newName);
                break;

            case 21: // Delete Folder
                std::cout << "Folder ID: "; std::getline(std::cin, folderId);
                client.deleteFolder(folderId);
                break;

            case 22: // Copy Folder
                std::cout << "Folder ID: "; std::getline(std::cin, folderId);
                std::cout << "Target Folder ID: "; std::getline(std::cin, targetId);
                client.copyFolder(folderId, targetId);
                break;

            case 23: // Move Folder
                std::cout << "Folder ID: "; std::getline(std::cin, folderId);
                std::cout << "Target Folder ID: "; std::getline(std::cin, targetId);
                client.moveFolder(folderId, targetId);
                break;

            case 24: // Upload File
                std::cout << "Group ID: "; std::getline(std::cin, groupId);
                std::cout << "Folder ID: "; std::getline(std::cin, folderId);
                std::cout << "File Path: "; std::getline(std::cin, filePath);
                client.uploadFile(groupId, folderId, filePath);
                break;

            case 25: // Download File
                std::cout << "File ID: "; std::getline(std::cin, fileId);
                std::cout << "Save to Path: "; std::getline(std::cin, savePath);
                client.downloadFile(fileId, savePath);
                break;

            case 26: // List Files
                std::cout << "Group ID: "; std::getline(std::cin, groupId);
                client.listFiles(groupId);
                break;

            case 27: // Rename File
                std::cout << "File ID: "; std::getline(std::cin, fileId);
                std::cout << "New Name: "; std::getline(std::cin, newName);
                client.renameFile(fileId, newName);
                break;

            case 28: // Delete File
                std::cout << "File ID: "; std::getline(std::cin, fileId);
                client.deleteFile(fileId);
                break;

            case 29: // Copy File
                std::cout << "File ID: "; std::getline(std::cin, fileId);
                std::cout << "Target Folder ID: "; std::getline(std::cin, targetId);
                client.copyFile(fileId, targetId);
                break;

            case 30: // Move File
                std::cout << "File ID: "; std::getline(std::cin, fileId);
                std::cout << "Target Folder ID: "; std::getline(std::cin, targetId);
                client.moveFile(fileId, targetId);
                break;

            case 0: // Exit
                std::cout << "Goodbye!" << std::endl;
                return 0;

            default:
                std::cout << "Invalid choice!" << std::endl;
        }
    }

    return 0;
}