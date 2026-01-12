Project: Laptrinhmang-BTL (version1)
=====================================

Overview
--------
This is a C-based file-sharing server and client project. The server uses PostgreSQL for metadata (users, groups, directories, files) and the filesystem for file storage. The client is a simple command-line program that communicates with the server over sockets using JSON messages.

Key features
------------
- User authentication (register, login, session)
- Group management (create, join, members, roles)
- Directory management: create, rename, delete, copy, move, list
- File management: upload (chunked), download, rename, delete, copy, move
- Permissions: group members and admins; per-group permission checks
- Activity logging and notifications

Repository layout (important files and folders)
-----------------------------------------------
- `database.sql` — SQL schema for PostgreSQL (tables: users, groups, directories, files, permissions, etc.)
- `server/` — server source code and Makefile
  - `server.c` — main server loop and request dispatcher
  - `auth_handler.c`, `file_handler.c`, `folder_handler.c`, `database.c` — handlers & DB layer
  - `Makefile` — build server binary
- `client/` — client source code and Makefile
  - `client.c` — CLI client that sends JSON commands to server
  - `Makefile` — build client binary
- `common/` — shared headers/utilities (e.g., protocol definitions)
- `storage/` — sample filesystem layout used for file storage during development
- `ban-tin.md` — specification & API examples (requests and responses)

Dependencies
------------
- C compiler (gcc)
- libpq (PostgreSQL C client library) and headers (e.g., `libpq-dev`)
- json-c development library (e.g., `libjson-c-dev`)
- OpenSSL (for hashing/token helpers)
- make

Recommended Ubuntu install (example):

```bash
sudo apt update
sudo apt install -y build-essential libpq-dev libjson-c-dev libssl-dev make postgresql
```

Database setup
--------------
1. Create a PostgreSQL database and user (adjust names and password):

```bash
sudo -u postgres psql
CREATE DATABASE file_share_db;
CREATE USER fs_user WITH PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE file_share_db TO fs_user;
\q
```

2. Import schema:

```bash
psql -U fs_user -d file_share_db -f database.sql
```

3. Edit DB connection settings (if needed): open `server/database.c` and adjust `conninfo` (host, dbname, user, password).

Configuration
-------------
- `STORAGE_BASE_PATH` is defined in `server/file_handler.c` and `server/folder_handler.c` as the root filesystem path used for file storage. Update those defines to point to the desired storage directory on your machine (or centralize this define if you prefer).

Build
-----
Build the server and client using their Makefiles.

```bash
cd version1/server
make
# run server (may require sudo depending on port)
./server

# in another terminal, build client
cd version1/client
make
./client
```

Running & Testing
-----------------
- Start PostgreSQL and ensure the schema is loaded.
- Start `./server` from `version1/server`.
- Run `./client` and try commands described in `ban-tin.md` such as:
  - `REGISTER` / `LOGIN`
  - `LIST_DIRECTORY` / `CREATE_DIRECTORY`
  - `UPLOAD_FILE` (start, chunk, complete)
  - `RENAME_FILE`, `MOVE_FILE`, `DELETE_FILE`
  - Directory copy/move operations

Notes & recent fixes (important)
--------------------------------
- `db_move_directory` has been updated to also modify `parent_path` and update subdirectories and files recursively so that `LIST_DIRECTORY` reflects moves correctly.
- Directory copy logic in `server/folder_handler.c` uses `mkdir -p` and `cp -r "source/." "dest/"` to ensure directories with spaces copy correctly on Linux and to copy directory contents into the target directory created by the DB operation.
- Member upload permissions: `server/file_handler.c` has been adjusted so group members may upload files (previous code incorrectly blocked members using a `can_write` gate). Owners (uploader) and group admins can rename/move/delete files.
- `db_move_file` now updates both `file_path` and `parent_directory` in the database so that moved files appear under the new parent when listing.

Troubleshooting
---------------
- If login fails with "Failed to create session", check DB connectivity and confirm `db_create_session` works and `conninfo` credentials are correct.
- Ensure `STORAGE_BASE_PATH` exists and the server process has read/write permissions for the storage folder (server uses `mkdir -p` in code to create directories).
- On Ubuntu, the `cp` and `mkdir` calls work as expected. If you run on a different OS, adjust commands accordingly.

Extending / Next steps
----------------------
- Centralize configuration: move `STORAGE_BASE_PATH`, DB conninfo, and other constants into a single config header or config file.
- Add unit or integration tests for key operations (file upload, move, copy, rename).
- Add safer handling for system commands (avoid `system()` with user-controlled input; use direct APIs or sanitize inputs).

