CC = gcc
CFLAGS = -Wall -pthread -I/usr/include/postgresql
LDFLAGS = -lpq -ljson-c -lssl -lcrypto -luuid

TARGET = server
OBJS = server.o auth_handler.o permission_handler.o group_handler.o folder_handler.o file_handler.o database.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)

server.o: server.c
	$(CC) $(CFLAGS) -c server.c

auth_handler.o: auth_handler.c
	$(CC) $(CFLAGS) -c auth_handler.c

permission_handler.o: permission_handler.c
	$(CC) $(CFLAGS) -c permission_handler.c

group_handler.o: group_handler.c
	$(CC) $(CFLAGS) -c group_handler.c

database.o: database.c
	$(CC) $(CFLAGS) -c database.c

folder_handler.o: folder_handler.c
	$(CC) $(CFLAGS) -c folder_handler.c

file_handler.o: file_handler.c
	$(CC) $(CFLAGS) -c file_handler.c

clean:
	rm -f $(TARGET) $(OBJS)
