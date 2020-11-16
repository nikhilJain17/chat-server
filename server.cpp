#include <iostream>
#include <stdio.h> 
#include <netdb.h> 
#include <netinet/in.h> 
#include <stdlib.h> 
#include <string> 
#include <string.h> 
#include <sys/socket.h> 
#include <sys/types.h> 
#include <unistd.h>
#include <vector>
#include <map>
#include <pthread.h>

#define MAX 20000 
#define MAX_ROOM_NAME 256
#define MAX_USER_LEN 256
#define SA struct sockaddr 

struct Client {
    std::string username;
    std::string room;
    int socket;

};

std::map<std::string, std::vector<Client *> * > rooms;
// std::vector<Client *> clients;

bool validate_join_instr(char* instr, int length, char* room, char* username) {

    printf("Validating: %s", instr);

    // "join"
    char* curr_tok = strtok(instr, " ");

    if (strncmp("join", instr, 4) != 0) {
        return false;
    }

    // <room>
    curr_tok = strtok(NULL, " ");
    if (curr_tok == NULL) {
        printf("no room?");
        return false;
    }

    strlcpy(room, curr_tok, MAX_ROOM_NAME);
    printf(">%s\n", room);

    // <username>
    curr_tok = strtok(NULL, " ");
    if (curr_tok == NULL) {
        printf("no username?");
        return false;
    }

    strlcpy(username, curr_tok, MAX_ROOM_NAME);
    strlcpy(username, username, strlen(username) - 1);
    strcat(username, "\0");

    printf(">%s\n", username);

    // nothing else should be present
    curr_tok = strtok(NULL, " ");
    if (curr_tok != NULL) {
        printf("%s", curr_tok);
        printf("Nothing else should be present %s", curr_tok);
        return false;
    }
    
    return true;
}

// Send all data from buffer to socket
bool send_msg(int socket, char* buffer, size_t length) {
    char* ptr = buffer;
    while (length > 0) {
        int i = send(socket, ptr, length, 0);
        if (i < 1) return false;
        ptr += i;
        length -= i; 
    }
    return true;
}

// Given a msg and a list of clients, send the msg to the clients.
void broadcast_to_room(std::vector<Client*>* clients, std::string msg) {
    for (int i = 0; i < clients->size(); i++) {
        bool status = send_msg((*clients)[i]->socket, (char *) msg.c_str(), strnlen(msg.c_str(), MAX));  
        if (status == false) {
            printf("Error sending to client\n");
        }
    }
}

// Function designed for chat between client and server. 
void *client_loop(void *sockarg) 
{ 
    int sockfd = *((int *) sockarg);
	char* buff = (char*) malloc(MAX); 
	int n; 

    // Validate JOIN command
    memset(buff, 0, MAX);
    read(sockfd, buff, MAX);

    printf("buff: %s\n", buff);

    char* roomname = (char *) calloc(1, MAX_ROOM_NAME);
    char* username = (char *) calloc(1, MAX_USER_LEN);

    if (!validate_join_instr(buff, strnlen(buff, MAX), roomname, username)) {
        char RESPONSE[] = "ERROR\n";
        std::cout << "Invalid join command" << ": "<< sockfd;
        write(sockfd, &RESPONSE, strnlen(RESPONSE, 30));
        free(buff);
        return NULL;
    }

    // Create user (and room if necessary).
    printf("User %s is joining room %s\n", username, roomname);
    Client *c = new Client();
    c->username = username;
    c->room = roomname;
    c->socket = sockfd;

    if (rooms.find(roomname) == rooms.end()) {
        std::vector<Client *> * new_room = new std::vector<Client*>;
        rooms.insert(std::pair<std::string, std::vector<Client*>*>(roomname, new_room));
    }
    std::vector<Client *>* clients = rooms.at(roomname) ;    
    clients->push_back(c);

	// Chat loop 
	while (true) { 

        // Read in msg
        memset(buff, 0, MAX);
		int status = read(sockfd, buff, MAX); 
        if (status == 0) {
            // Disconnected
            break;
        }

        // Format msg
		std::string msg = c->username;
        std::string buffstr(buff);
        msg += ": ";
        msg += buffstr;

        // Broadcast msg
        printf("[msg] %s", msg.c_str());
        broadcast_to_room(clients, msg);
        
    } 

    
    // Client is leaving room
    int index_to_remove = -1;
    for (int i = 0; i < clients->size(); i++) {
        if ((*clients)[i]->username == c->username) {
            index_to_remove = i;
            break;
        } 
    }
    clients->erase(clients->begin() + index_to_remove);

    std::string left_room_msg = c->username + " has left the room.\n";
    broadcast_to_room(clients, left_room_msg);
    
    // Clean up memory, deleting room if needed.
    delete(c);
    free(buff);
    if (clients->size() == 0) {
        delete(clients);
        rooms.erase(roomname);
    }

    return NULL;
} 

// Driver function 
int main(int argc, char* argv[]) 
{ 
    // Validate port.
    int PORT;
    if (argc == 1) {
        PORT = 1234;
    } 
    else if (argc > 2) {
        printf("Usage: ./server [port]\n");
        return -1;
    }
    else {
        PORT = atoi(argv[1]);
        if ((PORT < 0) || (PORT > 65535)) {
            printf("Invalid tcp port. Must be between 0-65535.\n");
            return -1;
        }
    }
    printf("Port: %d\n", PORT);

	int sockfd, connfd; 
    socklen_t len;
	struct sockaddr_in servaddr, cli; 

	// Socket create and verification 
	sockfd = socket(AF_INET, SOCK_STREAM, 0); 
	if (sockfd == -1) { 
		printf("Couldn't create socket. \n"); 
		return -1; 
	} 

	bzero(&servaddr, sizeof(servaddr)); 

	// Assign IP, PORT 
	servaddr.sin_family = AF_INET; 
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY); 
	servaddr.sin_port = htons(PORT); 

	// Bind newly created socket to given IP and verification 
	if ((bind(sockfd, (SA*)&servaddr, sizeof(servaddr))) != 0) { 
		printf("Couldn't bind socket.\n"); 
		return -2; 
	} 
	else
		printf("Socket successfully binded.\n"); 

	// Now server is ready to listen and verification 
	if ((listen(sockfd, 100)) != 0) { 
		printf("Couldn't listen on socket.\n"); 
		return -2;
	} 
	else {
        // Accept clients in new threads.
        std::vector<Client*> clients;
        pthread_t pids[100];
        int curr_pid = 0;

		while (true)
        {
            printf("Server is listening.\n"); 
            len = sizeof(cli); 

            connfd = accept(sockfd, (SA*)&cli, &len); 
            if (connfd < 0) { 
                printf("Server couldn't get packet from client.\n"); 
                return -3; 
            } 

            pthread_create(&(pids[curr_pid++]), NULL, client_loop, (void*) &connfd);
            if (curr_pid >= 80) {
                curr_pid = 0;
                while (curr_pid <= 80) {
                    pthread_join(pids[curr_pid++], NULL);
                }
                curr_pid = 0;
            }

        }
    }

	// After chatting, close the server socket.
	close(sockfd); 
} 

