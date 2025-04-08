#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MAX 10
#define IP "127.0.0.1"
#define PORT 6000
#define AES_KEY_SIZE 32
#define BUFFER_SIZE 1024
#define USERNAME_SIZE 30 * sizeof(char)

typedef struct {
    int fd;
    char username[USERNAME_SIZE];
} Client_t;

int nClients = 0;
Client_t active_clients[MAX];
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

void* broadcast(char* buffer, int fd) {
    printf("%s Lenght: %ld\n", buffer, strlen(buffer)); // debug line

    for (int i = 0; i < nClients; i++) {
        if (active_clients[i].fd == fd)
            continue;
        
        if (write(active_clients[i].fd, buffer, strlen(buffer)) < 0) {
            printf("[!] Error sending message to %s\n", active_clients[i].username);
            continue;
        }
    }
    
    return NULL;
}

void* unicast(char* buffer, const char* user) {
    printf("%s\n", buffer); // debug line
    
    for (int i = 0; i < nClients; i++) {
        if (strncmp(active_clients[i].username, user, USERNAME_SIZE))
            continue;
        
        if (write(active_clients[i].fd, buffer, strlen(buffer)) == -1) 
            printf("[!] Error sending message to %s\n", active_clients[i].username);
        
        break;
    }

    return NULL;
}

void* remove_user(int idx) {
    char buffer[100];
    snprintf(buffer, sizeof(buffer), "<SERVER> %s left the chat", active_clients[idx].username);
    
    pthread_mutex_lock(&mutex);
   
    for (int i = idx; i < nClients; i++) {
        if ((i + 1) < nClients) {
            active_clients[i].fd = active_clients[i + 1].fd;
            memset(active_clients[i].username, 0, USERNAME_SIZE);
            strncpy(active_clients[i].username, active_clients[i+1].username, USERNAME_SIZE);
        }
    }
    
    nClients--;
    pthread_mutex_unlock(&mutex);
      
    broadcast(buffer, -1);
    memset(buffer, 0, sizeof(buffer));
    return NULL;
}

void disconnect(int signum) {
    for (int i = 0; i < nClients; i++)
        close(active_clients[i].fd);
    
    printf("\n[+] Gracefully closed all the processes\n");
    signum = signum + 1 - 1;
    exit(EXIT_SUCCESS);
}

void send_msg(char* buffer) {
    int space = (int) strcspn(buffer, " ");
    int len = (int) strlen(buffer);
    if (space == len)
        return;
 
    char user[space + 1];
    strncpy(user, buffer, space);
    user[space] = '\0';
    memmove(buffer, buffer + space + 1, len - space);
    buffer[len - space] = '\0';

    char msg[BUFFER_SIZE + USERNAME_SIZE];
    snprintf(msg, sizeof(msg), "<%s> %s", user, buffer);
    unicast(msg, user);
    
    memset(msg, 0, sizeof(msg));
    memset(user, 0, sizeof(user));
}

int check_for_commands(char* buffer) {
    if (buffer[0] != '/')
        return 0;
    
    int first_space = (int) strcspn(buffer, " ");
    int len = (int) strlen(buffer);

    char cmd[first_space];
    strncpy(cmd, buffer, first_space);
    if (strncmp(cmd, "/msg", 4) == 0) {
        memmove(buffer, buffer + first_space + 1, len - first_space);
        buffer[len - first_space] = '\0';
        send_msg(buffer);
    }

    return 1;
}

void* handle_connection(void* args) {
    int* pfd = (int*) args;
    int clientfd = *pfd;

    char user[USERNAME_SIZE];
    if (read(clientfd, user, sizeof(user) - 1) < 0) {
        printf("[!] Error reading username from client!\n");
        return NULL;
    }
    user[strcspn(user, "\n")] = '\0';
    
    pthread_mutex_lock(&mutex);

    active_clients[nClients].fd = clientfd;
    strncpy(active_clients[nClients].username, user, USERNAME_SIZE);
    int idx = nClients;
    nClients++;

    pthread_mutex_unlock(&mutex);

    char msg[100];
    snprintf(msg, sizeof(msg), "<SERVER> %s joined the chat", user);
    broadcast(msg, clientfd);
    memset(msg, 0, sizeof(msg));

    // send the iv (version 2)

    char buffer_in[BUFFER_SIZE], buffer_out[BUFFER_SIZE + USERNAME_SIZE + 10];
    int _size_sock = 0;
    while ((_size_sock = read(clientfd, buffer_in, sizeof(buffer_in) - 1)) > 0) {
        buffer_in[_size_sock] = '\0';

        if (check_for_commands(buffer_in) == 1) continue;

        if (strlen(buffer_in) == 0) continue;

        snprintf(buffer_out, sizeof(buffer_out), "<%s> %s", user, buffer_in);
        broadcast(buffer_out, clientfd);
        
        // cleanup
        memset(buffer_out, 0, sizeof(buffer_out));
        memset(buffer_in, 0, sizeof(buffer_in));
    }
    
    remove_user(idx);
    close(clientfd);
    
    pthread_detach(pthread_self());
    return NULL; 
}

int main(void) {
    signal(SIGINT, disconnect);

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (!sockfd) {
        printf("[!] Error Creating a socket!\n");
        return 1;
    }

    int optval = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        printf("[!] Error setting up set sockopt!\n");
        close(sockfd);
        return 1;
    }

    struct sockaddr_in server, clientaddr;
    server.sin_family = AF_INET;
    server.sin_port = htons(PORT);
    server.sin_addr.s_addr = inet_addr(IP);
    if (bind(sockfd, (struct sockaddr*) &server, sizeof(server)) < 0) {
        printf("[!] Error binding to %s\n", IP);
        close(sockfd);
        return 1;
    }

    if (listen(sockfd, MAX) < 0) {
        printf("[!] Error setting up listener!\n");
        close(sockfd);
        return 1;
    }

    printf("[#] Listening on %s:%d ..\n", IP, PORT);
    pthread_t tid;

    while (1) {
        int _size_sock = sizeof(clientaddr);
        int clientfd = accept(sockfd, (struct sockaddr*) &clientaddr, (socklen_t*) &_size_sock);
        if (clientfd < 0) {
            printf("[!] Error accepting client!\n");
            return 1;
        }
        
        if ((nClients + 1) >= MAX) {
            char* msg = "<SERVER> Max Clients Reached!";
            if (write(clientfd, msg, strlen(msg)) == -1) {
                printf("[!] Error sending message!\n");
                continue;
            }
            printf("%s\n", msg);
            close(clientfd);
            continue;
        }
        
        pthread_create(&tid, NULL, &handle_connection, (void*) &clientfd);
    
        sleep(1);
    }    

    return 0;
}
