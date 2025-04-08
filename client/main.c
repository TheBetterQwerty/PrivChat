#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <pthread.h>
#include <unistd.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define IP "127.0.0.1"
#define PORT 6000
#define USERNAME_LENGTH 30 * sizeof(char)
#define AES_KEY_SIZE 32
#define AES_BLOCK_SIZE 16
#define BUFFER_SIZE 1024 * sizeof(char)

int sockfd = -1;
int is_server_ok = 0;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

void kill_client(int signum) {
    signal(SIGINT, SIG_IGN);  

    pthread_mutex_lock(&mutex);

    is_server_ok = 0;
    if (sockfd > 0) { 
        close(sockfd);
        printf("\n[*] Err%d: Closed socket exitting!\n", signum);
    }

    pthread_mutex_unlock(&mutex);

    exit(EXIT_SUCCESS);
}   

void* listen_for_msg(void* args) {
    char buffer[BUFFER_SIZE + USERNAME_LENGTH + 10];
    int size = 0;

    while ((size = read(sockfd, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[size] = '\0';
        printf("%s\n", buffer);
        memset(buffer, 0, sizeof(buffer));
        if (is_server_ok)
            break;
    }
    
    kill_client(36);
    pthread_detach(pthread_self());
    return NULL;
}     

void* listen_from_user(void* args) {
    char buffer[BUFFER_SIZE];
    
    while (fgets(buffer, sizeof(buffer) - 1, stdin) != NULL) {
        buffer[strcspn(buffer, "\n")] = '\0';
        printf("Client is sending: %s\n", buffer);
        if (write(sockfd, buffer, sizeof(buffer)) < 1) {
            printf("[!] Error47: sending message to server!\n");
        }
        memset(buffer, 0, sizeof(buffer));

        if (is_server_ok)
            break;
    } 
    pthread_detach(pthread_self());
    return NULL;
}  

int main(void) {
    signal(SIGINT, kill_client);

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        printf("[!] Error60: creating socket!\n");
        return EXIT_FAILURE;
    }
    
    struct sockaddr_in client;
    client.sin_family = AF_INET;
    client.sin_port = htons(PORT);
    client.sin_addr.s_addr = inet_addr(IP);
    client.sin_zero[7] = '\0';
    if (connect(sockfd, (const struct sockaddr*) &client, (socklen_t) sizeof(client)) < 0) { 
        printf("[!] Error70: connecting to server!\n");
        close(sockfd);
        return EXIT_FAILURE;
    }
    
    printf("Enter your username: ");
    char user[USERNAME_LENGTH];
    fgets(user, sizeof(user), stdin);
    if (strlen(user) <= 0) {
        printf("[!] Err78: Username cannot be empty!\n");
        return EXIT_FAILURE;
    }
    user[strcspn(user, "\n")] = '\0';

    if (write(sockfd, user, strlen(user)) < 0) {
        printf("[!] Error80: sending username!\n");
        kill_client(81);
    }

    pthread_t thread1, thread2;
    
    pthread_create(&thread1, NULL, &listen_for_msg, NULL);
    pthread_create(&thread2, NULL, &listen_from_user, NULL);
    
    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);

    printf("\n[@] Exitting gracefully\n");
    return EXIT_SUCCESS;
}
