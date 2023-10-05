#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <getopt.h>

struct ssl_socket {

    int client_socket;
    SSL_CTX *context;
    SSL *connection;
    struct sockaddr_in *server_addr;
    int tcp_connection_flag;
    int tls_connection_flag;
    const char *hostname;
    void (*initialise) (struct ssl_socket*);
};

void initialise_OpenSSLLib() {
    // Initialize OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ERR_load_crypto_strings();

}

struct sockaddr_in * create_server_socket(struct ssl_socket* ssl, int port) {
    // Get the IP Address of the host
    struct hostent *host_entry;
    host_entry = gethostbyname(ssl->hostname);
    if (host_entry == NULL) {
        printf("NULL host_entry");
    }

    struct sockaddr_in *server_addr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
    if (server_addr == NULL) {
        perror("Memory allocation failed");
        return NULL; // Return NULL if memory allocation fails
    }

    // Configure server address
    server_addr->sin_family = AF_INET;
    server_addr->sin_port = htons(port);
    memcpy(&server_addr->sin_addr, host_entry->h_addr_list[0], host_entry->h_length);

    return server_addr;

}

void initialise_SSL_Socket(struct ssl_socket* ssl){
    ssl->client_socket = -1;
    ssl->context = NULL;
    ssl->connection = NULL;
    ssl->tcp_connection_flag = -1;
    ssl->tls_connection_flag = -1;
    ssl->server_addr= NULL;


}

void establish_tcp_connection(struct ssl_socket *ssl, int port){

    //Step 1. Create Client Socket
    ssl->client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (ssl->client_socket == -1) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    //Step 2. Create server socket
    ssl->server_addr = create_server_socket(ssl, 443);

    //Step 3. Connect to the server


    ssl->tcp_connection_flag = connect(ssl->client_socket, (struct sockaddr *)(ssl->server_addr) , sizeof(struct sockaddr_in));

    if (ssl->tcp_connection_flag == -1) {
        perror("TCP Connection failed\n");
        exit(EXIT_FAILURE);
    }

}


void establish_tls_session(struct ssl_socket *ssl){

    // Step 1. Create a new SSL Context
     ssl->context = SSL_CTX_new(TLS_client_method());

    // if ssl context is not created then close the tcp connection and exit the program
    if (!ssl->context) {
        perror("SSL_CTX_new failed");
        close(ssl->client_socket);
        exit(EXIT_FAILURE);
    }

    // Step 2. Create a new SSL Connection
    ssl->connection = SSL_new(ssl->context);

    // IF the ssl connection is not established then close the tcp & free the memory of ssl_context
    if (!ssl->connection) {
        perror("SSL_new failed");
        close(ssl->client_socket);
        SSL_CTX_free(ssl->context);
        exit(EXIT_FAILURE);
    }

    // Step 3. Conenct the server and client socket and use the ssl/tls to communicate from now onwards
    SSL_set_fd(ssl->connection, ssl->client_socket);

    //Step 4. Set the SNI 
    SSL_set_tlsext_host_name(ssl->connection, ssl->hostname);

    // Step 5. Perform the TLS Handshake via using SSL_Connect
    ssl->tls_connection_flag = SSL_connect(ssl->connection);

    //If due to some failure the tls handshake is not done properly then close the client socket and free the memory
    if (ssl->tls_connection_flag != 1) {
        perror("TLS handshake failed");
        close(ssl->client_socket);
        SSL_free(ssl->connection);
        SSL_CTX_free(ssl->context);
        exit(EXIT_FAILURE);
    }

   return; 
}

struct ssl_socket* create_ssl_socket( const char *hostname, int port){
    struct ssl_socket *ssl = (struct ssl_socket*) malloc (sizeof(struct ssl_socket));
    ssl->initialise = initialise_SSL_Socket;
    ssl->initialise(ssl);
    ssl->hostname = hostname;
    initialise_OpenSSLLib();
    //Step 1. Establish TCP Connection between the client and remote server
    establish_tcp_connection(ssl,443);

    //Step 2. Establish TLS Session between the client and remote server to encrypt the messages
    establish_tls_session(ssl);

    return ssl;


}

char * create_header_request(char* hostname, char *path){

     // Calculate the length of the headers
    size_t headers_length = snprintf(NULL, 0, "HEAD /%s HTTP/1.1\r\nHost: %s\r\n\r\n", path, hostname) + 1; // +1 for null terminator
    // Estimate additional header size (if any)
    size_t additional_headers_size = 64; // Adjust as needed

    // Calculate the total header size
    size_t total_headers_size = headers_length + additional_headers_size;

    // Allocate memory for the header buffer
    char *head_request = (char *)malloc(total_headers_size);
    if (head_request == NULL) {
        perror("Memory allocation failed");
        exit(EXIT_FAILURE);
    }
    // Create the formatted header string
    snprintf(head_request, total_headers_size, "HEAD /%s HTTP/1.1\r\nHost: %s\r\n\r\n", path, hostname);
    return head_request;
}

void send_header_request( char *hostname,  char *path){
    struct ssl_socket* ssl = create_ssl_socket(hostname,443);
    char *head_request = create_header_request(hostname,path);

        SSL_write(ssl->connection, head_request, strlen(head_request));

    // Read and parse the content length from the HTTP response headers
    char response_buffer[1024];
    size_t content_length = 0;
    while (1) {
        int bytes_received = SSL_read(ssl->connection, response_buffer, sizeof(response_buffer));
        if (bytes_received <= 0) {
            break; // End of response
        }
        // Null-terminate the response
        response_buffer[bytes_received] = '\0'; 
        // Check if the response contains the "Content-Length" header
        char *content_length_start = strstr(response_buffer, "Content-Length:");
        if (content_length_start != NULL) {
            content_length_start += strlen("Content-Length:");
            content_length = strtoul(content_length_start, NULL, 10);
        }
     // Print the server's response
    fwrite(response_buffer, 1, bytes_received, stdout);
    }

    if (content_length == 0) {
        fprintf(stderr, "Failed to retrieve content length from HTTP response headers\n");
    }
    close(ssl->client_socket);
    SSL_shutdown(ssl->connection);
    SSL_free(ssl->connection);
    SSL_CTX_free(ssl->context);
    free(ssl->server_addr);
    free(ssl);
    free(head_request); // Free allocated memory
    exit(EXIT_FAILURE);
    

    return;
}


void send_get_range_request(char *hostname, char *path){
    
}