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


struct sockaddr_in create_server_socket(char * URL){

    // get the host from the URL
    
    // get the IP Address of the host
    struct hostent *host_entry;
    host_entry = gethostbyname("cobweb.cs.uga.edu");

    if(host_entry == NULL){
        printf("NULL host_entry");
    }
    // get the Port Number of the host

    struct sockaddr_in server_addr;
     server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(443);
    memcpy(&server_addr.sin_addr, host_entry->h_addr_list[0], host_entry->h_length);
    return server_addr;
}


void initialise_OpenSSLLib(){
    
    // Initialize OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ERR_load_crypto_strings();

}


int main() {

    //ssl_context pointer will point to the ssl_context object
    SSL_CTX *ssl_context;

    SSL *ssl_connection;

    initialise_OpenSSLLib();
    int client_socket;    
    // Create a client socket
    client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket == -1) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Get the host 

    // Configure server address
    struct hostent *host_entry;
    host_entry = gethostbyname("cobweb.cs.uga.edu");

    if(host_entry == NULL){
        printf("NULL host_entry");
    }
    struct sockaddr_in server_addr;
    server_addr = create_server_socket("https://cobweb.cs.uga.edu/~perdisci/CSCI6760-F21/Project2-TestFiles/topnav-sport2_r1_c1.gi");
    inet_pton(AF_INET, host_entry->h_addr_list[0], &server_addr.sin_addr);

    // Connect to the server
    int is_connected =connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr));
    printf("TCP Connect: %d\n", is_connected);
    if (is_connected == -1) {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }
    //TCP Established

    //Setting the SSL Context
     ssl_context = SSL_CTX_new(TLS_client_method());
    if (!ssl_context) {
        perror("SSL_CTX_new failed");
        close(client_socket);
        exit(EXIT_FAILURE);
    }

    ssl_connection = SSL_new(ssl_context);
    if (!ssl_connection) {
        perror("SSL_new failed");
        close(client_socket);
        SSL_CTX_free(ssl_context);
        exit(EXIT_FAILURE);
    }
    SSL_set_fd(ssl_connection, client_socket);

    char server_hostname[] = "cobweb.cs.uga.edu";
    // Set the Server Name Indication (SNI) extension
    SSL_set_tlsext_host_name(ssl_connection, server_hostname);

    // Perform the TLS handshake
    int is_ssl_connected = SSL_connect(ssl_connection);
    printf("TLS Connection: %d\n",is_ssl_connected); 
    if (is_ssl_connected != 1) {
        perror("TLS handshake failed");
        close(client_socket);
        SSL_free(ssl_connection);
        SSL_CTX_free(ssl_context);
        exit(EXIT_FAILURE);
    }


    const char *path = "/~perdisci/CSCI6760-F21/Project2-TestFiles/topnav-sport2_r1_c1.gif";
    char request[256];
    snprintf(request, sizeof(request), "HEAD %s HTTP/1.1\r\nHost: %s\r\n\r\n", path, server_hostname);
    SSL_write(ssl_connection, request, strlen(request));

    // Read and print the server's response
    char response_buffer[1024];
    int bytes_received;
    while ((bytes_received = SSL_read(ssl_connection, response_buffer, sizeof(response_buffer))) > 0) {
        fwrite(response_buffer, 1, bytes_received, stdout);
    }

    // Close the socket

    SSL_shutdown(ssl_connection);
    SSL_free(ssl_connection);
    SSL_CTX_free(ssl_context);
    close(client_socket);
    return 0;
}
