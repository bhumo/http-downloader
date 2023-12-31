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


struct ThreadArgument{
    int partNumber;
    size_t range_start;
    size_t range_end;
    char *hostname;
    char *path;
    int *run_Count;

};


void concatenateFiles(char *output_file, int num_parts) {
    FILE *output = fopen(output_file, "wb"); // Open the output file in binary write mode

    if (output == NULL) {
        perror("Unable to open the output file");
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < num_parts; i++) {
        char partFileName[20];
        snprintf(partFileName, sizeof(partFileName), "part_%d.gif", i);

        FILE *partFile = fopen(partFileName, "rb"); // Open each part file in binary read mode

        if (partFile == NULL) {
            perror("Unable to open part file");
            exit(EXIT_FAILURE);
        }
        char line[1024];
        while (fgets(line, sizeof(line), partFile) != NULL) {
            fwrite(line,1,sizeof(line),output);
        }

        fclose(partFile); // Close the part file
    }

    fclose(output); // Close the output file
}


void initialise_OpenSSLLib() {
    // Initialize OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ERR_load_crypto_strings();

}

// Function to concatenate multiple files into a single file

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
    char *head_request = (char *)malloc(sizeof(char)*total_headers_size);
    if (head_request == NULL) {
        perror("Memory allocation failed");
        exit(EXIT_FAILURE);
    }
    // Create the formatted header string
    snprintf(head_request, total_headers_size, "HEAD /%s HTTP/1.1\r\nHost: %s\r\n\r\n", path, hostname);
    return head_request;
}

int send_header_request( char *hostname,  char *path){
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
    return content_length;
}

char * get_range_request_header(char *hostname, char *path, size_t range_start,size_t range_end){

    int range_header_size = snprintf(NULL, 0, "Range: bytes=%zu-%zu\r\n", range_start, range_end);
    
    printf("range_header_size: %d bytes\n", range_header_size);
    
    char *range_header = (char *)malloc(sizeof(char)*(range_header_size + 1)); // +1 for null terminator
    if (range_header == NULL) {
        perror("Memory allocation failed");
        exit(EXIT_FAILURE);
    }
    // Format the Range header
    snprintf(range_header, range_header_size + 1, "Range: bytes=%zu-%zu\r\n", range_start, range_end);


    // Construct the GET request with the Range header
    int get_request_size = snprintf(NULL, 0, "GET /%s HTTP/1.1\r\nHost: %s\r\n%s\r\n", path, hostname, range_header);
    char *get_request = (char *)malloc((sizeof(char)*(get_request_size + 1))); // +1 for null terminator
    if (get_request == NULL) {
        perror("Memory allocation failed");
        free(range_header);
        exit(EXIT_FAILURE);
    }
        // Format the GET request
    snprintf(get_request, get_request_size + 2, "GET /%s HTTP/1.1\r\nHost: %s\r\n%s\r\n", path, hostname, range_header);
	// printf("%s\n",get_request);
    free(range_header);    
    return get_request;

}
void *send_get_range_request(void *thread_argu){
    
    struct ThreadArgument*  thread_argument = (struct ThreadArgument *) thread_argu;
     printf("%s\n", thread_argument->hostname);
    char *get_request = get_range_request_header(thread_argument->hostname,thread_argument->path, thread_argument->range_start,thread_argument->range_end);
    // printf("Got the request header");    
    struct ssl_socket* ssl = create_ssl_socket(thread_argument->hostname,443);
    // Perform the partial download
    int bytes_written_ssl =  SSL_write(ssl->connection, get_request,strlen(get_request));;
	if(bytes_written_ssl <=0 ){
		printf("Some error occured while performing the SSL_WRITE\n");

	}else{
		printf("Sent %d bytes\n Part %d\n",bytes_written_ssl,thread_argument->partNumber);
	}
	char response_buffer[1024];
    int bytes_received=0;
//	bytes_received = SSL_read(ssl->connection, response_buffer, sizeof(response_buffer));
	// printf("%d\n",SSL_pending(ssl->connection));
	// printf("%d\n",bytes_received);
    // printf("RB: %lu\n",sizeof(&response_buffer));
	// if(SSL_get_state(ssl->connection)==TLS_ST_OK){
	// 	printf("TLS is established\n");
	// }
	// int ssl_error = SSL_get_error(ssl->connection, bytes_received);
     printf("%lu\n",sizeof(&response_buffer));
    // const char *error_string = ERR_error_string(ssl_error, NULL);
    // fprintf(stderr, "SSL_read error: %s\n", error_string);
    char name[20];

    sprintf(name, "part_%d.gif\n",thread_argument->partNumber);

    int header_end = 0;

    FILE *file = fopen(name,"wb");

    while ((bytes_received = SSL_read(ssl->connection, response_buffer, sizeof(response_buffer))) > 0) {
        // response_buffer[bytes_received]='\n';
         printf("%s",response_buffer);
        // printf("BBBBBBBBBBBBBBB:%d    %lu\n",bytes_received,sizeof(response_buffer));
          // Search for the blank line that separates headers from body
        for (int i = 0; i < bytes_received; i++) {
            if (response_buffer[i] == '\r' && response_buffer[i + 1] == '\n' && response_buffer[i + 2] == '\r' && response_buffer[i + 3] == '\n') {
                header_end = i + 4;
                break;
            }
        }
 
    int content_length = bytes_received;
    // Now, read and process only the content (body) and remove trailing \r\n
    if (header_end < bytes_received) {
        content_length = bytes_received - header_end;
        if (content_length >= 2 && response_buffer[header_end + content_length - 2] == '\r' && response_buffer[header_end + content_length - 1] == '\n') {
            content_length -= 2; // Remove trailing \r\n

        }

        int total_file_size = thread_argument->range_end - thread_argument->range_start+1;
        int image_file_end = header_end;
        for(int i=header_end;i<content_length & total_file_size>=0;i++){
            image_file_end++;
            total_file_size--;
        }
        fwrite(response_buffer + header_end, 1, image_file_end,  file);	
    }

    }
    

    concatenateFiles("xyz.jpg",5);

    fclose(file);
    *thread_argument->run_Count= *thread_argument->run_Count + 1;
    printf("%d ",*thread_argument->run_Count);
    // Free dynamically allocated memory
    free(get_request);
    close(ssl->client_socket);
    SSL_shutdown(ssl->connection);
    SSL_free(ssl->connection);
    SSL_CTX_free(ssl->context);
    free(ssl->server_addr);
    free(ssl);
    // free(thread_argument);
    return NULL;
}
