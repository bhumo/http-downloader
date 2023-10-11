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
#include <pthread.h>

char *output_file = NULL;
char cookies[500];
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


// Function to concatenate multiple files into a single file


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

char * create_header_request(char* hostname, char *path, char* cookie){

     // Calculate the length of the headers
     size_t headers_length = 0;
     if(cookie!=NULL){
        headers_length =  snprintf(NULL, 0, "HEAD /%s HTTP/1.1\r\nConnection: keep-alive\r\nAccept: */*\r\nUser-Agent: PostmanRuntime/7.33.0\r\nHost: %s\r\n Cookie: %s\r\n\r\n", path, hostname,cookie) + 1; // +1 for null terminator
    // Estimate additional header size (if any)
     }else{
        headers_length = snprintf(NULL, 0, "HEAD /%s HTTP/1.1\r\nConnection: keep-alive\r\nAccept: */*\r\nUser-Agent: PostmanRuntime/7.33.0\r\nHost: %s\r\n\r\n", path, hostname) + 1; // +1 for null terminator
    // Estimate additional header size (if any)
     }
    
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
    if(cookie != NULL){
        snprintf(head_request, total_headers_size, "HEAD /%s HTTP/1.1\r\nConnection: keep-alive\r\nAccept: */*\r\nUser-Agent: PostmanRuntime/7.33.0\r\nHost: %s\r\nCookie: %s\r\n\r\n", path, hostname,cookie);
    }    
    else{
        snprintf(head_request, total_headers_size, "HEAD /%s HTTP/1.1\r\nConnection: keep-alive\r\nAccept: */*\r\nUser-Agent: PostmanRuntime/7.33.0\r\nHost: %s\r\n\r\n", path, hostname);
    }
    return head_request;
}
void extractCookies(char* httpResponse, char* cookies, size_t cookiesSize) {
    const char* setCookiePrefix = "Set-Cookie: ";
    const char* cookieDelimiter = "; ";
    char* cookieStart = strstr(httpResponse, setCookiePrefix);

    if (cookieStart != NULL) {
        cookieStart += strlen(setCookiePrefix); // Move past "Set-Cookie: "
        char* cookieEnd = strstr(cookieStart, cookieDelimiter);

        if (cookieEnd == NULL) {
            cookieEnd = strchr(cookieStart, '\r'); // Handle the last cookie in the header
        }

        if (cookieEnd != NULL) {
            size_t cookieLength = cookieEnd - cookieStart;
            if (cookieLength < cookiesSize - 1) {
                strncpy(cookies, cookieStart, cookieLength);
                cookies[cookieLength] = '\0'; // Null-terminate the cookie string
            }
        }
    }
}

int send_header_request( char *hostname,  char *path){
    struct ssl_socket* ssl = create_ssl_socket(hostname,443);
    char *head_request = create_header_request(hostname,path,NULL);
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



    if(strstr(response_buffer, "Set-Cookie: ")!= NULL )
    { 
    
     ssl = create_ssl_socket(hostname,443);
    extractCookies(response_buffer, cookies, sizeof(cookies));  

    
    
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


// Function to extract cookies from the "Set-Cookie" header in an HTTP response
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
    int get_request_size = snprintf(NULL, 0, "GET /%s HTTP/1.1\r\nAccept: */*\r\nUser-Agent: PostmanRuntime/7.33.0\r\nHost: %s\r\n%s\r\n", path, hostname, range_header);
    char *get_request = (char *)malloc((sizeof(char)*(get_request_size + 1))); // +1 for null terminator
    if (get_request == NULL) {
        perror("Memory allocation failed");
        free(range_header);
        exit(EXIT_FAILURE);
    }
        // Format the GET request

    snprintf(get_request, get_request_size + 2, "GET /%s HTTP/1.1\r\nAccept: */*\r\nUser-Agent: PostmanRuntime/7.33.0\r\nHost: %s\r\n%s\r\n", path, hostname, range_header);
	// printf("%s\n",get_request);

    free(range_header);    
    return get_request;

}


char * getFileExtention(char *file_name){

   char *fileExtension = strrchr(file_name, '.');

    if (fileExtension) {
        // Move to the character after the last '.' to get the file type.
        fileExtension++;
    }

    return fileExtension;

}

void concatenateFiles( char *output_file, int num_parts) {
    FILE *output = fopen(output_file, "wb"); // Open the output file in binary write mode

    if (output == NULL) {
        perror("Unable to open the output file");
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < num_parts; i++) {
        char partFileName[20];
        char *file_extention = getFileExtention(output_file);
        sprintf(partFileName, "part_%d.%s",i+1,file_extention);
        FILE *partFile = fopen(partFileName, "rb"); // Open each part file in binary read mode

        if (partFile == NULL) {
            perror("Unable to open part file");
            exit(EXIT_FAILURE);
        }

        char buffer[1024];
        size_t bytesRead;

        while ((bytesRead = fread(buffer, 1, sizeof(buffer), partFile)) > 0) {
            size_t bytesWritten = fwrite(buffer, 1, bytesRead, output);
            if (bytesWritten != bytesRead) {
                perror("Error writing to output file");
                exit(EXIT_FAILURE);
            }
        }

        fclose(partFile); // Close the part file
    }

    fclose(output); // Close the output file
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
	bytes_received = SSL_read(ssl->connection, response_buffer, sizeof(response_buffer));
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
    char *file_extention = getFileExtention(output_file);
    sprintf(name, "part_%d.%s",thread_argument->partNumber,file_extention);

    FILE *file = fopen(name,"wb");

    // Check if the response is chunked
    int chunked = 0;
    char *chunk_start = strstr(response_buffer, "Transfer-Encoding: chunked");
    if (chunk_start != NULL) {
        chunked = 1;
    printf("Reading chunck data");
    }
    
    if (chunked) {
        // Handle chunked response
        while (1) {
            // Read the chunk size in hexadecimal
            // if (SSL_read(ssl->connection, response_buffer, 2) != 2) {
            //     break; // Error handling for incomplete chunk size
            // }
            // response_buffer[2] = '\0';
            // int chunk_size = strtol(response_buffer, NULL, 16);

            // if (chunk_size == 0) {
            //     // End of chunked data
            //     break;
            // }

            // Read and process the chunk data
            // while (chunk_size > 0) {
            //     int bytes_to_read = (chunk_size < sizeof(response_buffer)) ? chunk_size : sizeof(response_buffer);
            //     int bytes_received = SSL_read(ssl->connection, response_buffer, bytes_to_read);

            //     if (bytes_received <= 0) {
            //         break; // Error handling for incomplete chunk data
            //     }

            //     fwrite(response_buffer, 1, bytes_received, file);
            //     chunk_size -= bytes_received;
            // }

            // Read and discard the chunk delimiter ("\r\n")
            // if (SSL_read(ssl->connection, response_buffer, 2) != 2) {
            //     break; // Error handling for incomplete chunk delimiter
            // }

            int bytes_received  =  SSL_read(ssl->connection, response_buffer, sizeof(response_buffer));
            if(bytes_received<=0){
                fwrite(response_buffer,1,bytes_received,file);
            }
        }
    } else {
        // Handle non-chunked response
        while ((bytes_received = SSL_read(ssl->connection, response_buffer, sizeof(response_buffer))) > 0) {
            fwrite(response_buffer, 1, bytes_received, file);
        }
    }

    fclose(file);
    free(get_request);
    close(ssl->client_socket);
    SSL_shutdown(ssl->connection);
    SSL_free(ssl->connection);
    SSL_CTX_free(ssl->context);
    free(ssl->server_addr);
    free(ssl);

    return NULL;
}

int main(int argc, char *argv[]){

   char *url = NULL;
    int num_parts = 1;
    output_file = NULL;
    int opt;

    while ((opt = getopt(argc, argv, "u:n:o:")) != -1) {
        switch (opt) {
            case 'u':
                url = optarg;
                break;
            case 'n':
                num_parts = atoi(optarg);
                break;
            case 'o':
                output_file = optarg;
                break;
            default:
                fprintf(stderr, "Usage: %s -u HTTPS_URL -n NUM_PARTS -o OUTPUT_FILE\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (url == NULL || num_parts <= 0 || output_file == NULL) {
        fprintf(stderr, "Invalid or missing command line arguments\n");
        exit(EXIT_FAILURE);
    }
   
    // Extract the hostname, port, and path from the URL
    char hostname[256];
    int port = 443; // Default HTTPS port
    char path[356];

    if (sscanf(url, "https://%255[^/]/%355[^\n]", hostname, path) < 2) {
        fprintf(stderr, "Invalid URL format\n");
        exit(EXIT_FAILURE);
    }

   
    struct ssl_socket;


    int content_length = send_header_request(hostname,path);
    if(content_length == 0){
        printf("Content Length is Zero in header\n");
//        exit(EXIT_FAILURE);
    }

    if(content_length == 0){
        //Try for get the
    }
    size_t part_size = content_length / num_parts;
    size_t remaining_bytes = content_length;
    int NUM_THREADS = num_parts;
    pthread_t threads[NUM_THREADS];

    
    int count = 0;

    // Create multiple threads to open TCP connections in parallel
    for (int i = 0; i < NUM_THREADS; i++) {

        size_t start_offset = i * part_size;
        size_t end_offset = start_offset + part_size - 1;
        printf("%d\n",num_parts);
        if (i == num_parts - 1) {
            // Last part may include remaining bytes
            end_offset = content_length - 1;
        }
        size_t current_part_size = end_offset - start_offset + 1;
        printf("About to create the thread %d\n",i);
        printf("Start : %zu & end: %zu",start_offset,end_offset);

        struct ThreadArgument  *thread_argument = (struct ThreadArgument*)malloc(sizeof(struct ThreadArgument));
        thread_argument->partNumber = i+1;
        thread_argument->range_start = start_offset;
        thread_argument->range_end = end_offset;
        thread_argument->hostname = hostname;
        thread_argument->path = path;
        thread_argument->run_Count = &count;
        // send_get_range_request(thread_argument);
        if (pthread_create(&threads[i], NULL, send_get_range_request,(void*) thread_argument ) != 0) {
            perror("Thread creation failed");
            exit(EXIT_FAILURE);
        }

    }

    // Wait for all threads to finish
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);      
    }

    concatenateFiles(output_file, num_parts);

    printf("File parts successfully stitched together into %s.\n", output_file);

    return 0;
}