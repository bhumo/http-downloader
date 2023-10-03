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

struct sockaddr_in create_server_socket(const char *hostname, int port) {
    // Get the IP Address of the host
    struct hostent *host_entry;
    host_entry = gethostbyname(hostname);
    if (host_entry == NULL) {
        printf("NULL host_entry");
    }

    // Configure server address
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    memcpy(&server_addr.sin_addr, host_entry->h_addr_list[0], host_entry->h_length);
    return server_addr;
}





void initialise_OpenSSLLib() {
    // Initialize OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ERR_load_crypto_strings();

}

int main(int argc, char *argv[]) {
    char *url = NULL;
    int num_parts = 1;
    char *output_file = NULL;
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
    char path[256];

    if (sscanf(url, "https://%255[^/]/%255[^\n]", hostname, path) < 2) {
        fprintf(stderr, "Invalid URL format\n");
        exit(EXIT_FAILURE);
    }

    // SSL context pointer will point to the SSL context object
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
    struct sockaddr_in server_addr;
    server_addr = create_server_socket(hostname, port);

    // Connect to the server
    int is_connected = connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr));
    printf("TCP Connect: %d\n", is_connected);
    if (is_connected == -1) {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }

    // TCP Established
    // Setting the SSL Context
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

    // Set the Server Name Indication (SNI) extension
    SSL_set_tlsext_host_name(ssl_connection, hostname);

    // Perform the TLS handshake
    int is_ssl_connected = SSL_connect(ssl_connection);
    printf("TLS Connection: %d\n", is_ssl_connected);
    if (is_ssl_connected != 1) {
        perror("TLS handshake failed");
        close(client_socket);
        SSL_free(ssl_connection);
        SSL_CTX_free(ssl_context);
        exit(EXIT_FAILURE);
    }
	printf("%d\n",SSL_get_state(ssl_connection));
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
    SSL_write(ssl_connection, head_request, strlen(head_request));

    // Read and parse the content length from the HTTP response headers
    char response_buffer[1024];
    size_t content_length = 0;
    while (1) {
        int bytes_received = SSL_read(ssl_connection, response_buffer, sizeof(response_buffer));
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
        close(client_socket);
        SSL_shutdown(ssl_connection);
        SSL_free(ssl_connection);
        SSL_CTX_free(ssl_context);
        free(head_request); // Free allocated memory
        exit(EXIT_FAILURE);
    }

// Calculate the size of each part based on the total length and the number of parts
size_t part_size = content_length / num_parts;
size_t remaining_bytes = content_length;

// Declare a buffer to store the part content
char part_buffer[1024]; // You can adjust the buffer size as needed

//In the below loop for n no of parts we will be calling Range Function
for (int i = 0; i < num_parts; i++) {
     // Determine the range for each part (e.g., byte offsets for partial downloads)
    size_t start_offset = i * part_size;
    size_t end_offset = start_offset + part_size - 1;
    if (i == num_parts - 1) {
        // Last part may include remaining bytes
        end_offset = content_length - 1;
    }
    
  // Calculate the size of the current part
    size_t current_part_size = end_offset - start_offset + 1;

    // Print range, start offset, end offset, and part size for the current range
    printf("Part %d Range: bytes=%zu-%zu (Start Offset: %zu, End Offset: %zu, current_part_size: %zu bytes)\n", i + 1, start_offset, end_offset, start_offset, end_offset, current_part_size);


    // Calculate the size needed for the Range header
    int range_header_size = snprintf(NULL, 0, "Range: bytes=%zu-%zu\r\n", start_offset, end_offset);
    printf("range_header_size: %d bytes\n", range_header_size);

    
    // Allocate memory for the Range header
    char *range_header = (char *)malloc(range_header_size + 1); // +1 for null terminator
    if (range_header == NULL) {
        perror("Memory allocation failed");
        exit(EXIT_FAILURE);
    }

    // Format the Range header
    snprintf(range_header, range_header_size + 1, "Range: bytes=%zu-%zu\r\n", start_offset, end_offset);

    // Construct the GET request with the Range header
    int get_request_size = snprintf(NULL, 0, "GET /%s HTTP/1.1\r\nHost: %s\r\n%s\r\n", path, hostname, range_header);
    char *get_request = (char *)malloc(get_request_size + 1); // +1 for null terminator
    if (get_request == NULL) {
        perror("Memory allocation failed");
        free(range_header);
        exit(EXIT_FAILURE);
    }

    // Format the GET request
    snprintf(get_request, get_request_size + 1, "GET /%s HTTP/1.1\r\nHost: %s\r\n%s\r\n", path, hostname, range_header);
	printf("%s\n",get_request);

    // Perform the partial download
    int bytes_written_ssl =  SSL_write(ssl_connection, get_request, get_request_size);
	if(bytes_written_ssl <=0 ){
		printf("Some error occured while performing the SSL_WRITE\n");
	}else{
		printf("Sent %d bytes\n",bytes_written_ssl);
	}
	char response_buffer[1024*8];
    int bytes_received;
	bytes_received = SSL_read(ssl_connection, response_buffer, sizeof(response_buffer));
	printf("%d\n",SSL_pending(ssl_connection));
	printf("%d\n",bytes_received);
	if(SSL_get_state(ssl_connection)==TLS_ST_OK){
		printf("TLS is established\n");
	}
	int ssl_error = SSL_get_error(ssl_connection, bytes_received);

    const char *error_string = ERR_error_string(ssl_error, NULL);
    fprintf(stderr, "SSL_read error: %s\n", error_string);
    while ((bytes_received = SSL_read(ssl_connection, response_buffer, sizeof(response_buffer))) > 0) {
        fwrite(response_buffer, 1, bytes_received, stdout);
		printf("HERE");
		
    }

    // Free dynamically allocated memory
    free(range_header);
    free(get_request);
}


    // Close the socket
    SSL_shutdown(ssl_connection);
    SSL_free(ssl_connection);
    SSL_CTX_free(ssl_context);
    close(client_socket);


    return 0;
}