#include "ssl_connection.c"
#include <pthread.h>


int main(int argc, char *argv[]){

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
    char path[356];

    if (sscanf(url, "https://%255[^/]/%355[^\n]", hostname, path) < 2) {
        fprintf(stderr, "Invalid URL format\n");
        exit(EXIT_FAILURE);
    }

   
    struct ssl_socket;


    int content_length = send_header_request(hostname,path);
    if(content_length == 0){
        printf("Content Length is Zero in header\n");
        exit(EXIT_FAILURE);
    }
    size_t part_size = content_length / num_parts;
    size_t remaining_bytes = content_length;
    int NUM_THREADS = num_parts;
    pthread_t threads[NUM_THREADS];
    int thread_ids[NUM_THREADS];


    // Create multiple threads to open TCP connections in parallel
    for (int i = 0; i < NUM_THREADS; i++) {

        size_t start_offset = i * part_size;
        size_t end_offset = start_offset + part_size - 1;
        if (i == num_parts - 1) {
            // Last part may include remaining bytes
            end_offset = content_length - 1;
        }
        size_t current_part_size = end_offset - start_offset + 1;
    
        thread_ids[i] = i;
        struct ThreadArgument * thread_argument= (struct ThreadArgument*) malloc (sizeof(struct ThreadArgument));
        thread_argument->partNumber = i;
        thread_argument->range_start = start_offset;
        thread_argument->range_end = end_offset;
        thread_argument->hostname = hostname;
        thread_argument->path = path;
        if (pthread_create(&threads[i], NULL, send_get_range_request(thread_argument), &thread_ids[i]) != 0) {
            perror("Thread creation failed");
            exit(EXIT_FAILURE);
        }
    }

    // Wait for all threads to finish
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    return 0;
}