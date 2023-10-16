# http-downloader
The project aims to understand how the mutiple TCP Connection can be made via encryption with TLS and make use of HTTP Pipelining and HTTP Range to fetch the resouces from the server.

# Download
OpenSSL
GCC

The project is capable of taking the following arguments

-u for taking the argument
-n for number of parts (bascially no of tcp over tls session you want to open and no of parts in which you to fetch the file)
-o for specifying the name of the output file

You may call the http_downloader file with the above arguments.
