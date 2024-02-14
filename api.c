#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 8080
#define RESPONSE_SIZE 1024
#define REQUEST_SIZE 2048

void init_openssl() { 
    SSL_load_error_strings();   
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_context(SSL_CTX *ctx) {
    SSL_CTX_set_ecdh_auto(ctx, 1);

    if (SSL_CTX_use_certificate_file(ctx, "./cert.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "./key.pem", SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

void handle_client_request(SSL *ssl, const char *request) {
    char method[16], path[1024];
    sscanf(request, "%s %s", method, path);

    printf("Received %s request for %s\n", method, path);

    if (strcmp(path, "/") == 0) {
        const char *response = "HTTP/1.1 200 OK\nContent-Type: text/plain\n\nWelcome to the root!";
        SSL_write(ssl, response, strlen(response));
    } else if (strcmp(path, "/hello") == 0) {
        const char *response = "HTTP/1.1 200 OK\nContent-Type: text/plain\n\nHello, World!";
        SSL_write(ssl, response, strlen(response));
    } else if (strcmp(path, "/json") == 0) {
        const char *json_response = "{\"message\": \"This is a JSON response\"}";
        const char *response = "HTTP/1.1 200 OK\nContent-Type: application/json\n\n";
        SSL_write(ssl, response, strlen(response));
        SSL_write(ssl, json_response, strlen(json_response));
    } else {
        const char *response = "HTTP/1.1 404 Not Found\nContent-Type: text/plain\n\nPage not found.";
        SSL_write(ssl, response, strlen(response));
    }
}

int main() {
    int server_fd;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    init_openssl();
    SSL_CTX *ctx = create_context();
    configure_context(ctx);

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("In socket");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("In bind");
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, 10) < 0) {
        perror("In listen");
        exit(EXIT_FAILURE);
    }

    while (1) {
        int client_fd;
        struct sockaddr_in addr;
        uint len = sizeof(addr);

        client_fd = accept(server_fd, (struct sockaddr*)&addr, &len);
        if (client_fd < 0) {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_fd);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        } else {
            char request[REQUEST_SIZE] = {0};
            int bytes = SSL_read(ssl, request, sizeof(request) - 1);
            if (bytes > 0) {
                request[bytes] = '\0';
                handle_client_request(ssl, request);
            }
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
    }

    close(server_fd);
    SSL_CTX_free(ctx);
    cleanup_openssl();
}