#include "common.hpp"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <atomic>
#include <thread>

int main(int argc, char** argv) {
    // SSL init
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ERR_load_crypto_strings();

    // SSL context
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    // Для самоподписанного сертификата отключаем проверку
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <ip> <port>" << std::endl;
        exit(-1);
    }
    
    const char* ip = argv[1];
    int port = std::stoi(argv[2]);

    auto dest_address = remote_addr(ip, port);
    int sock_fd = check(make_socket(SOCK_STREAM));
    check(connect(sock_fd, (sockaddr*)&dest_address, sizeof(dest_address)));
    
    // Создаем SSL объект
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock_fd);

    // TLS handshake
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(sock_fd);
        SSL_CTX_free(ctx);
        exit(1);
    }
    
    std::cout << "Connected to " << ip << ":" << port << std::endl;
    std::cout << "Enter messages (type 'exit' to quit):" << std::endl;
    
    std::atomic<bool> running{true};
    
    // Поток для чтения сообщений от сервера
    std::thread reader_thread([ssl, &running]() {
        char buffer[4096];
        while (running) {
            int bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
            if (bytes <= 0) {
                if (running) {
                    std::cout << "\nServer disconnected" << std::endl;
                }
                break;
            }
            buffer[bytes] = '\0';
            std::cout << "\rServer: " << buffer << std::endl;
            std::cout << "You: " << std::flush;
        }
    });
    
    // Основной поток для отправки сообщений
    std::string input;
    while (running) {
        std::cout << "You: " << std::flush;
        if (!std::getline(std::cin, input)) {
            break;
        }
        
        if (input == "exit") {
            running = false;
            break;
        }
        
        int bytes = SSL_write(ssl, input.c_str(), input.length());
        if (bytes <= 0) {
            std::cerr << "Failed to send message" << std::endl;
            break;
        }
    }
    
    running = false;
    if (reader_thread.joinable()) {
        reader_thread.join();
    }
    
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock_fd);
    SSL_CTX_free(ctx);
    
    return 0;
}
