#include "common.hpp"
#include <openssl/ssl.h>
#include <openssl/err.h>

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
    
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <port>" << std::endl;
        std::cerr << "Incorrect number of arguments. Try to use key --help." << std::endl;
        exit(-1);
    }
    
    int port = std::stoi(argv[1]);
    Message msg = { };
    auto dest_address = local_addr(port);
    int sock_fd = check(make_socket(SOCK_STREAM));
    check(connect(sock_fd, (sockaddr * ) & dest_address, sizeof(dest_address)));
    
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
    
    int min, max;
    std::cout << "Input min: ";
    std::cin >> min;
    std::cout << "Input max: ";
    std::cin >> max;
    
    msg = {0, Start};
    msg.to_net_order();
    SSL_write(ssl, &msg, sizeof(msg));
    msg = {min, SetMin};
    msg.to_net_order();
    SSL_write(ssl, &msg, sizeof(msg));
    msg = {max, SetMax};
    msg.to_net_order();
    SSL_write(ssl, &msg, sizeof(msg));
    auto size = SSL_read(ssl, &msg, sizeof(msg));
    
    if (size <= 0) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sock_fd);
        SSL_CTX_free(ctx);
        std::cout << "Server has been disconnected\n";
        exit(0);
    }
    
    msg.to_host_order();
    bool success = true;
    if (msg.status == Guess) {
        while(true) {
            int number;
            std::cout << "Input number: ";
            std::cin >> number;
            msg = {number, Number};
            msg.to_net_order();
            SSL_write(ssl, &msg, sizeof(msg));
            auto size = SSL_read(ssl, &msg, sizeof(msg));
            if (size < 1) {
                success = false;
                break;
            }
            msg.to_host_order();
            if (msg.status == Large)
                std::cout << "Guessed number is large than " << number << std::endl;
            else if (msg.status == Less)
                std::cout << "Guessed number is less than " << number << std::endl;
            else if (msg.status == Equal) {
                std::cout << "You win. Guessed number is " << number << std::endl;
                break;
            } else
                std::cout << "Your number is out of guess bounds\n";
        }
    } else
        std::cout << "The max value has been less or equal to the min value\n";
    
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock_fd);
    SSL_CTX_free(ctx);
    
    if (!success)
        std::cout << "Server has been disconnected\n";
    
    return 0;
}
