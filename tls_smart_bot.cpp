#include "common.hpp"
#include <openssl/ssl.h>
#include <openssl/err.h>


int main(int argc, char** argv) {
     if (argc != 2) {
          std::cerr << "Incorrect number of arguments. Try to use key --help." << std::endl;
          exit(-1);
     }
     
     bool success = true;
     int port = std::stoi(argv[1]);
     srand(time(0));
     Message msg = { };
     auto dest_address = local_addr(port);
     int sock_fd = check(make_socket(SOCK_STREAM));
     check(connect(sock_fd, (sockaddr * ) & dest_address, sizeof(dest_address)));

     // tls init
     SSL_library_init();
     OpenSSL_add_all_algorithms();
     SSL_load_error_strings();

     SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
     if (!ctx) {
          ERR_print_errors_fp(stderr);
          exit(1);
     }

     // Rightnow no checking
     SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);

     // May be use when we need verify,(don't forget line 52-55)
     // SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
     // if (!SSL_CTX_load_verify_locations(ctx, "../server.crt", nullptr)) {
     //      ERR_print_errors_fp(stderr);
     //      exit(1);
     // }

     SSL *ssl = SSL_new(ctx);
     SSL_set_fd(ssl, sock_fd);

     if (SSL_connect(ssl) <= 0) {
          ERR_print_errors_fp(stderr);
          SSL_free(ssl);
          SSL_CTX_free(ctx);
          close(sock_fd);
          exit(1);
     }
  
     // if (SSL_get_verify_result(ssl) != X509_V_OK) {
     //      std::cerr << "Cert verify failed\n";
     //      exit(1);
     // }
     
     int min = 0, max = 10000;
     
     msg = {0, Start};
     msg.to_net_order();
     SSL_write(ssl, &msg, sizeof(msg));
     msg = {min, SetMin};
     msg.to_net_order();
     SSL_write(ssl, &msg, sizeof(msg));
     msg = {max, SetMax};
     msg.to_net_order();
     SSL_write(ssl, &msg, sizeof(msg));
     auto size = check_except(SSL_read(ssl, &msg, sizeof(msg)), ENOTCONN);
     
     if (size < 1) {
          SSL_shutdown(ssl);
          SSL_free(ssl);
          SSL_CTX_free(ctx);
          close(sock_fd);
          std::cout << "Bot >> Server has been disconnected\n";
          exit(0);
     }
     
     msg.to_host_order();
     if (msg.status == Guess) {
          bool success = true;
          while(true) {
               int number = min + rand() % (max - min + 1);
               std::cout << "Bot >> Trying a number " << number << std::endl;
               msg = {number, Number};
               msg.to_net_order();
               SSL_write(ssl, &msg, sizeof(msg));
               auto size = check_except(SSL_read(ssl, &msg, sizeof(msg)), ENOTCONN);
               if (size < 1) {
                    success = false;
                    break;
               }
               
               msg.to_host_order();
               if (msg.status == Large) {
                    std::cout << "Guesser >> No, guessed number is large than " << number << std::endl;
                    min = number + 1;
               } else if (msg.status == Less) {
                    std::cout << "Guesser >> No, guessed number is less than " << number << std::endl;
                    max = number - 1;
               } else if (msg.status == Equal) {
                    std::cout << "Guesser >> You guess! Guessed number is " << number << std::endl;
                    std::cout << "Bot << I guess number " << number;
                    break;
               } else
                    std::cout << "Guesser >> Your number is out of guess bounds\n";
               sleep(1);
          }
     } else
          std::cout << "Bot >> The max value has been less or equal to the min value\n";
     
     SSL_shutdown(ssl);
     SSL_free(ssl);
     SSL_CTX_free(ctx);
     close(sock_fd);
     
     if (!success)
          std::cout << "Bot >> Server has been disconnected\n";
     
     return 0;
}
