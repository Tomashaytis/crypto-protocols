#include "common.hpp"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <thread>

SSL_CTX* create_ssl_context() {
    // Контекст для сервера
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    // Загружаем сертификат
    if (SSL_CTX_use_certificate_file(ctx, "../server.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    // Загружаем приватный ключ
    if (SSL_CTX_use_PrivateKey_file(ctx, "../server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    // Проверяем ключ
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the certificate public key\n");
        exit(1);
    }

    return ctx;
}

void server_work(std::string server_name, int port, bool is_daemon_mode, SSL_CTX *ctx) {
    nice(10);
    int fd = STDOUT_FILENO;
    
    if (is_daemon_mode) {
        unlink("ServerLog.log");
        fd = check(open("ServerLog.log", O_RDWR | O_CREAT | O_SYNC, S_IRWXU));
    }
    
    sem_t *sem = sem_open("/server_sem", O_CREAT, S_IWUSR | S_IRUSR, 1);
    std::string log_message = server_name + "::" + std::to_string(getpid()) + " >> I start work\n";
    check(write(fd, log_message.c_str(), log_message.size()));
    
    auto server_address = any_addr(port);
    auto listening_socket = check(make_socket(SOCK_STREAM));
    check(bind(listening_socket, (sockaddr *)&server_address, sizeof(server_address)));
    check(listen(listening_socket, 2));
    
    sockaddr_in connected_address{};
    socklen_t addrlen = sizeof(connected_address);
    int connected_socket = accept(listening_socket, (sockaddr *)&connected_address, &addrlen);
    
    // Создание SSL объекта ПОСЛЕ accept
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, connected_socket);

    // TLS Handshake
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(connected_socket);
        return;
    }
    
    srand(getpid());
    prctl(PR_SET_PDEATHSIG, SIGTERM);
    
    {
        SemGuard sem_guard(sem);
        log_message = server_name + "::" + std::to_string(getpid()) + " >> Connected from " + str_addr(connected_address) + "\n";
        check(write(fd, log_message.c_str(), log_message.size()));
    }
    
    // Поток для чтения сообщений от клиента
    std::thread reader_thread([ssl, fd, sem, server_name, connected_address]() {
        char buffer[4096];
        while (true) {
            int bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
            if (bytes <= 0) {
                break;
            }
            buffer[bytes] = '\0';
            
            {
                SemGuard sem_guard(sem);
                std::string msg = server_name + "::" + std::to_string(getpid()) + 
                                " >> Client: " + buffer + "\n";
                write(fd, msg.c_str(), msg.size());
            }
        }
    });
    
    // Основной поток для отправки сообщений от сервера
    std::string input;
    while (std::getline(std::cin, input)) {
        if (input == "exit") break;
        
        SSL_write(ssl, input.c_str(), input.length());
        
        {
            SemGuard sem_guard(sem);
            std::string msg = server_name + "::" + std::to_string(getpid()) + 
                            " >> Me: " + input + "\n";
            write(fd, msg.c_str(), msg.size());
        }
    }
    
    reader_thread.detach(); 
    
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(connected_socket);
    close(listening_socket);
}

int main(int argc, char **argv) {
    // SSL init
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ERR_load_crypto_strings();
    
    // SSL Context
    SSL_CTX *ctx = create_ssl_context();
    
    sigset_t mask;
    check(sigemptyset(&mask));
    check(sigaddset(&mask, SIGCHLD));
    struct sigaction action { };
    action.sa_handler = SIG_IGN;
    action.sa_mask = mask;
    action.sa_flags = SA_NOCLDWAIT;
    check(sigaction(SIGCHLD, &action, nullptr));
    std::string mode;
    
    if (argc == 2) {
        mode = std::string(argv[1]);
        if (mode == "-h" || mode == "--help") {
            std::cout << std::endl;
            std::cout << "First argument should be the port number." << std::endl;
            std::cout << "Available commands:" << std::endl;
            std::cout << "[--interactive] or [-i] - starts Server in the interactive mode." << std::endl;
            std::cout << "[--daemon] or [-d] - starts Server in the daemon mode." << std::endl;
            std::cout << "[--help] or [-h] - help with commands." << std::endl;
            std::cout << std::endl;
            exit(0);
        }
        std::cerr << "Usage: " << argv[0] << " <port> <mode>" << std::endl;
        std::cerr << "Incorrect number of arguments. Try to use key --help." << std::endl;
        exit(-1);
    }
    
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <port> <mode>" << std::endl;
        std::cerr << "Incorrect number of arguments. Try to use key --help." << std::endl;
        exit(-1);
    }
    
    mode = std::string(argv[2]);
    int port = std::stoi(argv[1]);
    
    if (mode == "-h" || mode == "--help") {
        std::cout << std::endl;
        std::cout << "First argument should be the port number." << std::endl;
        std::cout << "Available commands:" << std::endl;
        std::cout << "[--interactive] or [-i] - starts GuessServer in the interactive mode." << std::endl;
        std::cout << "[--daemon] or [-d] - starts GuessServer in the daemon mode." << std::endl;
        std::cout << "[--help] or [-h] - help with commands." << std::endl;
        std::cout << std::endl;
    } else if (mode == "-i" || mode == "--interactive") {
        server_work("Server", port, false, ctx);
    } else if (mode == "-d" || mode == "--daemon") {
        int pid = check(fork());
        if (pid == 0) {
            check(setsid());
            pid = check(fork());
            if (pid == 0) {
                server_work("Server", port, true, ctx);
            }
        }
    } else {
        std::cerr << "Usage: " << argv[0] << " <port> <mode>" << std::endl;
        std::cout << "Unrecognaized command " + mode + ". Try to use key --help." << std::endl;
        exit(-1);
    }
    
    SSL_CTX_free(ctx);
    
    return 0;
}

