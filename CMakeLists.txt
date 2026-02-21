cmake_minimum_required(VERSION 3.10)
project(CryptoProtocols)

# Устанавливаем стандарт C++
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Находим пакет OpenSSL
find_package(OpenSSL REQUIRED)

# Находим пакет Threads
find_package(Threads REQUIRED)

# Добавляем исполняемый файл
add_executable(tls_client tls_client.cpp)
add_executable(tls_server tls_server.cpp)

# Линкуем библиотеки OpenSSL и Threads
target_link_libraries(tls_client 
    OpenSSL::SSL 
    OpenSSL::Crypto
    Threads::Threads
)

target_link_libraries(tls_server 
    OpenSSL::SSL 
    OpenSSL::Crypto
    Threads::Threads
)

# Добавляем include директории
target_include_directories(tls_client PRIVATE ${OPENSSL_INCLUDE_DIR})
target_include_directories(tls_server PRIVATE ${OPENSSL_INCLUDE_DIR})
