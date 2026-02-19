cmake_minimum_required(VERSION 3.10)
project(CryptoProtocols)

# Устанавливаем стандарт C++
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Находим пакет OpenSSL
find_package(OpenSSL REQUIRED)

# Добавляем исполняемый файл
add_executable(tls_client tls_client.cpp)
add_executable(tls_server tls_server.cpp)
add_executable(tls_smart_bot tls_smart_bot.cpp)
add_executable(tls_stupid_bot tls_stupid_bot.cpp)

# Линкуем библиотеки OpenSSL
target_link_libraries(tls_client OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(tls_server OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(tls_smart_bot OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(tls_stupid_bot OpenSSL::SSL OpenSSL::Crypto)

# Добавляем include директории
target_include_directories(tls_client PRIVATE ${OPENSSL_INCLUDE_DIR})
target_include_directories(tls_server PRIVATE ${OPENSSL_INCLUDE_DIR})
target_include_directories(tls_smart_bot PRIVATE ${OPENSSL_INCLUDE_DIR})
target_include_directories(tls_stupid_bot PRIVATE ${OPENSSL_INCLUDE_DIR})
