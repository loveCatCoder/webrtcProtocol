cmake_minimum_required(VERSION 3.10)

project (iceserver VERSION 0.1.0)

add_subdirectory(net)
add_subdirectory(erizo)

# specify the C++ standard
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# add the executable
add_executable(${CMAKE_PROJECT_NAME} main.cpp
        http/HttpServer.cpp      
        erizo/WebrtcConn.cpp
)

find_library(zlog_lib libzlog.a   ${CMAKE_CURRENT_SOURCE_DIR}/zloglib/lib)
find_library(ssl_lib libssl.a   ${CMAKE_CURRENT_SOURCE_DIR}/openssl/lib)
find_library(crypto_lib libcrypto.a   ${CMAKE_CURRENT_SOURCE_DIR}/openssl/lib)
find_library(srtp2_lib libsrtp2.a   ${CMAKE_CURRENT_SOURCE_DIR}/srtp/lib)

target_link_libraries(${CMAKE_PROJECT_NAME} erizo net ${srtp2_lib} ${zlog_lib} ${ssl_lib}  ${crypto_lib}   dl pthread )

target_include_directories(${CMAKE_PROJECT_NAME} PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/
        ${CMAKE_CURRENT_SOURCE_DIR}/zloglib/include
        ${CMAKE_CURRENT_SOURCE_DIR}/openssl/include
        ${CMAKE_CURRENT_SOURCE_DIR}/srtp/include
        ${CMAKE_CURRENT_SOURCE_DIR}/erizo
)