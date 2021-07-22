
add_library(erizo STATIC ${CMAKE_CURRENT_SOURCE_DIR}/MyIce/IceServer.cpp
                ${CMAKE_CURRENT_SOURCE_DIR}/MyIce/MyIceConnection.cpp
                ${CMAKE_CURRENT_SOURCE_DIR}/MyIce/MyLoop.cpp
                ${CMAKE_CURRENT_SOURCE_DIR}/MyIce/StunPacket.cpp
                ${CMAKE_CURRENT_SOURCE_DIR}/MyIce/UdpSocket.cpp
                ${CMAKE_CURRENT_SOURCE_DIR}/MyIce/Utiils.cpp
                ${CMAKE_CURRENT_SOURCE_DIR}/SdpInfo.cpp
                ${CMAKE_CURRENT_SOURCE_DIR}/IceConnection.cpp
                ${CMAKE_CURRENT_SOURCE_DIR}/dtls/DtlsTransport.cpp
                ${CMAKE_CURRENT_SOURCE_DIR}/StringUtil.cpp
                ${CMAKE_CURRENT_SOURCE_DIR}/SrtpChannel.cpp
)

target_include_directories(erizo PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/
        ${CMAKE_CURRENT_SOURCE_DIR}/../
        ${CMAKE_CURRENT_SOURCE_DIR}/../zloglib/include
        ${CMAKE_CURRENT_SOURCE_DIR}/../openssl/include
        ${CMAKE_CURRENT_SOURCE_DIR}/../srtp/include
)