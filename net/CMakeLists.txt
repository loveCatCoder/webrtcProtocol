# make net static lib url:https://github.com/PHZ76/xop
file(GLOB NET_SRC ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)
add_library(net STATIC ${NET_SRC})