set(SOURCE ${PROJECT}/coap-server)

add_executable(coap-server 
    ${SOURCE}/common.hpp 
    ${SOURCE}/common.cpp 
    ${SOURCE}/coap-server.cpp
)

find_package(libcoap-2 REQUIRED)

target_include_directories(coap-server PRIVATE libcoap::libcoap)
target_link_libraries(coap-server libcoap::libcoap) 

install(TARGETS coap-server DESTINATION bin)
