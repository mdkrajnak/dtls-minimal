set(SOURCE ${PROJECT}/dtls-server)

add_executable(dtls-server 
    ${SOURCE}/common.hpp 
    ${SOURCE}/common.cpp 
    ${SOURCE}/dtls-server.cpp
)

find_package(libcoap-2 REQUIRED)

target_include_directories(dtls-server PRIVATE libcoap::libcoap)
target_link_libraries(dtls-server libcoap::libcoap) 

install(TARGETS dtls-server DESTINATION bin)
install(FILES ${PROJECT}/tools/selfsigned.pem DESTINATION etc/dtls-server)
