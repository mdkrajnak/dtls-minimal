cmake_minimum_required(VERSION 3.13)
project(dtls-minimal VERSION 0.1.0 LANGUAGES CXX C)

set(PROJECT ${CMAKE_SOURCE_DIR}/..)
set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/modules)

add_subdirectory(dtls-server)
add_subdirectory(coap-server)
