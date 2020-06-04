cmake_minimum_required(VERSION 3.4.1)
project(entrypoint)

find_package(Java REQUIRED)
find_package(JNI REQUIRED)
include(UseJava)

add_library(entrypoint SHARED
    entrypoint.cpp
    )

include_directories(
    ${JNI_INCLUDE_DIRS}
    ${CMAKE_SOURCE_DIR}/../idpassapi/
    )

target_link_libraries(entrypoint ${JNI_LIBRARIES})

set(LIB_DIR $ENV{build}/idpassapi/desktop)
add_library(idpassapi SHARED IMPORTED)
set_target_properties(idpassapi
    PROPERTIES IMPORTED_LOCATION
    ${LIB_DIR}/libidpassapi.so
    )

target_link_libraries(entrypoint
    idpassapi
    )
