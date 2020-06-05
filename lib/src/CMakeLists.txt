cmake_minimum_required(VERSION 3.10.1)
project(idpassapi)

find_package(Git)
if(GIT_FOUND)
    execute_process(
        COMMAND ${GIT_EXECUTABLE} rev-parse HEAD
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        OUTPUT_VARIABLE DXTRACKER
        ERROR_QUIET
        OUTPUT_STRIP_TRAILING_WHITESPACE
        )
endif()

set(DXTRACKER "DXTRACKER ${DXTRACKER}")

configure_file (
    "${CMAKE_SOURCE_DIR}/dxtracker.h.in"
    "${CMAKE_BINARY_DIR}/dxtracker.h"
    )

set(CMAKE_SKIP_INSTALL_ALL_DEPENDENCY TRUE)

if (NOT DEFINED CMAKE_ANDROID_ARCH_ABI)
    set(CMAKE_ANDROID_ARCH_ABI desktop)
endif()

set(DEPENDENCIES_INCLUDE ${CMAKE_SOURCE_DIR}/../../dependencies/build/${CMAKE_ANDROID_ARCH_ABI}/include/)
set(DEPENDENCIES_LIB ${CMAKE_SOURCE_DIR}/../../dependencies/build/${CMAKE_ANDROID_ARCH_ABI}/lib/)
set(PROTOC_EXE ${CMAKE_SOURCE_DIR}/../../dependencies/build/desktop/bin/protoc)
set(PROTO ${CMAKE_SOURCE_DIR}/proto)
set(PROTOGEN ${CMAKE_CURRENT_BINARY_DIR}/protogen)
set(OUTDIR ${CMAKE_SOURCE_DIR}/outdir/${CMAKE_ANDROID_ARCH_ABI}/)
set(DLIBMODELS ${CMAKE_SOURCE_DIR}/models)

if(NOT EXISTS ${DEPENDENCIES_LIB}/libmodels.a)
    add_subdirectory(models)
endif()

set(idpassapi_DEPENDS 
    protobuf 
    sodium 
    dlib
    models
    )

add_custom_command(OUTPUT ${PROTOGEN}/card_access.pb.cc
    COMMAND ${CMAKE_COMMAND} -E make_directory ${PROTOGEN}
    COMMAND ${PROTOC_EXE} --proto_path=${PROTO} --cpp_out=${PROTOGEN} ${PROTO}/card_access.proto
    COMMENT "Compiling card_access.proto ..."
    )

add_library(idpassapi SHARED
    ${PROTOGEN}/card_access.pb.cc
    idpassapi.cpp
    helper.cpp
    dlibapi.cpp
    qrcode.cpp
    bin16.cpp
    dxtracker.h
    )

# Dlib threshold adjustment from 0.6 to 0.42 
target_compile_definitions(idpassapi PRIVATE FACE_DIFF=0.42)

target_include_directories(idpassapi PUBLIC
    ${DEPENDENCIES_INCLUDE}
    ${CMAKE_CURRENT_BINARY_DIR}
    )

target_link_directories(idpassapi PUBLIC
    ${DEPENDENCIES_LIB}
    )

if ("${CMAKE_ANDROID_ARCH_ABI}" STREQUAL "x86-64")
    set(idpassapi_DEPENDS ${idpassapi_DEPENDS} pthread)
endif()

# STATIC_LIBRARY, MODULE_LIBRARY, SHARED_LIBRARY, EXECUTABLE 
get_target_property(target_type idpassapi TYPE)
if (target_type STREQUAL "SHARED_LIBRARY")
    if (CMAKE_BUILD_TYPE STREQUAL Release)
        add_custom_command(TARGET ${PROJECT_NAME}
            POST_BUILD
            COMMAND ${CMAKE_STRIP} ${CMAKE_SHARED_LIBRARY_PREFIX}${PROJECT_NAME}${CMAKE_SHARED_LIBRARY_SUFFIX}
            )
    endif()
endif ()

target_link_libraries(idpassapi ${idpassapi_DEPENDS})
install(TARGETS idpassapi DESTINATION ${CMAKE_INSTALL_PREFIX})
