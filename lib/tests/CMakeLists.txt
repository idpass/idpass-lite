cmake_minimum_required(VERSION 3.10.1)
project(idpasstests)

set(GTEST $ENV{ANDROID_NDK_HOME}/sources/third_party/googletest/)
add_library(gtest STATIC
    ${GTEST}/src/gtest_main.cc
    ${GTEST}/src/gtest-all.cc
    )

target_include_directories(gtest PRIVATE ${GTEST})
target_include_directories(gtest PUBLIC ${GTEST}/include)

if (NOT DEFINED CMAKE_ANDROID_ARCH_ABI)
    set(CMAKE_ANDROID_ARCH_ABI desktop)
endif()

set(DEPENDENCIES_INCLUDE ${CMAKE_SOURCE_DIR}/../../dependencies/build/${CMAKE_ANDROID_ARCH_ABI}/include/)
set(DEPENDENCIES_LIB ${CMAKE_SOURCE_DIR}/../../dependencies/build/${CMAKE_ANDROID_ARCH_ABI}/lib/)
set(IDPASSAPI_INCLUDE ${CMAKE_SOURCE_DIR}/../src/)
set(IDPASSAPI_LIB ${CMAKE_SOURCE_DIR}/../../build/idpass/desktop/)
set(PROTOC_EXE ${CMAKE_SOURCE_DIR}/../../dependencies/build/desktop/bin/protoc)
set(PROTO ${CMAKE_SOURCE_DIR}/proto)
set(PROTOGEN ${CMAKE_CURRENT_BINARY_DIR}/protogen)

set(idpasstests_DEPENDS 
    protobuf
    sodium
    idpass    
    gtest
    )

add_custom_command(OUTPUT ${PROTOGEN}/card_access.pb.cc
    COMMAND ${CMAKE_COMMAND} -E make_directory ${PROTOGEN}
    COMMAND ${PROTOC_EXE} --proto_path=${PROTO} --cpp_out=${PROTOGEN} ${PROTO}/card_access.proto
    COMMENT "Compiling card_access.proto ..."
    )

add_executable(idpasstests
    ${PROTOGEN}/card_access.pb.cc
    idpasstests.cpp
    )

target_include_directories(idpasstests PUBLIC
    ${DEPENDENCIES_INCLUDE}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${IDPASSAPI_INCLUDE}
    ${GTEST}/include
    )

target_link_directories(idpasstests PUBLIC
    ${DEPENDENCIES_LIB}
    ${IDPASSAPI_LIB}
    )

if ("${CMAKE_ANDROID_ARCH_ABI}" STREQUAL "x86-64")
	set(idpasstests_DEPENDS ${idpasstests_DEPENDS} pthread)
endif()

set(idpasstests_DEPENDS ${idpasstests_DEPENDS} pthread)
target_link_libraries(idpasstests ${idpasstests_DEPENDS})

#install(TARGETS idpasstests DESTINATION ${CMAKE_INSTALL_PREFIX})
