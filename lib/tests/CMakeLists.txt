cmake_minimum_required(VERSION 3.10.1)
project(idpasstests)

if(EXISTS "$ENV{ANDROID_NDK_HOME}/sources/third_party/googletest/")
    set(GTEST $ENV{ANDROID_NDK_HOME}/sources/third_party/googletest/)
else()
    set(GTEST ${CMAKE_SOURCE_DIR}/googletest/)
endif()

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
set(PROTOGEN ${CMAKE_CURRENT_BINARY_DIR}/proto/idpasslite)
set(PROTOGEN2 ${CMAKE_CURRENT_BINARY_DIR}/proto/api)

set(idpasstests_DEPENDS 
    protobuf
    sodium
    idpasslite
    gtest
    )

add_custom_command(OUTPUT ${PROTOGEN}/idpasslite.pb.cc
    COMMAND ${CMAKE_COMMAND} -E make_directory ${PROTOGEN}
    COMMAND ${PROTOC_EXE} --proto_path=${PROTO} --cpp_out=${PROTOGEN} ${PROTO}/idpasslite.proto
    COMMENT "Compiling idpasslite.proto ..."
    )

add_custom_command(OUTPUT ${PROTOGEN2}/api.pb.cc
    COMMAND ${CMAKE_COMMAND} -E make_directory ${PROTOGEN2}
    COMMAND ${PROTOC_EXE} --proto_path=${PROTO} --cpp_out=${PROTOGEN2} ${PROTO}/api.proto
    COMMENT "Compiling api.proto ..."
    )

add_custom_target(testdata
    COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_SOURCE_DIR}/data/ ${CMAKE_CURRENT_BINARY_DIR}/data/
    COMMENT "Copying test data ..."
    )

link_directories(
    ${DEPENDENCIES_LIB}
    ${IDPASSAPI_LIB}
    )

add_executable(idpasstests
    ${PROTOGEN}/idpasslite.pb.cc
    ${PROTOGEN2}/api.pb.cc
    idpasstests.cpp
    ${IDPASSAPI_INCLUDE}/Cert.cpp
    )


include_directories(
    ${DEPENDENCIES_INCLUDE}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${IDPASSAPI_INCLUDE}
    ${GTEST}/include
    )


if ("${CMAKE_ANDROID_ARCH_ABI}" STREQUAL "x86-64")
	set(idpasstests_DEPENDS ${idpasstests_DEPENDS} pthread)
endif()

set(idpasstests_DEPENDS ${idpasstests_DEPENDS} pthread)
target_link_libraries(idpasstests ${idpasstests_DEPENDS})

add_dependencies(idpasstests testdata)
#install(TARGETS idpasstests DESTINATION ${CMAKE_INSTALL_PREFIX})
