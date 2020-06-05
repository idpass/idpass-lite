cmake_minimum_required(VERSION 3.10.1)
project(idpassapitests)

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
set(PROTOC_EXE ${CMAKE_SOURCE_DIR}/../../dependencies/build/desktop/bin/protoc)
set(PROTO ${CMAKE_SOURCE_DIR}/proto)
set(PROTOGEN ${CMAKE_CURRENT_BINARY_DIR}/protogen)
set(OUTDIR ${CMAKE_SOURCE_DIR}/outdir/${CMAKE_ANDROID_ARCH_ABI}/)
set(DLIBMODELS ${CMAKE_SOURCE_DIR}/dlibmodels)

set(idpassapitests_DEPENDS 
    protobuf
    sodium
    idpassapi    
    gtest
    )

add_custom_command(OUTPUT ${PROTOGEN}/card_access.pb.cc
    COMMAND ${CMAKE_COMMAND} -E make_directory ${PROTOGEN}
    COMMAND ${PROTOC_EXE} --proto_path=${PROTO} --cpp_out=${PROTOGEN} ${PROTO}/card_access.proto
    COMMENT "Compiling card_access.proto ..."
    )

add_executable(idpassapitests
    ${PROTOGEN}/card_access.pb.cc
    idpassapitests.cpp
    )

target_include_directories(idpassapitests PUBLIC
    ${DEPENDENCIES_INCLUDE}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_SOURCE_DIR}/../src/
    ${GTEST}/include
    )

target_link_directories(idpassapitests PUBLIC
    ${DEPENDENCIES_LIB}
    ${CMAKE_SOURCE_DIR}/../../build/idpassapi/desktop/
    )

if ("${CMAKE_ANDROID_ARCH_ABI}" STREQUAL "x86-64")
	set(idpassapitests_DEPENDS ${idpassapitests_DEPENDS} pthread)
endif()

set(idpassapitests_DEPENDS ${idpassapitests_DEPENDS} pthread)
target_link_libraries(idpassapitests ${idpassapitests_DEPENDS})

#install(TARGETS idpassapitests DESTINATION ${CMAKE_INSTALL_PREFIX})
