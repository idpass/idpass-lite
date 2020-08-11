project(idpasslite)

if (NOT DEFINED CMAKE_ANDROID_ARCH_ABI)
    set(CMAKE_ANDROID_ARCH_ABI desktop)
else()
    set(JAVA_AWT_LIBRARY NotNeeded)
    set(JAVA_JVM_LIBRARY NotNeeded)
    set(JAVA_INCLUDE_PATH2 NotNeeded)
    set(JAVA_AWT_INCLUDE_PATH NotNeeded)
endif()

find_package(Java REQUIRED)
find_package(JNI REQUIRED)
include(UseJava)

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
    "${CMAKE_CURRENT_SOURCE_DIR}/dxtracker.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/dxtracker.h"
    )

set(CMAKE_SKIP_INSTALL_ALL_DEPENDENCY TRUE)

set(DEPENDENCIES_INCLUDE ${CMAKE_SOURCE_DIR}/dependencies/build/${CMAKE_ANDROID_ARCH_ABI}/include/)
set(DEPENDENCIES_LIB ${CMAKE_SOURCE_DIR}/dependencies/build/${CMAKE_ANDROID_ARCH_ABI}/lib/)
set(PROTOC_EXE ${CMAKE_SOURCE_DIR}/dependencies/build/desktop/bin/protoc)
set(PROTO ${CMAKE_CURRENT_SOURCE_DIR}/proto)
set(PROTOGEN ${CMAKE_CURRENT_BINARY_DIR}/proto/idpasslite/)
set(PROTOGEN2 ${CMAKE_CURRENT_BINARY_DIR}/proto/api/)

if(NOT EXISTS ${DEPENDENCIES_LIB}/libmodels.a)
    add_subdirectory(models)
endif()

set(idpass_DEPENDS 
    protobuf 
    sodium 
    dlib
    models
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

link_directories(
    ${DEPENDENCIES_LIB}
    ${JNI_LIBRARIES}
    )

add_library(idpasslite SHARED
    ${PROTOGEN}/idpasslite.pb.cc
    ${PROTOGEN2}/api.pb.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/jni/idpass_jni.cpp
    idpass.cpp
    helper.cpp
    dlibapi.cpp
    qrcode.cpp
    bin16.cpp
    dxtracker.h
    CCertificate.h
    )

target_compile_definitions (idpasslite PRIVATE _IDPASS_JNI_)

include_directories(
    ${DEPENDENCIES_INCLUDE}
    ${JNI_INCLUDE_DIRS}
    ${CMAKE_CURRENT_BINARY_DIR}
    )

if ("${CMAKE_ANDROID_ARCH_ABI}" STREQUAL "x86-64")
    set(idpass_DEPENDS ${idpass_DEPENDS} pthread)
endif()

# STATIC_LIBRARY, MODULE_LIBRARY, SHARED_LIBRARY, EXECUTABLE 
get_target_property(target_type idpasslite TYPE)
if (target_type STREQUAL "SHARED_LIBRARY")
    if (CMAKE_BUILD_TYPE STREQUAL Release)
	    add_custom_command(TARGET ${PROJECT_NAME}
            POST_BUILD
	    COMMAND ${CMAKE_STRIP} ${CMAKE_SHARED_LIBRARY_PREFIX}${PROJECT_NAME}${CMAKE_SHARED_LIBRARY_SUFFIX}
            )
    endif()
endif ()

target_link_libraries(idpasslite PUBLIC ${idpass_DEPENDS} PUBLIC covcfg)
install(TARGETS idpasslite DESTINATION ${CMAKE_INSTALL_PREFIX})
