project(idpasslite)

if (NOT DEFINED CMAKE_ANDROID_ARCH_ABI)
    set(CMAKE_ANDROID_ARCH_ABI desktop)
else()
    set(JAVA_AWT_LIBRARY NotNeeded)
    set(JAVA_JVM_LIBRARY NotNeeded)
    set(JAVA_INCLUDE_PATH2 NotNeeded)
    set(JAVA_AWT_INCLUDE_PATH NotNeeded)
endif()

add_custom_command(OUTPUT $ENV{project}/dependencies/build/${CMAKE_ANDROID_ARCH_ABI}/
    COMMAND $ENV{project}/dependencies/rebuild.sh ${CMAKE_ANDROID_ARCH_ABI}
    COMMENT "Build dependency ${CMAKE_ANDROID_ARCH_ABI}"
    )

add_custom_target(${CMAKE_ANDROID_ARCH_ABI} DEPENDS $ENV{project}/dependencies/build/${CMAKE_ANDROID_ARCH_ABI}/
    COMMENT "Executing logical target:${CMAKE_ANDROID_ARCH_ABI}"
    )

if (WITH_JNI)
   find_package(Java REQUIRED)
   find_package(JNI REQUIRED)
   include(UseJava)
endif()

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

set(DEPENDENCIES_INCLUDE $ENV{project}/dependencies/build/${CMAKE_ANDROID_ARCH_ABI}/include/)
set(DEPENDENCIES_LIB $ENV{project}/dependencies/build/${CMAKE_ANDROID_ARCH_ABI}/lib/)

if ("${CMAKE_ANDROID_ARCH_ABI}" STREQUAL "macos")
    set(PROTOC_EXE $ENV{project}/dependencies/build/${CMAKE_ANDROID_ARCH_ABI}/bin/protoc)

    add_custom_command(OUTPUT ${PROTOC_EXE}
        COMMAND $ENV{project}/dependencies/rebuild.sh ${CMAKE_ANDROID_ARCH_ABI}
        COMMENT "Build dependency ${CMAKE_ANDROID_ARCH_ABI}"
        )
    
    add_custom_target(protoc_compiler DEPENDS ${PROTOC_EXE}
        COMMENT "Executing logical target:${CMAKE_ANDROID_ARCH_ABI}"
        )
elseif ("${CMAKE_ANDROID_ARCH_ABI}" STREQUAL "macosm1")
    set(PROTOC_EXE $ENV{project}/dependencies/build/${CMAKE_ANDROID_ARCH_ABI}/bin/protoc)

    add_custom_command(OUTPUT ${PROTOC_EXE}
        COMMAND $ENV{project}/dependencies/rebuild.sh ${CMAKE_ANDROID_ARCH_ABI}
        COMMENT "Build dependency ${CMAKE_ANDROID_ARCH_ABI}"
        )
    
    add_custom_target(protoc_compiler DEPENDS ${PROTOC_EXE}
        COMMENT "Executing logical target:${CMAKE_ANDROID_ARCH_ABI}"
        )
else()
    set(PROTOC_EXE $ENV{project}/dependencies/build/desktop/bin/protoc)
    add_custom_command(OUTPUT ${PROTOC_EXE}
        COMMAND $ENV{project}/dependencies/rebuild.sh ${CMAKE_ANDROID_ARCH_ABI}
        COMMENT "Build dependency ${CMAKE_ANDROID_ARCH_ABI}"
        )
    
    add_custom_target(protoc_compiler DEPENDS ${PROTOC_EXE}
        COMMENT "Executing logical target:${CMAKE_ANDROID_ARCH_ABI}"
        )
endif()

set(PROTO ${CMAKE_CURRENT_SOURCE_DIR}/proto)
set(PROTOGEN_IDPASSLITE ${CMAKE_CURRENT_BINARY_DIR}/proto/idpasslite/)
set(PROTOGEN_API ${CMAKE_CURRENT_BINARY_DIR}/proto/api/)

if (EMBED_MODELS)
    if(NOT EXISTS ${DEPENDENCIES_LIB}/libmodels.a)
        add_subdirectory(models)
    endif()

    add_definitions(-DEMBED_MODELS)
    set(idpass_DEPENDS 
        protobuf 
        sodium 
        dlib
        models
        )
else()
    set(idpass_DEPENDS 
        protobuf 
        sodium 
        dlib
        )
endif()

add_custom_command(OUTPUT ${PROTOGEN_IDPASSLITE}/idpasslite.pb.cc
    DEPENDS protoc_compiler
    COMMAND ${CMAKE_COMMAND} -E make_directory ${PROTOGEN_IDPASSLITE}
    COMMAND ${PROTOC_EXE} --proto_path=${PROTO} --cpp_out=${PROTOGEN_IDPASSLITE} ${PROTO}/idpasslite.proto
    COMMENT "Compiling idpasslite.proto ..."
    )

add_custom_command(OUTPUT ${PROTOGEN_API}/api.pb.cc
    DEPENDS protoc_compiler
    COMMAND ${CMAKE_COMMAND} -E make_directory ${PROTOGEN_API}
    COMMAND ${PROTOC_EXE} --proto_path=${PROTO} --cpp_out=${PROTOGEN_API} ${PROTO}/api.proto
    COMMENT "Compiling api.proto ..."
    )

if (WITH_JNI)
    link_directories(
        ${DEPENDENCIES_LIB}
        ${JNI_LIBRARIES}
        )
else()
    link_directories(
        ${DEPENDENCIES_LIB}
        )
endif()

if (WITH_JNI)
    add_library(idpasslite SHARED
        ${PROTOGEN_IDPASSLITE}/idpasslite.pb.cc
        ${PROTOGEN_API}/api.pb.cc
        ${CMAKE_CURRENT_SOURCE_DIR}/jni/idpass_jni.cpp
        idpass.cpp
        helper.cpp
        dlibapi.cpp
        qrcode.cpp
        bin16.cpp
        dxtracker.h
        CCertificate.h
        )
else()
    add_library(idpasslite SHARED
        ${PROTOGEN_IDPASSLITE}/idpasslite.pb.cc
        ${PROTOGEN_API}/api.pb.cc
        idpass.cpp
        helper.cpp
        dlibapi.cpp
        qrcode.cpp
        bin16.cpp
        dxtracker.h
        CCertificate.h
        )
endif()

add_dependencies(idpasslite ${CMAKE_ANDROID_ARCH_ABI})
if (WITH_JNI)
    target_compile_definitions (idpasslite PRIVATE WITH_JNI)
endif()

include_directories(
    ${DEPENDENCIES_INCLUDE}
    ${JNI_INCLUDE_DIRS}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${PROTOGEN_IDPASSLITE}
    )

if ("${CMAKE_ANDROID_ARCH_ABI}" STREQUAL "x86-64")
    set(idpass_DEPENDS ${idpass_DEPENDS} pthread)
endif()

# STATIC_LIBRARY, MODULE_LIBRARY, SHARED_LIBRARY, EXECUTABLE 
get_target_property(target_type idpasslite TYPE)
if (target_type STREQUAL "SHARED_LIBRARY")
    if (CMAKE_BUILD_TYPE STREQUAL Release)
        if (NOT CMAKE_ANDROID_ARCH_ABI STREQUAL macos)
	    add_custom_command(TARGET ${PROJECT_NAME}
            POST_BUILD
	    COMMAND ${CMAKE_STRIP} ${CMAKE_SHARED_LIBRARY_PREFIX}${PROJECT_NAME}${CMAKE_SHARED_LIBRARY_SUFFIX}
            )
        endif()
    endif()
endif ()

target_link_libraries(idpasslite PUBLIC ${idpass_DEPENDS} PUBLIC covcfg)
install(TARGETS idpasslite DESTINATION ${CMAKE_INSTALL_PREFIX})
