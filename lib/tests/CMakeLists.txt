
if(EXISTS "$ENV{ANDROID_NDK_HOME}/sources/third_party/googletest/")
    set(GTEST $ENV{ANDROID_NDK_HOME}/sources/third_party/googletest/)
else()
	set(GTEST ${CMAKE_CURRENT_SOURCE_DIR}/googletest/)
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

set(DEPENDENCIES_INCLUDE ${CMAKE_SOURCE_DIR}/dependencies/build/${CMAKE_ANDROID_ARCH_ABI}/include/)
set(DEPENDENCIES_LIB ${CMAKE_SOURCE_DIR}/dependencies/build/${CMAKE_ANDROID_ARCH_ABI}/lib/)
set(IDPASSAPI_INCLUDE ${CMAKE_SOURCE_DIR}/lib/src/)
set(IDPASSAPI_LIB ${CMAKE_SOURCE_DIR}/build/idpass/desktop/)
set(PROTOC_EXE ${CMAKE_SOURCE_DIR}/dependencies/build/desktop/bin/protoc)
set(PROTO ${CMAKE_CURRENT_SOURCE_DIR}/proto)
set(PROTOGEN_IDPASSLITE ${CMAKE_CURRENT_BINARY_DIR}/proto/idpasslite)
set(PROTOGEN_API ${CMAKE_CURRENT_BINARY_DIR}/proto/api)

set(idpasstests_DEPENDS 
    protobuf
    sodium
    idpasslite
    gtest
    )

add_custom_command(OUTPUT ${PROTOGEN_IDPASSLITE}/idpasslite.pb.cc
    COMMAND ${CMAKE_COMMAND} -E make_directory ${PROTOGEN_IDPASSLITE}
    COMMAND ${PROTOC_EXE} --proto_path=${PROTO} --cpp_out=${PROTOGEN_IDPASSLITE} ${PROTO}/idpasslite.proto
    COMMENT "Compiling idpasslite.proto ..."
    )

add_custom_command(OUTPUT ${PROTOGEN_API}/api.pb.cc
    COMMAND ${CMAKE_COMMAND} -E make_directory ${PROTOGEN_API}
    COMMAND ${PROTOC_EXE} --proto_path=${PROTO} --cpp_out=${PROTOGEN_API} ${PROTO}/api.proto
    COMMENT "Compiling api.proto ..."
    )

add_custom_target(testdata
	COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR}/data/ ${CMAKE_CURRENT_BINARY_DIR}/data/
    COMMENT "Copying test data ..."
    )

add_custom_target(testjnilink
	COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR}/jni/ ${CMAKE_CURRENT_BINARY_DIR}/jni/
    COMMENT "Copying JNI link test code ..."
    )

link_directories(
    ${DEPENDENCIES_LIB}
    ${IDPASSAPI_LIB}
    )

add_executable(idpasstests
    ${PROTOGEN_IDPASSLITE}/idpasslite.pb.cc
    ${PROTOGEN_API}/api.pb.cc
    idpasstests.cpp
    ${IDPASSAPI_INCLUDE}/bin16.cpp
    )

include_directories(
    ${DEPENDENCIES_INCLUDE}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${IDPASSAPI_INCLUDE}
    ${GTEST}/include
    ${PROTOGEN_IDPASSLITE}
    )

if ("${CMAKE_ANDROID_ARCH_ABI}" STREQUAL "x86-64")
	set(idpasstests_DEPENDS ${idpasstests_DEPENDS} pthread)
endif()

set(idpasstests_DEPENDS ${idpasstests_DEPENDS} pthread)
target_link_libraries(idpasstests ${idpasstests_DEPENDS})

add_dependencies(idpasstests testdata testjnilink)
#install(TARGETS idpasstests DESTINATION ${CMAKE_INSTALL_PREFIX})

add_test (NAME idpasstests COMMAND idpasstests)
add_test (NAME create_card_with_certificates_content_tampering COMMAND idpasstests)
add_test (NAME idpass_lite_create_card_with_face_certificates COMMAND idpasstests)
add_test (NAME idpass_lite_init_test COMMAND idpasstests)
add_test (NAME idpass_lite_create_card_with_face_test COMMAND idpasstests)
add_test (NAME generate_secretsignature_key COMMAND idpasstests)
add_test (NAME generate_encryption_key COMMAND idpasstests)
add_test (NAME face_template_test COMMAND idpasstests)
add_test (NAME create_card_verify_with_face COMMAND idpasstests)

#add_test (NAME create_card_with_certificates COMMAND idpasstests)
#add_test (NAME check_qrcode_md5sum COMMAND idpasstests)
#add_test (NAME createcard_manny_verify_as_brad COMMAND idpasstests)
#add_test (NAME cansign_and_verify_with_pin COMMAND idpasstests)
#add_test (NAME threading_multiple_instance_test COMMAND idpasstests)
#add_test (NAME threading_single_instance_test COMMAND idpasstests)
