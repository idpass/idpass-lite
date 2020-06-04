cmake_minimum_required(VERSION 3.10.1)
project(models)

add_library(models STATIC
    dlib_face_recognition_resnet_model_v1.dat.c
    shape_predictor_5_face_landmarks.dat.c
    )

add_custom_command(OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/dlib_face_recognition_resnet_model_v1.dat.c
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMAND xxd -i dlib_face_recognition_resnet_model_v1.dat dlib_face_recognition_resnet_model_v1.dat.c
    COMMENT "Converting model dlib_face_recognition_resnet_model_v1.dat ..."
    )

add_custom_command(OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/shape_predictor_5_face_landmarks.dat.c
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMAND xxd -i shape_predictor_5_face_landmarks.dat shape_predictor_5_face_landmarks.dat.c
    COMMENT "Converting model shape_predictor_5_face_landmarks.dat ..."
    )

if (LIBHEADERS_LIB)
    install(TARGETS models DESTINATION ${LIBHEADERS_LIB})
    #file(COPY ${CMAKE_CURRENT_BINARY_DIR}/libmodels.a DESTINATION ${LIBHEADERS_LIB})
    #add_custom_command(
    #    TARGET models POST_BUILD
    #    COMMAND ${CMAKE_COMMAND} -E copy
    #            ${CMAKE_CURRENT_BINARY_DIR}/libmodels.a
    #            ${LIBHEADERS_LIB}/libmodels.a)

    add_custom_command(TARGET models
        POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_BINARY_DIR}/libmodels.a ${LIBHEADERS_LIB}/libmodels.a
        COMMENT "*** Copying libmodels.a ***"
        )

else()
    install(TARGETS models DESTINATION ${CMAKE_INSTALL_PREFIX})
endif()

add_custom_command(TARGET models
    POST_BUILD
    COMMAND rm -f ${CMAKE_CURRENT_SOURCE_DIR}/*.c
    COMMENT "*** clean models ***"
    )

