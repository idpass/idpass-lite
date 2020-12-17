cmake_minimum_required (VERSION 3.10.1)
project(idpassmosip)

if(EXISTS "${CMAKE_SOURCE_DIR}/version.txt")
    file(READ "version.txt" ver)
    string(REGEX MATCH "VERSION_MAJOR ([0-9]*)" _ ${ver})
    set(ver_major ${CMAKE_MATCH_1})

    string(REGEX MATCH "VERSION_MINOR ([0-9]*)" _ ${ver})
    set(ver_minor ${CMAKE_MATCH_1})

    string(REGEX MATCH "VERSION_PATCH ([0-9]*)" _ ${ver})
    set(ver_patch ${CMAKE_MATCH_1})
endif()

message("semver: ${ver_major}.${ver_minor}.${ver_patch}")

if (ALWAYS)
    add_definitions(-DALWAYS)
endif()

add_library(covcfg INTERFACE)

if (COVERAGE AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  target_compile_options (covcfg INTERFACE -O0 -g --coverage)
  if (CMAKE_VERSION VERSION_GREATER_EQUAL 3.13)
    target_link_options(covcfg INTERFACE --coverage -O0 -g) 
  else()
    target_link_libraries(covcfg INTERFACE --coverage -O0 -g) 
  endif()	    
endif()

add_subdirectory (lib/src)

if (TESTAPP)
  enable_testing()
  add_subdirectory (lib/tests)
endif()
