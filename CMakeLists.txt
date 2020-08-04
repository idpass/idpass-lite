cmake_minimum_required (VERSION 3.10.1)
project(idpassmosip)

add_library(covcfg INTERFACE)

if (COVERAGE AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  target_compile_options (covcfg INTERFACE -O0 -g --coverage)
  if (CMAKE_VERSION VERSION_GREATER_EQUAL 3.13)
    target_link_options(covcfg INTERFACE --coverage) 
  else()
    target_link_libraries(covcfg INTERFACE --coverage) 
  endif()	    
endif()

add_subdirectory (lib/src)

if (TESTAPP)
  enable_testing()
  add_subdirectory (lib/tests)
endif()
