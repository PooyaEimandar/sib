cmake_minimum_required(VERSION 3.25...4.0)

project(sib
  VERSION 1.0.0
  DESCRIPTION "A high-performance and cross-platform C++ modules optimized for networking and streaming."
)

# Required packages
find_package(Git REQUIRED)
include(CheckCXXCompilerFlag)
include(FetchContent)
set(FETCHCONTENT_QUIET OFF)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "Build type" FORCE)
  message(STATUS "CMAKE_BUILD_TYPE not set. Defaulting to Debug.")
endif()

# SIB options
option(SIB_TECHEMPOWER "Build TechEmpower benchmark" ON)
# option(SIB_BUILD_BENCH "Build benchmarks" OFF)
# option(SIB_BUILD_TEST "Build tests" OFF)
# option(SIB_NET_HTTP_SERVER "Enable HTTP3/2/1.1 server" ON)
# option(SIB_DB_FDB "Enable FoundationDB" OFF)

# Check compiler support for newer C++ versions

check_cxx_compiler_flag("-std=c++23" HAS_CPP23)
if(HAS_CPP23)
    set(DEFAULT_CXX_STANDARD 23)
else()
    check_cxx_compiler_flag("-std=c++20" HAS_CPP20)
    if(HAS_CPP20)
        set(DEFAULT_CXX_STANDARD 20)
    else()
        message(FATAL_ERROR "C++20 or later is required. Please update your compiler.")
    endif()
endif()

set(C_STANDARD 17 CACHE STRING "C standard to use")
set(CXX_STANDARD ${DEFAULT_CXX_STANDARD} CACHE STRING "C++ standard to use. Minimum standard is 20")
set(CMAKE_C_STANDARD ${C_STANDARD})
set(CMAKE_CXX_STANDARD ${CXX_STANDARD})
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(THREADS_PREFER_PTHREAD_FLAG TRUE)

# Apple-specific compiler flags
add_compile_options(-fexceptions)
if(APPLE)
  add_compile_options(-Wno-deprecated-builtins -Wno-nullability-completeness)
endif()

# Sanitizers
option(ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(ENABLE_TSAN "Enable ThreadSanitizer" OFF)

if(ENABLE_ASAN AND ENABLE_TSAN)
  message(FATAL_ERROR "ASAN and TSAN cannot be enabled at the same time.")
endif()

if(ENABLE_ASAN)
  message(STATUS "AddressSanitizer enabled")
  set(SANITIZER_FLAGS "-fsanitize=address" "-fno-omit-frame-pointer")
elif(ENABLE_TSAN)
  message(STATUS "ThreadSanitizer enabled")
  set(SANITIZER_FLAGS "-fsanitize=thread" "-fno-omit-frame-pointer")
endif()

if(SANITIZER_FLAGS)
  add_compile_options(${SANITIZER_FLAGS})
  add_link_options(${SANITIZER_FLAGS})
endif()

# Set preprocessor definitions for SIB_* options
get_cmake_property(_vars VARIABLES)
foreach (_var ${_vars})
  string(FIND ${_var} "SIB_" out)
  if(("${out}" EQUAL 0) AND ("(${${_var}}" MATCHES ON))
    add_definitions("-D${_var}")
  endif()
endforeach()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(SEASTAR_BUILD_TYPE "dev")
else()
    set(SEASTAR_BUILD_TYPE "release")
endif()

# Extend CMake prefix paths
list(APPEND CMAKE_PREFIX_PATH
  "${CMAKE_CURRENT_SOURCE_DIR}/dep/seastar/build/${SEASTAR_BUILD_TYPE}"
)
list(APPEND CMAKE_MODULE_PATH
 "${CMAKE_CURRENT_SOURCE_DIR}/dep/seastar/build/${SEASTAR_BUILD_TYPE}/_cooking/installed/lib/cmake/Seastar"
)

# Dependencies
find_package (Seastar REQUIRED)

# file(GLOB_RECURSE NETWORK_FILES "${CMAKE_CURRENT_SOURCE_DIR}/sib/network/*.cpp")
# file(GLOB_RECURSE DATABASE_FILES "${CMAKE_CURRENT_SOURCE_DIR}/sib/database/*.cpp")
# file(GLOB_RECURSE SYSTEM_FILES "${CMAKE_CURRENT_SOURCE_DIR}/sib/system/*.cpp")

# Main library
add_executable(${PROJECT_NAME} 
  sib/sib.cpp
  # ${NETWORK_FILES}
  # ${DATABASE_FILES}
  # ${SYSTEM_FILES}
)

# Compile definitions
if(CMAKE_BUILD_TYPE MATCHES Debug)
  target_compile_definitions(${PROJECT_NAME} PRIVATE DEBUG _DEBUG)
else()
  target_compile_definitions(${PROJECT_NAME} PRIVATE NDEBUG)
endif()

# Include dirs
target_include_directories(${PROJECT_NAME}
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Link directories
target_link_directories(${PROJECT_NAME}
  PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
)

# Link libraries
set(LIBS
  Seastar::seastar
)

if(APPLE)
  if (SIB_DB_FDB)
    find_library(FDB_C_LIBRARY fdb_c PATHS /usr/local/lib REQUIRED)
    list(APPEND LIBS ${FDB_C_LIBRARY})
  endif()
  find_library(CoreFoundation_Framework CoreFoundation)
  find_library(CoreServices_Framework CoreServices)
  find_library(Security_Framework Security)
  list(APPEND LIBS
    ${CoreFoundation_Framework}
    ${CoreServices_Framework}
    ${Security_Framework}
  )
elseif(UNIX)
  if (SIB_DB_FDB)
    list(APPEND LIBS fdb_c)
  endif()
  # list(APPEND LIBS atomic unwind iberty)
endif()

target_link_libraries(${PROJECT_NAME} PRIVATE ${LIBS})

# if(SIB_BUILD_TEST)
#   include(cmake/test.cmake)
# endif()

# if(SIB_BUILD_BENCH)
#   include(cmake/bench.cmake)
# endif()

#if(SIB_TECHEMPOWER)
#  include(cmake/techempower.cmake)
#endif()

# if(CMAKE_EXPORT_COMPILE_COMMANDS)
#   include(cmake/clang.cmake)
# endif()
