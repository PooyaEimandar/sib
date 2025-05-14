cmake_minimum_required(VERSION 3.28...4.0)

project(sib
  VERSION 1.0.0
  DESCRIPTION "A high-performance and cross-platform C++ modules optimized for streaming and rendering."
)

# required packages
find_package(Git REQUIRED)
include(FetchContent)
set(FETCHCONTENT_QUIET OFF)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "Build type" FORCE)
  message(STATUS "CMAKE_BUILD_TYPE not set. Defaulting to Debug.")
endif()

# set C/CXX standards
option(SIB_BUILD_BENCH "Build benchmarks" ON)
option(SIB_BUILD_TEST "Build tests" ON)
option(SIB_NET_HTTP "Enable HTTP3/2/1.1 server based on Facebook's Proxygen" ON)
option(SIB_NET_TCP "Enable TCP networking" OFF)
option(SIB_NET_UDP "Enable UDP networking" OFF)
option(SIB_DB_FDB "Enable FoundationDB" ON)

set(FOLLY_VERSION "v2025.05.12.00" CACHE STRING "set the folly version")
set(C_STANDARD 17 CACHE STRING "C standard to use")
set(CXX_STANDARD 20 CACHE STRING "C++ standard to use. Minimum standard is 20")
set(CMAKE_C_STANDARD ${C_STANDARD})
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD ${CXX_STANDARD})
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(THREADS_PREFER_PTHREAD_FLAG TRUE)

# set C++ flags
add_compile_options(-fexceptions)
if(APPLE)
    add_compile_options(-Wno-deprecated-builtins -Wno-nullability-completeness)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -stdlib=libc++ -lc++abi")
endif()

# Sanitizer options
option(ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(ENABLE_TSAN "Enable ThreadSanitizer" OFF)

if(ENABLE_ASAN AND ENABLE_TSAN)
    message(FATAL_ERROR "ASAN and TSAN cannot be enabled at the same time.")
endif()

if(ENABLE_ASAN)
    message(STATUS "AddressSanitizer enabled")
    set(SANITIZER_FLAGS "-fsanitize=address" "-fno-omit-frame-pointer")
elseif(ENABLE_TSAN)
    message(STATUS "ThreadSanitizer enabled")
    set(SANITIZER_FLAGS "-fsanitize=thread" "-fno-omit-frame-pointer")
endif()

if(SANITIZER_FLAGS)
    add_compile_options(${SANITIZER_FLAGS})
    add_link_options(${SANITIZER_FLAGS})
endif()

# setup SIB definitions
get_cmake_property(_vars VARIABLES)
foreach (_var ${_vars})
    string(FIND ${_var} "SIB_" out)
    if(("${out}" EQUAL 0) AND ("(${${_var}}" MATCHES ON))
        add_definitions("-D${_var}")
    endif()
endforeach()

set(PROXYGEN_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/dep/proxygen)
set(PROXYGEN_DEPS ${PROXYGEN_ROOT}/proxygen/_build/deps)

# check for dep
if(NOT (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/dep/proxygen/proxygen/_build/deps") OR 
   NOT EXISTS "${PROXYGEN_ROOT}/proxygen/_build/proxygen/httpserver/libproxygenhttpserver.a")
    message(STATUS "Running build.sh with build type: ${CMAKE_BUILD_TYPE}...")
    execute_process(
        COMMAND bash build.sh ${CMAKE_BUILD_TYPE} ${FOLLY_VERSION} ${SIB_NET_HTTP}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/dep
        RESULT_VARIABLE PROXYGEN_SCRIPT_RESULT
    )
    if(NOT PROXYGEN_SCRIPT_RESULT EQUAL 0)
        message(FATAL_ERROR "Running ./dep/build.sh failed with exit code ${PROXYGEN_SCRIPT_RESULT}")
    endif()
endif()

# check for dep
if(SIB_DB_FDB)
    message(STATUS "Running foundationDB.sh...")
    execute_process(
        COMMAND bash foundationDB.sh
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/dep
        RESULT_VARIABLE FDB_SCRIPT_RESULT
    )
    if(NOT FDB_SCRIPT_RESULT EQUAL 0)
        message(FATAL_ERROR "Running ./dep/foundationDB.sh failed with exit code ${FDB_SCRIPT_RESULT}")
    endif()
endif()

find_package(Boost REQUIRED COMPONENTS filesystem system context program_options)
if(Boost_FOUND)
    message(STATUS "Boost version: ${Boost_VERSION}")
    message(STATUS "Boost include dir: ${Boost_INCLUDE_DIRS}")
    message(STATUS "Boost libraries: ${Boost_LIBRARIES}")
    get_filename_component(BOOST_ROOT_HINT "${Boost_INCLUDE_DIRS}" DIRECTORY)
else()
    message(FATAL_ERROR "Boost was not found")
endif()

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

file(GLOB_RECURSE SYSTEM_DB_FILES
    "${CMAKE_CURRENT_SOURCE_DIR}/sib/database/*.cpp"
)
file(GLOB_RECURSE SYSTEM_SYS_FILES
    "${CMAKE_CURRENT_SOURCE_DIR}/sib/system/*.cpp"
)

add_library(${PROJECT_NAME} 
    sib/sib.cpp
    ${SYSTEM_DB_FILES}
    ${SYSTEM_SYS_FILES}
)

if(CMAKE_BUILD_TYPE MATCHES Debug)
    target_compile_definitions(${PROJECT_NAME} PRIVATE DEBUG _DEBUG)
else()
    target_compile_definitions(${PROJECT_NAME} PRIVATE NDEBUG)
endif()

target_include_directories(${PROJECT_NAME}
  PRIVATE
    ${Boost_INCLUDE_DIRS}
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${PROXYGEN_ROOT}
    ${PROXYGEN_ROOT}/proxygen/_build/generated
    ${PROXYGEN_DEPS}/include
    $<$<AND:$<BOOL:${SIB_DB_FDB}>,$<PLATFORM_ID:Darwin>>:/usr/local/include/foundationdb>
    $<$<AND:$<BOOL:${SIB_DB_FDB}>,$<PLATFORM_ID:Linux>>:/usr/include/foundationdb>
    $<$<PLATFORM_ID:Darwin>:/opt/homebrew/Cellar/double-conversion/3.3.1/include>
    $<$<PLATFORM_ID:Darwin>:/opt/homebrew/Cellar/gflags/2.2.2/include>
)

target_link_directories(${PROJECT_NAME}
    PRIVATE
    /usr/local/lib/
    /opt/homebrew/lib/
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/dep/proxygen/proxygen/_build/deps/lib
    /opt/homebrew/Cellar/double-conversion/3.3.1/lib
    /opt/homebrew/Cellar/gflags/2.2.2/lib
)

if(APPLE)
    find_library(FDB_C_LIBRARY fdb_c PATHS /usr/local/lib REQUIRED)
    find_library(CoreFoundation_Framework CoreFoundation)
    find_library(CoreServices_Framework CoreServices)
    find_library(Security_Framework Security)
    target_link_libraries(${PROJECT_NAME} PRIVATE 
        ${CoreFoundation_Framework}
        ${CoreServices_Framework}
        ${Security_Framework}
    )
elseif(UNIX)
    set(FDB_C_LIBRARY fdb_c)
    target_link_libraries(${PROJECT_NAME} PRIVATE unwind iberty)
endif()

set(LIBS
    Threads::Threads
    Boost::filesystem
    Boost::system
    Boost::context
    Boost::program_options
    double-conversion
    gflags
    folly
    $<$<PLATFORM_ID:Linux>:atomic>
    $<$<CONFIG:Debug>:fmtd>
    $<$<NOT:$<CONFIG:Debug>>:fmt>
    $<$<CONFIG:Debug>:glogd>
    $<$<NOT:$<CONFIG:Debug>>:glog>
    $<$<CONFIG:Debug>:eventd>
    $<$<NOT:$<CONFIG:Debug>>:event>
    $<$<BOOL:${SIB_DB_FDB}>:${FDB_C_LIBRARY}>
)

if(SIB_NET_HTTP)
   list(APPEND LIBS 
        ${PROXYGEN_ROOT}/proxygen/_build/proxygen/httpclient/samples/curl/libproxygencurl.a
        ${PROXYGEN_ROOT}/proxygen/_build/proxygen/httpserver/libproxygenhttpserver.a
        ${PROXYGEN_ROOT}/proxygen/_build/proxygen/httpserver/libproxygenhqloggerhelper.a
        ${PROXYGEN_ROOT}/proxygen/_build/proxygen/httpserver/libproxygendeviousbaton.a
        ${PROXYGEN_ROOT}/proxygen/_build/proxygen/lib/libproxygen.a
        
        fizz
        wangle
        mvfst_transport
        mvfst_client
        mvfst_server
        -lcityhash

        OpenSSL::SSL 
        OpenSSL::Crypto
    )

    if(NOT ENABLE_ASAN)
        list(APPEND LIBS -ljemalloc)
    else()
        message(STATUS "ASan enabled: disabling jemalloc to avoid allocator conflicts")
    endif()

endif()

target_link_libraries(${PROJECT_NAME} PRIVATE ${LIBS})

if (SIB_BUILD_BENCH)
    include(cmake/bench.cmake)
endif()

if(SIB_BUILD_TEST)
    include(cmake/test.cmake)
endif()

if(CMAKE_EXPORT_COMPILE_COMMANDS)
    include(cmake/clang.cmake)
endif()
