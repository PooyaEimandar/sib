add_executable(sib_bench
  ${CMAKE_CURRENT_SOURCE_DIR}/dep/proxygen/proxygen/_build/deps/folly/folly/Benchmark.cpp
  bench/main.cpp
)

if (APPLE AND SIB_DB_FDB)
  get_filename_component(FDB_LIB_DIR ${FDB_C_LIBRARY} DIRECTORY)
  set_target_properties(sib_bench PROPERTIES
    BUILD_RPATH "${FDB_LIB_DIR}"
    INSTALL_RPATH "${FDB_LIB_DIR}"
  )
endif()

target_include_directories(sib_bench
  PRIVATE
    /usr/local/include
    ${Boost_INCLUDE_DIRS}
    ${PROXYGEN_ROOT}
    ${PROXYGEN_ROOT}/proxygen/_build/generated
    ${PROXYGEN_DEPS}/include
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/dep/proxygen/proxygen/_build/deps/include
    $<$<AND:$<BOOL:${SIB_DB_FDB}>,$<PLATFORM_ID:Darwin>>:/usr/local/include/foundationdb>
    $<$<AND:$<BOOL:${SIB_DB_FDB}>,$<PLATFORM_ID:Linux>>:/usr/include/foundationdb>
    $<$<PLATFORM_ID:Darwin>:/opt/homebrew/Cellar/double-conversion/3.3.1/include>
    $<$<PLATFORM_ID:Darwin>:/opt/homebrew/Cellar/gflags/2.2.2/include>
)

target_link_directories(sib_bench
    PRIVATE
    /usr/local/lib/
    /opt/homebrew/lib/
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/dep/proxygen/proxygen/_build/deps/lib
    /opt/homebrew/Cellar/double-conversion/3.3.1/lib
    /opt/homebrew/Cellar/gflags/2.2.2/lib
)

target_link_libraries(sib_bench
  PRIVATE
    folly
    OpenSSL::SSL 
    OpenSSL::Crypto
    ${PROJECT_NAME}
)
