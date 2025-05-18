# -----------------------------------------------------------------------------
# Clang-Format and Clang-Tidy Checks (std-style friendly)
# -----------------------------------------------------------------------------

# Inject macOS SDK for Homebrew Clang (macOS only)
if(APPLE)
  execute_process(
    COMMAND xcrun --show-sdk-path
    OUTPUT_VARIABLE MACOS_SDK
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )
  message(STATUS "Detected macOS SDK path: ${MACOS_SDK}")
  set(CMAKE_OSX_SYSROOT "${MACOS_SDK}" CACHE STRING "macOS SDK path")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -isysroot ${MACOS_SDK}")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -isysroot ${MACOS_SDK}")
endif()

# Detect clang-format and clang-tidy paths
if(APPLE)
  set(CLANG_FORMAT_BIN "/opt/homebrew/opt/llvm/bin/clang-format")
  set(CLANG_TIDY_BIN "/opt/homebrew/opt/llvm/bin/clang-tidy")
else()
  find_program(CLANG_FORMAT_BIN NAMES clang-format-18 clang-format-17 clang-format)
  find_program(CLANG_TIDY_BIN NAMES clang-tidy-18 clang-tidy-17 clang-tidy)
endif()

if(NOT CLANG_FORMAT_BIN)
  message(FATAL_ERROR "Clang-format not found.")
endif()

if(NOT CLANG_TIDY_BIN)
  message(FATAL_ERROR "Clang-tidy not found.")
endif()

message(STATUS "clang-format: ${CLANG_FORMAT_BIN}")
message(STATUS "clang-tidy: ${CLANG_TIDY_BIN}")

file(GLOB_RECURSE ALL_SOURCE_FILES CONFIGURE_DEPENDS
  ${CMAKE_SOURCE_DIR}/sib/*.[ch]pp
  ${CMAKE_SOURCE_DIR}/sib/*.h
)

# -------------------------------
# Clang-Format
# -------------------------------
set(CLANG_FORMAT_STAMP ${CMAKE_BINARY_DIR}/.clang-format-stamp)
set(CLANG_FORMAT_SCRIPT ${CMAKE_BINARY_DIR}/check-format.sh)

file(WRITE ${CLANG_FORMAT_SCRIPT} "#!/bin/bash\n")
file(APPEND ${CLANG_FORMAT_SCRIPT} "UPDATED=()\n")
foreach(SRC ${ALL_SOURCE_FILES})
  file(APPEND ${CLANG_FORMAT_SCRIPT} "[ \"${SRC}\" -nt \"${CLANG_FORMAT_STAMP}\" ] && UPDATED+=(\"${SRC}\")\n")
endforeach()
file(APPEND ${CLANG_FORMAT_SCRIPT}
"if [ \${#UPDATED[@]} -ne 0 ]; then\n"
"  echo \"Running clang-format on modified files...\"\n"
"  \"${CLANG_FORMAT_BIN}\" --dry-run --Werror \"\${UPDATED[@]}\" || exit 1\n"
"  touch \"${CLANG_FORMAT_STAMP}\"\n"
"else\n"
"  echo \"No format changes detected.\"\n"
"fi\n")

add_custom_target(clang-format-check
  COMMAND bash ${CLANG_FORMAT_SCRIPT}
  COMMENT "Incremental clang-format check"
)

# -------------------------------
# Clang-Tidy
# -------------------------------
set(CLANG_TIDY_STAMP ${CMAKE_BINARY_DIR}/.clang-tidy-stamp)
set(CLANG_TIDY_SCRIPT ${CMAKE_BINARY_DIR}/check-tidy.sh)

# Collect only files in sib/test and sib/bench
file(GLOB_RECURSE TEST_AND_BENCH_FILES CONFIGURE_DEPENDS
  ${CMAKE_SOURCE_DIR}/sib/test/*.[ch]pp
  ${CMAKE_SOURCE_DIR}/sib/test/*.h
  ${CMAKE_SOURCE_DIR}/sib/bench/*.[ch]pp
  ${CMAKE_SOURCE_DIR}/sib/bench/*.h
)

file(WRITE ${CLANG_TIDY_SCRIPT} "#!/bin/bash\n")
file(APPEND ${CLANG_TIDY_SCRIPT} "UPDATED=()\n")
foreach(SRC ${TEST_AND_BENCH_FILES})
  file(APPEND ${CLANG_TIDY_SCRIPT} "[ \"${SRC}\" -nt \"${CLANG_TIDY_STAMP}\" ] && UPDATED+=(\"${SRC}\")\n")
endforeach()
file(APPEND ${CLANG_TIDY_SCRIPT}
"if [ \${#UPDATED[@]} -ne 0 ]; then\n"
"  echo \"Running clang-tidy on test/bench files in parallel...\"\n"
"  printf \"%s\\n\" \"\${UPDATED[@]}\" | \\\n"
"    xargs -P\$(nproc) -n1 \"${CLANG_TIDY_BIN}\" -p \"${CMAKE_BINARY_DIR}\" -header-filter=\"^${CMAKE_SOURCE_DIR}/sib/(test|bench)/\" || exit 1\n"
"  touch \"${CLANG_TIDY_STAMP}\"\n"
"else\n"
"  echo \"No tidy changes detected in test/bench.\"\n"
"fi\n")

add_custom_target(clang-tidy-all
  COMMAND bash ${CLANG_TIDY_SCRIPT}
  COMMENT "Parallel clang-tidy for test and bench files"
)

# -------------------------------
# Combined Check
# -------------------------------
add_custom_target(code-quality-check ALL
  DEPENDS clang-format-check clang-tidy-all
  COMMENT "Code quality checks before build"
)

# -------------------------------
# Clang Version Info
# -------------------------------
if(APPLE)
  execute_process(
    COMMAND ${CLANG_FORMAT_BIN} --version
    OUTPUT_VARIABLE CLANG_VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )
  message(STATUS "Using Clang from Homebrew:\n${CLANG_VERSION}")
endif()
