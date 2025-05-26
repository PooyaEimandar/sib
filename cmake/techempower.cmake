add_executable(sib_techempower
  techempower/main.cpp
)

target_include_directories(sib_techempower
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_directories(sib_techempower
    PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
)

target_link_libraries(sib_techempower
  PRIVATE
    Seastar::seastar
    ${PROJECT_NAME}
)
