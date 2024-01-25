if(NOT (IS_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/aes-ni"))
  message(STATUS "ERROR: Not found ${CMAKE_CURRENT_SOURCE_DIR}/aes-ni")
  message(STATUS "NOTE: Missing a Git repository, please glone into \"${CMAKE_CURRENT_SOURCE_DIR}\":")
  message(STATUS "NOTE:   git clone https://github.com/tell/aes-ni")
endif()

add_subdirectory(aes-ni)
#add_custom_target(aes-ni_update
#  ALL COMMAND "git" "pull" "origin" "master" "||" "true"
#  WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/aesni")
#add_dependencies(aes-ni aes-ni_update)

