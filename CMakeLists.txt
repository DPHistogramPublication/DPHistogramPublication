cmake_minimum_required(VERSION 3.10.0)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

enable_language(CXX)
project(mpc_laplace_noise)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${PROJECT_SOURCE_DIR}/cmake)
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/csv)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wpessimizing-move -Wredundant-move -pedantic -march=native -maes")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g -fsanitize=address")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -Ofast -DNDEBUG -maes")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} -Ofast -g -fsanitize=address")
set(CMAKE_CXX_FLAGS_MINSIZEREL "${CMAKE_CXX_FLAGS_MINSIZEREL} -Os -s -DNDEBUG")

set(OPENSSL_USE_STATIC_LIBS TRUE)

# find_package(Threads REQUIRED)
# find_package(fmt REQUIRED)
find_package(Boost REQUIRED COMPONENTS date_time regex system thread)
find_package(GMP REQUIRED)
find_package(OpenSSL REQUIRED)

# include("third_party/aes-ni/cmake/search_openmp.cmake")
# include("third_party/aes-ni/cmake/search_gmp.cmake")

# add_subdirectory("third_party")

# add_executable(${PROJECT_NAME} "src/main.cpp")
add_library(mpc_laplace_noise
    "src/util.cpp"
)

target_include_directories(mpc_laplace_noise PUBLIC "include")
target_include_directories(mpc_laplace_noise PUBLIC "/usr/include")

target_link_libraries(mpc_laplace_noise libmcl.a)

target_link_libraries(mpc_laplace_noise
#   fmt::fmt
  GMP::GMP
  Boost::headers Boost::date_time Boost::regex Boost::system
  OpenSSL::Crypto
)

enable_testing()
add_subdirectory("test")