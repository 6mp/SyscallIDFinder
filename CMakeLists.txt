cmake_minimum_required(VERSION 3.19)
project(SyscallIDFinder)

set(CMAKE_CXX_STANDARD 20)
set(COMPILER_FLAGS "-MD /EHs -Wno-everything")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${COMPILER_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${COMPILER_FLAGS}")


include("FetchContent")
FetchContent_Declare(
        fmt
        GIT_REPOSITORY https://github.com/fmtlib/fmt.git
)
FetchContent_MakeAvailable(fmt)

file(GLOB_RECURSE SOURCES
        src/*.hpp
        src/*.h
        src/*.c
        src/*.cpp)
list(REMOVE_ITEM SOURCES "src/main.cpp")

add_executable(SyscallIDFinder ${SOURCES} src/main.cpp)
target_link_libraries(SyscallIDFinder PRIVATE fmt::fmt)
