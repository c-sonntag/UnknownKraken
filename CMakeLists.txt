## @brief LibUnknownEcho
## @author Charly Lamothe

# --- PROJECT ---

PROJECT(unknownecho C)
cmake_minimum_required(VERSION 3.8)


# --- GLOBAL OPTIONS ---

set(CMAKE_VERBOSE_MAKEFILE on)

# Set as TRUE to link with openssl dependecies in lib folder. Set to FALSE otherwise.
set(OPENSSL_LOCAL_LINK TRUE)

if (WIN32)
    # Uncomment and chance path for non conventional Openssl root path
    set(OPENSSL_ROOT_DIR CACHE PATH "C:/OpenSSL-Win64")

    # Change the path if it's different of yours
    set(ZLIB_ROOT CACHE PATH "C:/zlib")
    set(ZLIB_INCLUDE_DIR "C:/zlib/include")
endif ()

# --- PATH ---

set(${CMAKE_CURRENT_SOURCE_DIR} ..)
set(SRC_PATH "${CMAKE_CURRENT_SOURCE_DIR}/src")
set(TESTS_PATH "${CMAKE_CURRENT_SOURCE_DIR}/tests")
set(EXAMPLES_PATH "${CMAKE_CURRENT_SOURCE_DIR}/examples")

if (CMAKE_BUILD_TYPE STREQUAL "Release")
	set(LIBRARY_OUTPUT_PATH "${CMAKE_CURRENT_SOURCE_DIR}/bin/release")
	set(EXAMPLES_OUTPUT_PATH "${CMAKE_CURRENT_SOURCE_DIR}/bin/release/examples")
	set(TESTS_OUTPUT_PATH "${CMAKE_CURRENT_SOURCE_DIR}/bin/release/tests")
elseif (CMAKE_BUILD_TYPE STREQUAL "Debug")
	set(LIBRARY_OUTPUT_PATH "${CMAKE_CURRENT_SOURCE_DIR}/bin/debug")
	set(EXAMPLES_OUTPUT_PATH "${CMAKE_CURRENT_SOURCE_DIR}/bin/debug/examples")
	set(TESTS_OUTPUT_PATH "${CMAKE_CURRENT_SOURCE_DIR}/bin/debug/tests")
endif ()


# --- COMPILE OPTIONS ---

if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")     ## (not debug)
   if(CMAKE_COMPILER_IS_GNUCXX)               ## (GNU COMMAND)
      add_compile_options("-O3")              ### No Optimization
      set(CMAKE_EXE_LINKER_FLAGS "-s")        ### Strip binary (only in release mode)
   endif ()
else ()
	add_compile_options("-g")
endif ()

if (UNIX)
	add_compile_options("-std=gnu99" "-pthread" "-ldl")
elseif (WIN32)
    add_compile_options("-std=c99" "-lkernel32" "-lntdll")
    if (CMAKE_BUILD_TYPE STREQUAL "Debug")
        add_compile_options("-static-libgcc" "-static-libstdc++" "-ggdb")
    endif ()
else ()
    add_compile_options("-std=c99")
endif ()

add_compile_options("-Wall" "-Werror" "-pedantic" "-fno-builtin")

if (WIN32)
    macro(get_WIN32_WINNT version)
        if (WIN32 AND CMAKE_SYSTEM_VERSION)
            set(ver ${CMAKE_SYSTEM_VERSION})
            string(REPLACE "." "" ver ${ver})
            string(REGEX REPLACE "([0-9])" "0\\1" ver ${ver})
            set(${version} "0x${ver}")
        endif()
    endmacro()
    get_WIN32_WINNT(ver)
    add_definitions(-D_WIN32_WINNT=${ver})
endif ()

# CCache

find_program(CCACHE_PROGRAM ccache)
if (CCACHE_PROGRAM)
    set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE "${CCACHE_PROGRAM}")
    set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK "${CCACHE_PROGRAM}")
endif()

# --- SEARCH LIB ---

# Search OpenSSL
if (UNIX)
	find_package(PkgConfig REQUIRED)
	pkg_search_module(OPENSSL REQUIRED openssl)
elseif (WIN32)
	find_package(OPENSSL REQUIRED)
endif ()
include_directories(${OPENSSL_INCLUDE_DIR})
message(STATUS "Using OpenSSL ${OPENSSL_VERSION}")

# Search ZLib
if (UNIX)
	pkg_search_module(ZLIB REQUIRED zlib)
elseif (WIN32)
	find_package(ZLIB REQUIRED)
endif ()
include_directories(${ZLIB_INCLUDE_DIRS})
message(STATUS "Using ZLib ${ZLIB_VERSION}")

# Search pthread

if (UNIX)
	find_package (Threads)
endif ()


# --- BUILD UNKNOWNECHO ---

# Options
set(PROJECT_NAME_STATIC "${PROJECT_NAME}_static")
set(PROJECT_NAME_SHARED "${PROJECT_NAME}_shared")

# Load source files
file(GLOB_RECURSE PROGRAM_TARGET_SRC_FILES "${SRC_PATH}/*.*")

# Build shared library
add_library(${PROJECT_NAME_SHARED} SHARED ${PROGRAM_TARGET_SRC_FILES})
target_include_directories(${PROJECT_NAME_SHARED} PUBLIC "${SRC_PATH}")
set_target_properties(${PROJECT_NAME_SHARED} PROPERTIES OUTPUT_NAME unknownecho)
if (OPENSSL_LOCAL_LINK)
    if (UNIX)
        target_link_libraries(${PROJECT_NAME_SHARED} "${CMAKE_SOURCE_DIR}/lib/linux/libssl.so.1.1" -ldl)
        target_link_libraries(${PROJECT_NAME_SHARED} "${CMAKE_SOURCE_DIR}/lib/linux/libcrypto.so.1.1" -ldl)
    elseif (WIN32)
        target_link_libraries(${PROJECT_NAME_SHARED} "${CMAKE_SOURCE_DIR}/lib/windows/libssl.lib" ws2_32 mswsock wsock32)
        target_link_libraries(${PROJECT_NAME_SHARED} "${CMAKE_SOURCE_DIR}/lib/windows/libcrypto.lib" ws2_32 mswsock wsock32)
    endif ()
else ()
	target_link_libraries(${PROJECT_NAME_SHARED} ${OPENSSL_LIBRARIES})
    if (WIN32)
        target_link_libraries(${PROJECT_NAME_SHARED} ws2_32 mswsock wsock32)
    endif ()
endif ()
target_link_libraries(${PROJECT_NAME_SHARED} ${ZLIB_LIBRARIES})
target_link_libraries(${PROJECT_NAME_SHARED} ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries(${PROJECT_NAME_SHARED} "-lei")

# Build static library
add_library(${PROJECT_NAME_STATIC} STATIC ${PROGRAM_TARGET_SRC_FILES})
target_include_directories(${PROJECT_NAME_STATIC} PUBLIC "${SRC_PATH}")
set_target_properties(${PROJECT_NAME_STATIC} PROPERTIES OUTPUT_NAME unknownecho)
if (OPENSSL_LOCAL_LINK)
	if (UNIX)
        target_link_libraries(${PROJECT_NAME_STATIC} "${CMAKE_SOURCE_DIR}/lib/linux/libssl.so.1.1" -ldl)
        target_link_libraries(${PROJECT_NAME_STATIC} "${CMAKE_SOURCE_DIR}/lib/linux/libcrypto.so.1.1" -ldl)
    elseif (WIN32)
        target_link_libraries(${PROJECT_NAME_STATIC} "${CMAKE_SOURCE_DIR}/lib/windows/libssl.lib" ws2_32 mswsock wsock32)
        target_link_libraries(${PROJECT_NAME_STATIC} "${CMAKE_SOURCE_DIR}/lib/windows/libcrypto.lib" ws2_32 mswsock wsock32)
    endif ()
else ()
    target_link_libraries(${PROJECT_NAME_STATIC} ${OPENSSL_LIBRARIES})
    if (WIN32)
        target_link_libraries(${PROJECT_NAME_STATIC} ws2_32 mswsock wsock32)
    endif ()
endif ()
target_link_libraries(${PROJECT_NAME_STATIC} ${ZLIB_LIBRARIES})
target_link_libraries(${PROJECT_NAME_STATIC} ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries(${PROJECT_NAME_STATIC} "-lei")


# --- INSTALL ---

if (UNIX)
    # Copy includes
    install(DIRECTORY ${CMAKE_SOURCE_DIR}/src/ DESTINATION /usr/include FILES_MATCHING PATTERN "*.h")

    # Copy static library
    install (TARGETS ${PROJECT_NAME_STATIC} ARCHIVE DESTINATION "/usr/lib")

    # Copy shared library
    install (TARGETS ${PROJECT_NAME_SHARED} LIBRARY DESTINATION "/usr/lib")
endif ()

# Build tests
#file(GLOB_RECURSE PROGRAM_TARGET_TESTS_FILES "${TESTS_PATH}/*.c")
#add_executable(ue_test ${PROGRAM_TARGET_TESTS_FILES})
#target_include_directories(ue_test PUBLIC "${TESTS_PATH}")
#target_link_libraries(ue_test ${PROJECT_NAME_STATIC})
#set_target_properties(ue_test PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${TESTS_OUTPUT_PATH})

# Build examples
file(GLOB files "${EXAMPLES_PATH}/*.c")
foreach (filePath ${files} )
	get_filename_component(executableName ${filePath} NAME_WE)
	message(STATUS "Build Program : ${executableName}")
	add_executable(${executableName} ${filePath})
	if (OPENSSL_LOCAL_LINK)
		if (UNIX)
            target_link_libraries(${executableName} "${CMAKE_SOURCE_DIR}/lib/linux/libssl.so.1.1" -ldl)
            target_link_libraries(${executableName} "${CMAKE_SOURCE_DIR}/lib/linux/libcrypto.so.1.1" -ldl)
        elseif (WIN32)
            target_link_libraries(${executableName} "${CMAKE_SOURCE_DIR}/lib/windows/libssl.lib" ws2_32 mswsock wsock32)
            target_link_libraries(${executableName} "${CMAKE_SOURCE_DIR}/lib/windows/libcrypto.lib" ws2_32 mswsock wsock32)
        endif ()
	else ()
        target_link_libraries(${executableName} ${OPENSSL_LIBRARIES})
        if (WIN32)
            target_link_libraries(${executableName} ws2_32 mswsock wsock32)
        endif ()
	endif ()
	target_link_libraries(${executableName} ${ZLIB_LIBRARIES})
    target_link_libraries(${executableName} ${PROJECT_NAME_STATIC})
    target_link_libraries(${executableName} "-lei")
    set_target_properties(${executableName} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${EXAMPLES_OUTPUT_PATH})
endforeach ()
