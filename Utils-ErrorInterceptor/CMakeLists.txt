 ###############################################################################
 # Copyright (C) 2018 Charly Lamothe                                           #
 #                                                                             #
 # This file is part of LibErrorInterceptor.                                   #
 #                                                                             #
 #   Licensed under the Apache License, Version 2.0 (the "License");           #
 #   you may not use this file except in compliance with the License.          #
 #   You may obtain a copy of the License at                                   #
 #                                                                             #
 #   http://www.apache.org/licenses/LICENSE-2.0                                #
 #                                                                             #
 #   Unless required by applicable law or agreed to in writing, software       #
 #   distributed under the License is distributed on an "AS IS" BASIS,         #
 #   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  #
 #   See the License for the specific language governing permissions and       #
 #   limitations under the License.                                            #
 ###############################################################################

# --- PROJECT ---

PROJECT(ei C)
cmake_minimum_required(VERSION 3.8)


# --- GLOBAL OPTIONS ---

set(CMAKE_VERBOSE_MAKEFILE on)
set(BUILD_EXAMPLE on)

# --- PATH ---

set(${CMAKE_CURRENT_SOURCE_DIR} ..)
set(SRC_PATH "${CMAKE_CURRENT_SOURCE_DIR}/src")
set(EXAMPLES_PATH "${CMAKE_CURRENT_SOURCE_DIR}/examples")

if (CMAKE_BUILD_TYPE STREQUAL "Release")
    set(LIBRARY_OUTPUT_PATH "${CMAKE_CURRENT_SOURCE_DIR}/bin/release")
    set(EXAMPLES_OUTPUT_PATH "${CMAKE_CURRENT_SOURCE_DIR}/bin/release/examples")
elseif (CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(LIBRARY_OUTPUT_PATH "${CMAKE_CURRENT_SOURCE_DIR}/bin/debug")
    set(EXAMPLES_OUTPUT_PATH "${CMAKE_CURRENT_SOURCE_DIR}/bin/debug/examples")
endif ()


# --- COMPILE OPTIONS

set(CMAKE_C_FLAGS "-fPIC")

if (MSVC)
    # Use secure functions by defaualt and suppress warnings about
    #"deprecated" functions
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /D _CRT_SECURE_CPP_OVERLOAD_STANDARD_NAMES=1")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /D _CRT_SECURE_CPP_OVERLOAD_STANDARD_NAMES_COUNT=1")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /D _CRT_NONSTDC_NO_WARNINGS=1 /D _CRT_SECURE_NO_WARNINGS=1")
endif ()

if (LINUX)
    if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")     ## (not debug)
        if(CMAKE_COMPILER_IS_GNUCXX)              ## (GNU COMMAND)
            add_compile_options("-O3")            ### No Optimization
            set(CMAKE_EXE_LINKER_FLAGS "-s")      ### Strip binary (only in release mode)
        endif ()
    else ()
        add_compile_options("-g")
    endif ()
endif ()

if (UNIX)
    add_compile_options("-std=gnu99" "-pthread" "-ldl")
    add_compile_options("-Wall" "-pedantic" "-fno-builtin")
elseif (WIN32)
    #add_compile_options("std=c99" "lkernel32" "lntdll")
    if (CMAKE_BUILD_TYPE STREQUAL "Debug")
        add_compile_options("static-libgcc" "ggdb")
    endif ()
    set(CMAKE_C_FLAGS "${CMAKE_ENABLE_C99}")
endif ()

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

    set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
endif ()

# CCache

find_program(CCACHE_PROGRAM ccache)
if (CCACHE_PROGRAM)
    set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE "${CCACHE_PROGRAM}")
    set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK "${CCACHE_PROGRAM}")
endif()

# --- SEARCH LIB ---

# Search pthread

if (UNIX)
    find_package (Threads)
endif ()


# --- BUILD LIBERRORINTERCEPTOR ---

# Options
set(PROJECT_NAME_STATIC "${PROJECT_NAME}_static")
set(PROJECT_NAME_SHARED "${PROJECT_NAME}_shared")

# Load source files
file(GLOB_RECURSE PROGRAM_TARGET_SRC_FILES "${SRC_PATH}/*.*")

# Build shared library
add_library(${PROJECT_NAME_SHARED} SHARED ${PROGRAM_TARGET_SRC_FILES})
target_include_directories(${PROJECT_NAME_SHARED} PUBLIC "${SRC_PATH}")
set_target_properties(${PROJECT_NAME_SHARED} PROPERTIES OUTPUT_NAME ei)
target_link_libraries(${PROJECT_NAME_SHARED} ${CMAKE_THREAD_LIBS_INIT})

# Build static library
add_library(${PROJECT_NAME_STATIC} STATIC ${PROGRAM_TARGET_SRC_FILES})
target_include_directories(${PROJECT_NAME_STATIC} PUBLIC "${SRC_PATH}")
set_target_properties(${PROJECT_NAME_STATIC} PROPERTIES OUTPUT_NAME ei_static)
target_link_libraries(${PROJECT_NAME_STATIC} ${CMAKE_THREAD_LIBS_INIT})

# --- INSTALL ---

# Copy includes
install(DIRECTORY ${CMAKE_SOURCE_DIR}/src/ DESTINATION ${CMAKE_INSTALL_PREFIX}/include FILES_MATCHING PATTERN "*.h")

# Copy static library
install (
    TARGETS ${PROJECT_NAME_STATIC}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_PREFIX}/lib
    LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/lib
)

if (UNIX)
    install (
        TARGETS ${PROJECT_NAME_SHARED}
        LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/lib
        RUNTIME DESTINATION ${CMAKE_INSTALL_PREFIX}/lib
    )
elseif (WIN32)
    install (
        TARGETS ${PROJECT_NAME_SHARED}
        RUNTIME DESTINATION ${CMAKE_INSTALL_PREFIX}/lib
    )
endif ()

if (BUILD_EXAMPLE)
    # Build examples
    file(GLOB files "${EXAMPLES_PATH}/*.c")
    foreach (filePath ${files} )
        get_filename_component(executableName ${filePath} NAME_WE)
        add_executable(${executableName} ${filePath})
        target_link_libraries(${executableName} ${PROJECT_NAME_STATIC})
        set_target_properties(${executableName} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${EXAMPLES_OUTPUT_PATH})
    endforeach ()
endif ()
