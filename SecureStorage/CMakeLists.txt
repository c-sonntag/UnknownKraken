#
## UnknownKrakenSecureStorage project
#
## Author Charly Lamothe (http://u4a.at)
## Author Christophe-Alexandre Sonntag (http://u4a.at)
## Under the Apache License 2.0.
#

# --- PROJECT ---
project(UnknownKrakenSecureStorage)
cmake_minimum_required(VERSION 3.4)
#
set(UnknownKrakenSecureStorage_VERSION_MAJOR 1)
set(UnknownKrakenSecureStorage_VERSION_MINOR 0)
set(PROJECT_UnknownKrakenSecureStorage_STATIC "${PROJECT_NAME}_static")
set(PROJECT_UnknownKrakenSecureStorage_SHARED "${PROJECT_NAME}_shared")

#
##
#

# --- SET CMAKE MODULES ---
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/../cmake;${CMAKE_MODULE_PATH}")
include("macros")

# --- LIB : UnknownKrakenUtils ---
if(TARGET UnknownKrakenUtils)
  link_libraries(UnknownKrakenUtils)
else()
  find_package(UnknownKrakenUtils REQUIRED)
  link_libraries(${UnknownKrakenUtils_LIBRARIES})
endif()
include_directories(${UnknownKrakenUtils_INCLUDE_DIRS} ${UnknownKrakenUtils_INCLUDE_DIR})
add_definitions(${UnknownKrakenUtils_DEFINITIONS})
link_directories(${UnknownKrakenUtils_DIRECTORIES})

# --- LIB : UnknownKrakenCrypto ---
if(TARGET UnknownKrakenCrypto)
  link_libraries(UnknownKrakenCrypto)
else()
  find_package(UnknownKrakenCrypto REQUIRED)
  link_libraries(${UnknownKrakenCrypto_LIBRARIES})
endif()
include_directories(${UnknownKrakenCrypto_INCLUDE_DIRS} ${UnknownKrakenCrypto_INCLUDE_DIR})
add_definitions(${UnknownKrakenCrypto_DEFINITIONS})
link_directories(${UnknownKrakenCrypto_DIRECTORIES})

# --- LIB : ZLIB ---
find_package(ZLIB REQUIRED)
include_directories(${ZLIB_INCLUDE_DIRS} ${ZLIB_INCLUDE_DIR})
link_directories(${ZLIB_DIRECTORIES})
link_libraries(${ZLIB_LIBRARIES})
add_definitions(${ZLIB_DEFINITIONS})

# --- LIB : OPENSSL ---
find_package(OPENSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR})
link_directories(${OPENSSL_DIRECTORIES})
#link_libraries(OpenSSL::SSL OpenSSL::Crypto)
link_libraries(${OPENSSL_CRYPTO_LIBRARY} ${OPENSSL_SSL_LIBRARY})
add_definitions(${OPENSSL_DEFINITIONS})

# --- LIB : Threads ---
if (UNIX)
  find_package(Threads REQUIRED)
  link_libraries(${Threads_LIBRARIES})
endif()



#
##
#

# --- TARGETS PATH ---
set(SRC_PATH "src")
set(HEADER_PATH "src")
set(EXAMPLES_PATH "examples")

# --- COMPILE OPTIONS ---
include_directories(${HEADER_PATH})
set(CMAKE_C_FLAGS "-fPIC")

# Compile options for Microsoft Visual Studio
if (MSVC)
    # Add O2 optimization if build type is Release
    if (CMAKE_BUILD_TYPE STREQUAL "Release")
        add_compile_options("$<$<CONFIG:RELEASE>:/O2>")
    endif ()
    add_compile_options("/W4")
    if (MSVC_VERSION GREATER_EQUAL 1900)
        add_compile_options("/permissive-") # Add /permissive- (kind of -pedantic) available since Visual Studio 2017
    endif ()
    add_compile_options("/W4")
    set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON) # This variable is used to initialize the property on each target as it is created
    set(CMAKE_C_FLAGS "${CMAKE_ENABLE_C11}") # Compile with C11 rules

    # Use secure functions by defaualt and suppress warnings about
    # deprecated" functions
    # TODO: try to remove this flags and fix the issue raised
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /D _CRT_SECURE_CPP_OVERLOAD_STANDARD_NAMES=1")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /D _CRT_SECURE_CPP_OVERLOAD_STANDARD_NAMES_COUNT=1")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /D _CRT_NONSTDC_NO_WARNINGS=1 /D _CRT_SECURE_NO_WARNINGS=1")
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang") # If compiler is Clang
    if (CMAKE_BUILD_TYPE STREQUAL "Release") # Release build mode
        # Set all this flags explicitly, even if some of them may be covered by -Wall, in order to fine-tune the warning flags we want
        # Note that -Weverything isn't available in some version of Mac and iOS
        # Source: https://github.com/macmade/SeriousCode
        add_compile_options("-Wall" "-Wbad-function-cast" "-Wcast-align" "-Wconversion" "-Wdeclaration-after-statement"
            "-Wdeprecated-implementations" "-Wextra" "-Wfloat-equal" "-Wformat=2" "-Wformat-nonliteral" "-Wfour-char-constants"
            "-Wimplicit-atomic-properties" "-Wmissing-braces" "-Wmissing-declarations" "-Wmissing-field-initializers"
            "-Wmissing-format-attribute" "-Wmissing-noreturn" "-Wmissing-prototypes" "-Wnested-externs" "-Wnewline-eof"
            "-Wold-style-definition" "-Woverlength-strings" "-Wparentheses" "-Wpointer-arith" "-Wredundant-decls"
            "-Wreturn-type" "-Wsequence-point" "-Wshadow" "-Wshorten-64-to-32" "-Wsign-compare" "-Wsign-conversion"
            "-Wstrict-prototypes" "-Wstrict-selector-match" "-Wswitch -Wswitch-default" "-Wswitch-enum" "-Wundeclared-selector"
            "-Wuninitialized" "-Wunknown-pragmas" "-Wunreachable-code" "-Wunused-function" "-Wunused-label" "-Wunused-parameter"
            "-Wunused-value" "-Wunused-variable" "-Wwrite-strings")
    else ()
        # Minimum flags for debug mode
        add_compile_options("-Wall" "-Werror" "-Wextra" "-g")
    endif ()
else ()
    # Unix plateform
    if (UNIX)
        add_compile_options("-std=gnu11" "-pthread" "-ldl")
        if (CMAKE_BUILD_TYPE STREQUAL "Release") # Release build mode
            if (CMAKE_COMPILER_IS_GNUCC) # GNU compiler
                add_compile_options("-O2") # O2 optimization
                set(CMAKE_EXE_LINKER_FLAGS "-s") # Strip binary (only in release mode as it prevent debugging)

                # Hardening options
                ## -fstack-protector-strong
                ### Stack smashing protector
                ## -D_FORTIFY_SOURCE=2
                ### Compile-time protection against static sized buffer overflows.
                ### No known regressions or performance loss
                ## -Wl,-z,now
                ### Disable lazy binding
                ## -Wl,-z,relro
                ### Read-only segments after relocation
                add_compile_options("-D_FORTIFY_SOURCE=2" "-Wl,-z,now" "-Wl,-z,relro")
                if (CMAKE_COMPILER_IS_GNUCC VERSION_GREATER 4.9)
                    add_compile_options("-fstack-protector-strong")
                endif ()
            endif ()
        else () # Debug mode
            add_compile_options("-g") # Add debug symbols
        endif ()
    endif ()
    # It should work on any unix platform ?
    if (CMAKE_BUILD_TYPE STREQUAL "Release") # Release mode
        add_compile_options("$<$<CONFIG:RELEASE>:-O2>" "-fno-builtin")
    endif ()
    ## -Werror=format-security
    ### Reject potentially unsafe format string arguments
    ## -Werror=implicit-function-declaration
    ### Reject missing function prototypes
    #add_compile_options("-Wall" "-Wextra" "-Werror" "-pedantic" "-Werror=format-security" "-Werror=implicit-function-declaration")
    add_compile_options("-Wall" "-Wextra" "-pedantic" "-Werror=format-security" "-Werror=implicit-function-declaration")
endif ()

if (WIN32)
    macro(get_WIN32_WINNT version)
    if (WIN32 AND CMAKE_SYSTEM_VERSION)
        set(ver ${CMAKE_SYSTEM_VERSION})
        string(REPLACE "." "" ver ${ver})
        string(REGEX REPLACE "([0-9])" "0\\1" ver ${ver})
        set(${version} "0x${ver}")
    endif ()
    endmacro()
    get_WIN32_WINNT(ver)
    add_definitions(-D_WIN32_WINNT=${ver})
endif ()


#
##
#

# --- BUILD OPTIONS : STATIC/SHARED ---
SET(UnknownKrakenSecureStorage_SHARED ON CACHE BOOL "Build shared UnknownKrakenSecureStorage library")
SET(UnknownKrakenSecureStorage_STATIC ON CACHE BOOL "Build static UnknownKrakenSecureStorage library")

# --- CHECK BUILD OPTIONS ---
if( (NOT ${UnknownKrakenSecureStorage_SHARED}) AND (NOT ${UnknownKrakenSecureStorage_STATIC}) )
  message(FATAL_ERROR, "\n\n   !! Require one of SHARED or STATIC for UnknownKrakenSecureStorage !! \n\n")
  set(UnknownKrakenSecureStorage_FOUND OFF)
  return()
endif()

#
##
#

# --- BUILD OPTIONS  ---
set(UnknownKrakenSecureStorage_BUILD_TOOLS ON CACHE BOOL "Build tools for UnknownKrakenSecureStorage library")
set(UnknownKrakenSecureStorage_BUILD_EXAMPLES ON CACHE BOOL "Build examples for UnknownKrakenSecureStorage library")
set(UnknownKrakenSecureStorage_BUILD_TESTS ON CACHE BOOL "Build tests for UnknownKrakenSecureStorage library")

#
##
#

# CCache
find_program(CCACHE_PROGRAM ccache)
if (CCACHE_PROGRAM)
  set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE "${CCACHE_PROGRAM}")
  set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK "${CCACHE_PROGRAM}")
endif()

#
##
#


# --- TARGETS FILES ---
file(GLOB_RECURSE TARGET_SRC_FILES "${SRC_PATH}/*.cpp" "${SRC_PATH}/*.c")
file(GLOB_RECURSE TARGET_HEADER_FILES "${HEADER_PATH}/*.h" "${HEADER_PATH}/*.hpp")

# --- BUILDS LIB TARGET STATIC ---
if(${UnknownKrakenSecureStorage_STATIC})
  add_library(${PROJECT_UnknownKrakenSecureStorage_STATIC} STATIC ${TARGET_SRC_FILES} ${TARGET_HEADER_FILES})
  set_target_properties(${PROJECT_UnknownKrakenSecureStorage_STATIC} PROPERTIES OUTPUT_NAME ${PROJECT_NAME})

  # --- INSTALL LIB ---
  install(TARGETS ${PROJECT_UnknownKrakenSecureStorage_STATIC}
          LIBRARY DESTINATION "lib"
          ARCHIVE DESTINATION "lib")

endif()

# --- BUILDS LIB TARGET SHARED ---
if(${UnknownKrakenSecureStorage_SHARED})
  add_library(${PROJECT_UnknownKrakenSecureStorage_SHARED} SHARED ${TARGET_SRC_FILES} ${TARGET_HEADER_FILES})
  set_target_properties(${PROJECT_UnknownKrakenSecureStorage_SHARED} PROPERTIES OUTPUT_NAME ${PROJECT_NAME})

  # --- INSTALL LIB ---
  install(TARGETS ${PROJECT_UnknownKrakenSecureStorage_SHARED}
          RUNTIME DESTINATION "bin"
          LIBRARY DESTINATION "lib"
          ARCHIVE DESTINATION "lib")


endif()

# --- INSTALL INCLUDE ---
install(DIRECTORY "${HEADER_PATH}/" DESTINATION "include" FILES_MATCHING PATTERN "*.h")
UnknownKraken_MarkLibrary(UnknownKrakenSecureStorage)

#
##
#

# --- SUB BUILD LINKING ---
set(UnknownKrakenSecureStorage_INCLUDE_DIRS "${CMAKE_CURRENT_LIST_DIR}/${HEADER_PATH}")
set(UnknownKrakenSecureStorage_DEFINITIONS)
set(UnknownKrakenSecureStorage_DIRECTORIES)
if(UnknownKrakenSecureStorage_SHARED)
  set(UnknownKrakenSecureStorage ${PROJECT_UnknownKrakenSecureStorage_SHARED})
elseif(UnknownKrakenSecureStorage_STATIC)
  set(UnknownKrakenSecureStorage ${PROJECT_UnknownKrakenSecureStorage_STATIC})
endif()
set(UnknownKrakenSecureStorage_INCLUDE_DIRS ${UnknownKrakenSecureStorage_INCLUDE_DIRS} PARENT_SCOPE)
set(UnknownKrakenSecureStorage_DEFINITIONS ${UnknownKrakenSecureStorage_DEFINITIONS} PARENT_SCOPE)
set(UnknownKrakenSecureStorage ${UnknownKrakenSecureStorage} PARENT_SCOPE)
add_library(UnknownKrakenSecureStorage ALIAS ${UnknownKrakenSecureStorage})


#
##
#

# --- ADD SUB BUILD  ---
link_libraries(UnknownKrakenSecureStorage)

# --- BUILDS TOOLS ---
if(${UnknownKrakenSecureStorage_BUILD_TOOLS})
  ## TODO
endif()

# --- BUILDS EXAMPLES ---
if(${UnknownKrakenSecureStorage_BUILD_EXAMPLES})

  file(GLOB files "${EXAMPLES_PATH}/*.c")
  foreach (filePath ${files} )

    # --- NEW EXAMPLE ---
    get_filename_component(executableName ${filePath} NAME_WE)
    #message(STATUS "Build example : ${executableName}")
    add_executable(${executableName} ${filePath})
    if (UNIX)
        target_link_libraries(${executableName} "-ldl")
    endif ()

    # --- INSTALL EXAMPLE ---
    install(TARGETS ${executableName} RUNTIME DESTINATION "bin")

  endforeach ()

endif()

# --- BUILDS TESTS ---
if(${UnknownKrakenSecureStorage_BUILD_TESTS})
  ## TODO
endif()

