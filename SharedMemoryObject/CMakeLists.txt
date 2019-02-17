#
## UnknownKrakenSharedMemoryObject project
#
## Author Charly Lamothe (http://u4a.at)
## Author Christophe-Alexandre Sonntag (http://u4a.at)
## Under the Apache License 2.0.
#

# --- PROJECT ---
project(UnknownKrakenSharedMemoryObject)
cmake_minimum_required(VERSION 3.4)

#
set(UnknownKrakenSharedMemoryObject_VERSION_MAJOR 1)
set(UnknownKrakenSharedMemoryObject_VERSION_MINOR 0)
set(PROJECT_UnknownKrakenSharedMemoryObject_STATIC "${PROJECT_NAME}_static")
set(PROJECT_UnknownKrakenSharedMemoryObject_SHARED "${PROJECT_NAME}_shared")

#
##
#


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


#
##
#

# --- BUILD OPTIONS : STATIC/SHARED ---
SET(UnknownKrakenSharedMemoryObject_SHARED ON CACHE BOOL "Build shared UnknownKrakenSharedMemoryObject library")
SET(UnknownKrakenSharedMemoryObject_STATIC ON CACHE BOOL "Build static UnknownKrakenSharedMemoryObject library")

# --- CHECK BUILD OPTIONS ---
if( (NOT ${UnknownKrakenSharedMemoryObject_SHARED}) AND (NOT ${UnknownKrakenSharedMemoryObject_STATIC}) )
  message(FATAL_ERROR, "\n\n   !! Require one of SHARED or STATIC for UnknownKrakenSharedMemoryObject !! \n\n")
  set(UnknownKrakenSharedMemoryObject_FOUND OFF)
  return()
endif()

#
##
#

# --- BUILD OPTIONS  ---
set(UnknownKrakenSharedMemoryObject_BUILD_TOOLS ON CACHE BOOL "Build tools for UnknownKrakenSharedMemoryObject library")
set(UnknownKrakenSharedMemoryObject_BUILD_EXAMPLES ON CACHE BOOL "Build examples for UnknownKrakenSharedMemoryObject library")
set(UnknownKrakenSharedMemoryObject_BUILD_TESTS ON CACHE BOOL "Build tests for UnknownKrakenSharedMemoryObject library")

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
file(GLOB_RECURSE TARGET_API_SRC_FILES "${SRC_PATH}/uk/smo/api/*.c"  "${SRC_PATH}/uk/smo/api/*.cpp")
file(GLOB_RECURSE TARGET_API_HEADER_FILES "${HEADER_PATH}/uk/smo/api/*.h" "${HEADER_PATH}/uk/smo/api/*.hpp")

# --- TARGETS SPECIFIC PLATFORM FILES ---
set(TARGET_PLATFORM)
if (WIN32)
  set(TARGET_PLATFORM "windows")
else ()
  set(TARGET_PLATFORM "linux")
endif ()
file(GLOB_RECURSE TARGET_PLATFORM_SRC_FILES "${SRC_PATH}/uk/smo/impl/${TARGET_PLATFORM}/*.c"  "${SRC_PATH}/uk/smo/impl/${TARGET_PLATFORM}/*.cpp")
file(GLOB_RECURSE TARGET_PLATFORM_HEADER_FILES "${HEADER_PATH}/uk/smo/impl/${TARGET_PLATFORM}/*.h" "${HEADER_PATH}/uk/smo/impl/${TARGET_PLATFORM}/*.hpp")


# --- BUILDS LIB TARGET STATIC ---
if(${UnknownKrakenSharedMemoryObject_STATIC})
  add_library(${PROJECT_UnknownKrakenSharedMemoryObject_STATIC} STATIC ${TARGET_API_SRC_FILES} ${TARGET_API_HEADER_FILES} ${TARGET_PLATFORM_SRC_FILES} ${TARGET_PLATFORM_HEADER_FILES})
  set_target_properties(${PROJECT_UnknownKrakenSharedMemoryObject_STATIC} PROPERTIES OUTPUT_NAME ${PROJECT_NAME})

  # --- INSTALL LIB ---
  install(TARGETS ${PROJECT_UnknownKrakenSharedMemoryObject_STATIC}
          LIBRARY DESTINATION "lib"
          ARCHIVE DESTINATION "lib")

endif()

# --- BUILDS LIB TARGET SHARED ---
if(${UnknownKrakenSharedMemoryObject_SHARED})
  add_library(${PROJECT_UnknownKrakenSharedMemoryObject_SHARED} SHARED ${TARGET_API_SRC_FILES} ${TARGET_API_HEADER_FILES} ${TARGET_PLATFORM_SRC_FILES} ${TARGET_PLATFORM_HEADER_FILES})
  set_target_properties(${PROJECT_UnknownKrakenSharedMemoryObject_SHARED} PROPERTIES OUTPUT_NAME ${PROJECT_NAME})

  # --- INSTALL LIB ---
  install(TARGETS ${PROJECT_UnknownKrakenSharedMemoryObject_SHARED}
          RUNTIME DESTINATION "bin"
          LIBRARY DESTINATION "lib"
          ARCHIVE DESTINATION "lib")


endif()

# --- INSTALL INCLUDE ---
install(DIRECTORY "${HEADER_PATH}/" DESTINATION "include" FILES_MATCHING PATTERN "*.h")


#
##
#

# --- SUB BUILD LINKING ---
set(UnknownKrakenSharedMemoryObject_INCLUDE_DIRS "${CMAKE_CURRENT_LIST_DIR}/${HEADER_PATH}")
set(UnknownKrakenSharedMemoryObject_DEFINITIONS)
set(UnknownKrakenSharedMemoryObject_DIRECTORIES)
if(UnknownKrakenSharedMemoryObject_SHARED)
  set(UnknownKrakenSharedMemoryObject ${PROJECT_UnknownKrakenSharedMemoryObject_SHARED})
elseif(UnknownKrakenSharedMemoryObject_STATIC)
  set(UnknownKrakenSharedMemoryObject ${PROJECT_UnknownKrakenSharedMemoryObject_STATIC})
endif()
set(UnknownKrakenSharedMemoryObject_INCLUDE_DIRS ${UnknownKrakenSharedMemoryObject_INCLUDE_DIRS} PARENT_SCOPE)
set(UnknownKrakenSharedMemoryObject_DEFINITIONS ${UnknownKrakenSharedMemoryObject_DEFINITIONS} PARENT_SCOPE)
set(UnknownKrakenSharedMemoryObject ${UnknownKrakenSharedMemoryObject} PARENT_SCOPE)
add_library(UnknownKrakenSharedMemoryObject ALIAS ${UnknownKrakenSharedMemoryObject})


#
##
#

# --- ADD SUB BUILD  ---
link_libraries(UnknownKrakenSharedMemoryObject)

# --- BUILDS TOOLS ---
if(${UnknownKrakenSharedMemoryObject_BUILD_TOOLS})
  ## TODO
endif()

# --- BUILDS EXAMPLES ---
if(${UnknownKrakenSharedMemoryObject_BUILD_EXAMPLES})

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
if(${UnknownKrakenSharedMemoryObject_BUILD_TESTS})
  ## TODO
endif()

