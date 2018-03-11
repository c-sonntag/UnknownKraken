#
## @brief LibUnknownEcho
## @author Charly Lamothe
#

# --- PROJECT ---

PROJECT(unknownecho)
cmake_minimum_required(VERSION 3.5)

#
##
#

# --- PATH ---
set(${CMAKE_CURRENT_SOURCE_DIR} ..)
set(SRC_PATH "${CMAKE_CURRENT_SOURCE_DIR}/src")
set(TESTS_PATH "${CMAKE_CURRENT_SOURCE_DIR}/tests")
set(EXAMPLES_PATH "${CMAKE_CURRENT_SOURCE_DIR}/examples")
set(SEARCH_LIB FALSE)

if(CMAKE_BUILD_TYPE STREQUAL "Release")
	set(LIBRARY_OUTPUT_PATH "${CMAKE_CURRENT_SOURCE_DIR}/bin/release")
	set(EXAMPLES_OUTPUT_PATH "${CMAKE_CURRENT_SOURCE_DIR}/bin/release/examples")
	set(TESTS_OUTPUT_PATH "${CMAKE_CURRENT_SOURCE_DIR}/bin/release/tests")
elseif(CMAKE_BUILD_TYPE STREQUAL "Debug")
	set(LIBRARY_OUTPUT_PATH "${CMAKE_CURRENT_SOURCE_DIR}/bin/debug")
	set(EXAMPLES_OUTPUT_PATH "${CMAKE_CURRENT_SOURCE_DIR}/bin/debug/examples")
	set(TESTS_OUTPUT_PATH "${CMAKE_CURRENT_SOURCE_DIR}/bin/debug/tests")
endif ()

#
##
#

# --- GNU COMPILE OPTIONS ---
if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")     ## (not debug)
   if(CMAKE_COMPILER_IS_GNUCXX)               ## (GNU COMMAND)
      add_compile_options("-O3")              ### No Optimization
      set(CMAKE_EXE_LINKER_FLAGS "-s")        ### Strip binary (no work on debug)
   endif ()
else ()
	add_compile_options("-g")
endif ()

if (UNIX)
	add_compile_options("-std=gnu99")
else ()
	add_compile_options("-std=c99")
endif ()

add_compile_options("-Wall" "-Werror" "-pedantic" "-pthread" "-ldl" "-fno-builtin")

#
##
#

# --- LIBRARY ---

if (SEARCH_LIB)
	find_package(PkgConfig REQUIRED)

	# Search OpenSSL
	pkg_search_module(OPENSSL REQUIRED openssl)
	if (OPENSSL_FOUND)
	    include_directories(${OPENSSL_INCLUDE_DIRS})
	    message(STATUS "Using OpenSSL ${OPENSSL_VERSION}")
	else ()
	    # Error; with REQUIRED, pkg_search_module() will throw an error by it's own
	endif ()

	# Search ZLib
	pkg_search_module(ZLIB REQUIRED zlib)
	if (ZLIB_FOUND)
	    include_directories(${ZLIB_INCLUDE_DIRS})
	    message(STATUS "Using ZLib ${ZLIB_VERSION}")
	else ()
	    # Error; with REQUIRED, pkg_search_module() will throw an error by it's own
	endif ()
endif ()

# Search pthread
find_package (Threads)

#
## PROGRAM :
#

# Build library
file(GLOB_RECURSE PROGRAM_TARGET_SRC_FILES "${SRC_PATH}/*.c")
add_library(${PROJECT_NAME} STATIC ${PROGRAM_TARGET_SRC_FILES})
target_include_directories(${PROJECT_NAME} PUBLIC "${SRC_PATH}")
if (SEARCH_LIB)
	target_link_libraries(${PROJECT_NAME} ${OPENSSL_LIBRARIES})
	target_link_libraries(${PROJECT_NAME} ${ZLIB_LIBRARIES})
else ()
	target_link_libraries(${PROJECT_NAME} "${CMAKE_SOURCE_DIR}/lib/libssl.so.1.1" -ldl)
	target_link_libraries(${PROJECT_NAME} "${CMAKE_SOURCE_DIR}/lib/libcrypto.so.1.1" -ldl)
	target_link_libraries(${PROJECT_NAME} "${CMAKE_SOURCE_DIR}/lib/libz.a"  -ldl)
endif ()
target_link_libraries(${PROJECT_NAME} ${CMAKE_THREAD_LIBS_INIT})

# Build tests
#file(GLOB_RECURSE PROGRAM_TARGET_TESTS_FILES "${TESTS_PATH}/*.c")
#add_executable(ue_test ${PROGRAM_TARGET_TESTS_FILES})
#target_include_directories(ue_test PUBLIC "${TESTS_PATH}")
#target_link_libraries(ue_test ${PROJECT_NAME})
#set_target_properties(ue_test PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${TESTS_OUTPUT_PATH})

# Build examples
file(GLOB files "${EXAMPLES_PATH}/*.c")
foreach (filePath ${files} )
	get_filename_component(executableName ${filePath} NAME_WE)
	message(STATUS "Build Program : ${executableName}")
	add_executable(${executableName} ${filePath})
	if (SEARCH_LIB)
		target_link_libraries(${executableName} ${OPENSSL_LIBRARIES})
		target_link_libraries(${executableName} ${ZLIB_LIBRARIES})
	else ()
		target_link_libraries(${executableName} "${CMAKE_SOURCE_DIR}/lib/libssl.so.1.1" -ldl)
		target_link_libraries(${executableName} "${CMAKE_SOURCE_DIR}/lib/libcrypto.so.1.1" -ldl)
	endif ()
	target_link_libraries(${executableName} ${PROJECT_NAME})
	#target_link_libraries(${executableName} "${CMAKE_SOURCE_DIR}/lib/asmlib/libaelf64.a")
	set_target_properties(${executableName} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${EXAMPLES_OUTPUT_PATH})
endforeach ()
