#
## UnknownKraken project
#
## Author Charly Lamothe (http://u4a.at)
## Author Christophe-Alexandre Sonntag (http://u4a.at)
## Under the Apache License 2.0.
#

# --- PROJECT ---
project(UnknownKraken)
cmake_minimum_required(VERSION 3.4)

#
##
#

# --- BUILD OPTIONS : STATIC/SHARED ---
set(UnknownKraken_BUILD_Utils              ON CACHE BOOL "Build Utils")
set(UnknownKraken_BUILD_Crypto             ON CACHE BOOL "Build Crypto (need Utils)")
set(UnknownKraken_BUILD_MemorySlot         ON CACHE BOOL "Build MemorySlot (need Utils)")
set(UnknownKraken_BUILD_SharedMemoryObject ON CACHE BOOL "Build SharedMemoryObject (need Utils)")
set(UnknownKraken_BUILD_SecureStorage      ON CACHE BOOL "Build SecureStorage (need Crypto Utils)")
set(UnknownKraken_BUILD_UnknownEcho        ON CACHE BOOL "Build UnknownEcho (need Crypto Utils)")
set(UnknownKraken_BUILD_MemoryPlugin       ON CACHE BOOL "Build MemoryPlugin (need SharedMemoryObject MemorySlot Crypto Utils)")

#
##
#

# TODO CHECK BUILD DEPENDENCIES COMPATIBILITY

#
##
#

macro(make_package_config PROJECT_NAME )

  #message(STATUS "PROJECT_NAME:  ${PROJECT_NAME}")

  # --- SETS ---
  set(${PROJECT_NAME}_ConfigName "${PROJECT_NAME}Config.cmake")
  #message(STATUS "${PROJECT_NAME}_ConfigName:  ${${PROJECT_NAME}_ConfigName}")

  # --- CONFIGURE FILE ---
  set(LIB_NAME       "${PROJECT_NAME}")
  set(ROOT_DIR       "${CMAKE_INSTALL_PREFIX}")
  set(VERSION_STRING "${${PROJECT_NAME}_VERSION_MAJOR}.${${PROJECT_NAME}_VERSION_MINOR}")
  #
  set(TARGET_STATIC "${${PROJECT_NAME}_STATIC}")
  set(TARGET_SHARED "${${PROJECT_NAME}_SHARED}")
  #
  set(LIBRARY_STATIC-NOT_DEFINED)
  set(LIBRARY_SHARED-NOT_DEFINED)
  if(TARGET ${${PROJECT_NAME}_STATIC})
    get_target_property(LIBRARY_STATIC ${${PROJECT_NAME}_STATIC} OUTPUT_NAME)
    set(LIBRARY_STATIC "${CMAKE_STATIC_LIBRARY_PREFIX}${LIBRARY_STATIC}${CMAKE_STATIC_LIBRARY_SUFFIX}")
  endif()
  if(TARGET ${${PROJECT_NAME}_SHARED})
    get_target_property(LIBRARY_SHARED ${${PROJECT_NAME}_SHARED} OUTPUT_NAME)
    set(LIBRARY_SHARED "${CMAKE_SHARED_LIBRARY_PREFIX}${LIBRARY_SHARED}${CMAKE_SHARED_LIBRARY_SUFFIX}")
  endif()
  if((TARGET ${${PROJECT_NAME}_STATIC}) AND (TARGET ${${PROJECT_NAME}_SHARED}))
    set(HAVE_MULTIPLE_LIBRARIES ON)
  else()
    set(HAVE_MULTIPLE_LIBRARIES OFF)
    if(TARGET ${${PROJECT_NAME}_STATIC})
      set(LIBRARY_ONCE_TYPE STATIC)
      set(LIBRARY_ONCE ${${PROJECT_NAME}_STATIC})
    elseif(TARGET ${${PROJECT_NAME}_SHARED})
      set(LIBRARY_ONCE_TYPE SHARED)
      set(LIBRARY_ONCE ${${PROJECT_NAME}_SHARED})
    endif()
  endif()

  #add_custom_target(print${PROJECT_NAME}
  #  COMMAND ${CMAKE_COMMAND} -E echo $<TARGET_FILE:${${PROJECT_NAME}_SHARED}>
  #)
  #set(LIBRARY_STATIC $<TARGET_FILE:${${PROJECT_NAME}_STATIC}>)
  #set(LIBRARY_SHARED $<TARGET_FILE:${${PROJECT_NAME}_SHARED}>)
  #set(LIBRARY_STATIC ${${PROJECT_NAME}_STATIC})
  #set(LIBRARY_SHARED ${${PROJECT_NAME}_SHARED})
  #message(STATUS "LIBRARY_STATIC:  ${LIBRARY_STATIC}")
  #message(STATUS "LIBRARY_SHARED:  ${LIBRARY_SHARED}")
  #configure_file("${PROJECT_SOURCE_DIR}/package.in.cmake" "${PROJECT_BINARY_DIR}/${${PROJECT_NAME}_ConfigName}(wait_install)" @ONLY)

  set(ConfigTemplate_DIRECTORY   "${PROJECT_SOURCE_DIR}/cmake")
  set(ConfigName_OUTPUT_FILEPATH "${PROJECT_BINARY_DIR}/${${PROJECT_NAME}_ConfigName}")
  #
  configure_file("${ConfigTemplate_DIRECTORY}/config-head.tpl.cmake"   "${ConfigName_OUTPUT_FILEPATH}-head"   @ONLY)
  configure_file("${ConfigTemplate_DIRECTORY}/config-footer.tpl.cmake" "${ConfigName_OUTPUT_FILEPATH}-footer" @ONLY)
  #
  if(HAVE_MULTIPLE_LIBRARIES)
    configure_file("${ConfigTemplate_DIRECTORY}/config-multiple_libraries.tpl.cmake" "${ConfigName_OUTPUT_FILEPATH}-lib" @ONLY)
  else()
    configure_file("${ConfigTemplate_DIRECTORY}/config-once_library.tpl.cmake"       "${ConfigName_OUTPUT_FILEPATH}-lib" @ONLY)
  endif()
  #
  set(ConfigContent "")
  string_append_from_file(ConfigContent "${ConfigName_OUTPUT_FILEPATH}-head")
  string_append_from_file(ConfigContent "${ConfigName_OUTPUT_FILEPATH}-lib")
  string_append_from_file(ConfigContent "${ConfigName_OUTPUT_FILEPATH}-footer")
  #
  file(
    GENERATE
      OUTPUT "${ConfigName_OUTPUT_FILEPATH}"
      CONTENT "${ConfigContent}"
  )
  #
  # #
  # file_write_from_file ("${ConfigName_OUTPUT_FILEPATH}-head"   "${ConfigName_OUTPUT_FILEPATH}")
  # file_append_from_file("${ConfigName_OUTPUT_FILEPATH}-lib"    "${ConfigName_OUTPUT_FILEPATH}")
  # file_append_from_file("${ConfigName_OUTPUT_FILEPATH}-footer" "${ConfigName_OUTPUT_FILEPATH}")


  #configure_file("${PROJECT_SOURCE_DIR}/package.in.cmake" "${PROJECT_BINARY_DIR}/${${PROJECT_NAME}_ConfigName}")
  #file(GENERATE OUTPUT "${PROJECT_BINARY_DIR}/${${PROJECT_NAME}_ConfigName}" INPUT "${PROJECT_BINARY_DIR}/${${PROJECT_NAME}_ConfigName}(wait_file)")
  #file(GENERATE OUTPUT "${PROJECT_BINARY_DIR}/${${PROJECT_NAME}_ConfigName}" INPUT "${PROJECT_SOURCE_DIR}/package.in.cmake")

  # --- INSTALL LIB ---
  install(FILES "${PROJECT_BINARY_DIR}/${${PROJECT_NAME}_ConfigName}" DESTINATION "lib/")

  #message(STATUS "  ")

endmacro()

#
##
#

if(UnknownKraken_BUILD_Utils)
  add_subdirectory("Utils/")
  make_package_config(UnknownKrakenUtils)
endif()

if(UnknownKraken_BUILD_Crypto)
  add_subdirectory("Crypto/")
  make_package_config(UnknownKrakenCrypto)
endif()

if(UnknownKraken_BUILD_MemorySlot)
  add_subdirectory("MemorySlot/")
  make_package_config(UnknownKrakenMemorySlot)
endif()

if(UnknownKraken_BUILD_SharedMemoryObject)
  add_subdirectory("SharedMemoryObject/")
  make_package_config(UnknownKrakenSharedMemoryObject)
endif()

if(UnknownKraken_BUILD_MemoryPlugin)
  add_subdirectory("MemoryPlugin/")
  make_package_config(UnknownKrakenMemoryPlugin)
endif()

if(UnknownKraken_BUILD_SecureStorage)
  add_subdirectory("SecureStorage/")
  make_package_config(UnknownKrakenSecureStorage)
endif()

if(UnknownKraken_BUILD_UnknownEcho)
  add_subdirectory("UnknownEcho/")
  make_package_config(UnknownKrakenUnknownEcho)
endif()

#
##
#




