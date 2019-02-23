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

function(message_target_var PROJECT_NAME VAR)
  get_target_property(${VAR}_SHARED ${${PROJECT_NAME}_SHARED} ${VAR})
  get_target_property(${VAR}_STATIC ${${PROJECT_NAME}_STATIC} ${VAR})
  message(STATUS "${VAR} : ${${VAR}_SHARED} | ${${VAR}_STATIC}")
endfunction()

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
  get_target_property(LIBRARY_STATIC ${${PROJECT_NAME}_STATIC} OUTPUT_NAME)
  if(LIBRARY_STATIC)
    set(LIBRARY_STATIC "${CMAKE_STATIC_LIBRARY_PREFIX}${LIBRARY_STATIC}${CMAKE_STATIC_LIBRARY_SUFFIX}")
  endif()
  get_target_property(LIBRARY_SHARED ${${PROJECT_NAME}_SHARED} OUTPUT_NAME)
  if(LIBRARY_SHARED)
    set(LIBRARY_SHARED "${CMAKE_SHARED_LIBRARY_PREFIX}${LIBRARY_SHARED}${CMAKE_SHARED_LIBRARY_SUFFIX}")
  endif()

  ## message_target_var(${PROJECT_NAME} OUTPUT_NAME)
  message_target_var(${PROJECT_NAME} RUNTIME_OUTPUT_NAME)


  #add_custom_target(print${PROJECT_NAME}
  #  COMMAND ${CMAKE_COMMAND} -E echo $<TARGET_FILE:${${PROJECT_NAME}_SHARED}>
  #)
  #set(LIBRARY_STATIC $<TARGET_FILE:${${PROJECT_NAME}_STATIC}>)
  #set(LIBRARY_SHARED $<TARGET_FILE:${${PROJECT_NAME}_SHARED}>)
  #set(LIBRARY_STATIC ${${PROJECT_NAME}_STATIC})
  #set(LIBRARY_SHARED ${${PROJECT_NAME}_SHARED})
  #message(STATUS "LIBRARY_STATIC:  ${LIBRARY_STATIC}")
  #message(STATUS "LIBRARY_SHARED:  ${LIBRARY_SHARED}")
  configure_file("${PROJECT_SOURCE_DIR}/package.in.cmake" "${PROJECT_BINARY_DIR}/${${PROJECT_NAME}_ConfigName}(wait_install)" @ONLY)
  #configure_file("${PROJECT_SOURCE_DIR}/package.in.cmake" "${PROJECT_BINARY_DIR}/${${PROJECT_NAME}_ConfigName}")
  file(GENERATE OUTPUT "${PROJECT_BINARY_DIR}/${${PROJECT_NAME}_ConfigName}" INPUT "${PROJECT_BINARY_DIR}/${${PROJECT_NAME}_ConfigName}(wait_install)")

  # --- INSTALL LIB ---
  #install(FILES "${PROJECT_BINARY_DIR}/${${PROJECT_NAME}_ConfigName}" DESTINATION "lib/${PROJECT_NAME}/")
  #install(FILES "${PROJECT_BINARY_DIR}/${${PROJECT_NAME}_ConfigName}" DESTINATION "lib/cmake/${PROJECT_NAME}/")
  #install(FILES "${PROJECT_BINARY_DIR}/${${PROJECT_NAME}_ConfigName}" DESTINATION "lib/${PROJECT_NAME}/cmake")
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




