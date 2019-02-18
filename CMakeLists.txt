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

  # --- SETS ---
  set(${PROJECT_NAME}_ConfigName "${PROJECT_NAME}Config.cmake")

  # --- CONFIGURE FILE ---
  set(ROOT_DIR       "${CMAKE_INSTALL_PREFIX}")
  set(VERSION_STRING "${${PROJECT_NAME}_VERSION_MAJOR}.${${PROJECT_NAME}_VERSION_MINOR}")
  get_target_property(LIBRARY_STATIC ${${PROJECT_NAME}_SHARED} OUTPUT_NAME)
  get_target_property(LIBRARY_SHARED ${${PROJECT_NAME}_SHARED} OUTPUT_NAME)
  configure_file("${PROJECT_SOURCE_DIR}/package.in.cmake" "${PROJECT_BINARY_DIR}/${${PROJECT_NAME}_ConfigName}" @ONLY)

  # --- INSTALL LIB ---
  #install(FILES "${PROJECT_BINARY_DIR}/${${PROJECT_NAME}_ConfigName}" DESTINATION "lib/${PROJECT_NAME}/${${PROJECT_NAME}_ConfigName}")
  #install(FILES "${PROJECT_BINARY_DIR}/${${PROJECT_NAME}_ConfigName}" DESTINATION "lib/cmake/${PROJECT_NAME}/${${PROJECT_NAME}_ConfigName}")
  install(FILES "${PROJECT_BINARY_DIR}/${${PROJECT_NAME}_ConfigName}" DESTINATION "lib/${${PROJECT_NAME}_ConfigName}")

endmacro()

#
##
#

if(UnknownKraken_BUILD_Utils)
  add_subdirectory("Utils/")
  #make_package_config(UnknownKrakenUtils)
endif()

if(UnknownKraken_BUILD_Crypto)
  add_subdirectory("Crypto/")
endif()

if(UnknownKraken_BUILD_MemorySlot)
  add_subdirectory("MemorySlot/")
endif()

if(UnknownKraken_BUILD_SharedMemoryObject)
  add_subdirectory("SharedMemoryObject/")
endif()

if(UnknownKraken_BUILD_MemoryPlugin)
  add_subdirectory("MemoryPlugin/")
  make_package_config(UnknownKrakenMemoryPlugin)
endif()

if(UnknownKraken_BUILD_SecureStorage)
  add_subdirectory("SecureStorage/")
endif()

if(UnknownKraken_BUILD_UnknownEcho)
  add_subdirectory("UnknownEcho/")
endif()

#
##
#




