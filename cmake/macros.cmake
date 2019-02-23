#
## ${LibraryName} project
#
## Author Charly Lamothe (http://u4a.at)
## Author Christophe-Alexandre Sonntag (http://u4a.at)
## Under the Apache License 2.0.
#

macro(UnknownKraken_MarkLibrary LibraryName)

  # --- SUB BUILD LINKING ---
  set(${LibraryName}_INCLUDE_DIRS "${CMAKE_CURRENT_LIST_DIR}/${HEADER_PATH}")
  set(${LibraryName}_DEFINITIONS)
  set(${LibraryName}_DIRECTORIES)
  if(${LibraryName}_SHARED)
    set(${LibraryName} ${PROJECT_${LibraryName}_SHARED})
  elseif(${LibraryName}_STATIC)
    set(${LibraryName} ${PROJECT_${LibraryName}_STATIC})
  endif()
  set(${LibraryName}_INCLUDE_DIRS ${${LibraryName}_INCLUDE_DIRS} PARENT_SCOPE)
  set(${LibraryName}_DEFINITIONS ${${LibraryName}_DEFINITIONS} PARENT_SCOPE)
  set(${LibraryName}_SHARED ${PROJECT_${LibraryName}_SHARED} PARENT_SCOPE)
  set(${LibraryName}_STATIC ${PROJECT_${LibraryName}_STATIC} PARENT_SCOPE)
  set(${LibraryName} ${${LibraryName}} PARENT_SCOPE)
  set(${LibraryName}_VERSION_MAJOR ${${LibraryName}_VERSION_MAJOR} PARENT_SCOPE)
  set(${LibraryName}_VERSION_MINOR ${${LibraryName}_VERSION_MINOR} PARENT_SCOPE)
  add_library(${LibraryName} ALIAS ${${LibraryName}})

  ## # --- LIB CONFIG FILE ---
  ## include(CMakePackageConfigHelpers)
  ## configure_package_config_file(
  ##   "${CMAKE_CURRENT_SOURCE_DIR}/../package.in.cmake"
  ##   "${CMAKE_CURRENT_BINARY_DIR}/${LibraryName}Config.cmake"
  ##   INSTALL_DESTINATION "lib/${LibraryName}/cmake"
  ## )
  ## write_basic_package_version_file(
  ##   "${CMAKE_CURRENT_BINARY_DIR}/${LibraryName}ConfigVersion.cmake"
  ##   VERSION ${LibraryName}_VERSION_MAJOR}.${LibraryName}_VERSION_MINOR}
  ##   COMPATIBILITY SameMajorVersion
  ## )
  ## install(
  ##   FILES "${CMAKE_CURRENT_BINARY_DIR}/${LibraryName}Config.cmake"
  ##   "${CMAKE_CURRENT_BINARY_DIR}/${LibraryName}ConfigVersion.cmake"
  ##   DESTINATION "lib/${LibraryName}/cmake"
  ## )

endmacro()


#
##
#

function(file_write_from_file IN_FILE OUT_FILE)
  file(READ ${IN_FILE} CONTENTS)
  file(WRITE ${OUT_FILE} "${CONTENTS}")
endfunction()

function(file_append_from_file IN_FILE OUT_FILE)
  file(READ ${IN_FILE} CONTENTS)
  file(APPEND ${OUT_FILE} "${CONTENTS}")
endfunction()




