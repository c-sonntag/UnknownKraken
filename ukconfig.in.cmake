#
## @LIB_NAME@ Config file
#
## Author Charly Lamothe (http://u4a.at)
## Author Christophe-Alexandre Sonntag (http://u4a.at)
## Under the Apache License 2.0.
#


# Use the following variables to compile and link against @LIB_NAME@:
#  @LIB_NAME@_FOUND              - True if @LIB_NAME@ was found on your system
#  @LIB_NAME@_DEFINITIONS        - Definitions needed to build with @LIB_NAME@
#  @LIB_NAME@_INCLUDE_DIR        - Directory where @LIB_NAME@ can be found
#  @LIB_NAME@_INCLUDE_DIRS       - List of directories of @LIB_NAME@ and it's dependencies
#  @LIB_NAME@_LIBRARY_STATIC     - List of libraries to link against @LIB_NAME@ library in STATIC mode
#  @LIB_NAME@_LIBRARY_SHARED     - List of libraries to link against @LIB_NAME@ library in SHARED mode
#  @LIB_NAME@_LIBRARIES          - List of libraries to link against @LIB_NAME@ library depending by @LIB_NAME@_STATIC or @LIB_NAME@_SHARED
#  @LIB_NAME@_LIBRARY_DIRS       - List of directories containing @LIB_NAME@' libraries
#  @LIB_NAME@_ROOT_DIR           - The base directory of @LIB_NAME@
#  @LIB_NAME@_VERSION_STRING     - A human-readable string containing the version

set( @LIB_NAME@_FOUND           1 )
set( @LIB_NAME@_ROOT_DIR        "@ROOT_DIR@" )
set( @LIB_NAME@_VERSION_STRING  "@VERSION_STRING@" )
set( @LIB_NAME@_INCLUDE_DIR     "${@LIB_NAME@_ROOT_DIR}/include" )
set( @LIB_NAME@_INCLUDE_DIRS    "${@LIB_NAME@_ROOT_DIR}/include" )
set( @LIB_NAME@_LIBRARY_DIRS    "${@LIB_NAME@_ROOT_DIR}/lib" )
set( @LIB_NAME@_DEFINITIONS     "" )
set( @LIB_NAME@_DIRECTORIES     "" )
set( @LIB_NAME@_LIBRARY_STATIC  "@LIBRARY_STATIC@" )
set( @LIB_NAME@_LIBRARY_SHARED  "@LIBRARY_SHARED@" )


#
##
if( @LIB_NAME@_LIBRARY_STATIC AND @LIB_NAME@_LIBRARY_SHARED )
  if( 
    ( (NOT @LIB_NAME@_SHARED) AND (NOT @LIB_NAME@_STATIC) ) OR
    ( (@LIB_NAME@_SHARED) AND (@LIB_NAME@_STATIC) ) OR
    ( (NOT DEFINED @LIB_NAME@_SHARED) AND (NOT @LIB_NAME@_STATIC) ) OR
    ( (NOT DEFINED @LIB_NAME@_STATIC) AND (NOT @LIB_NAME@_SHARED) )
  )
    message(SEND_ERROR
      "\n\n"
      "   !! Require one of SHARED or STATIC setting for @LIB_NAME@ !! \n"
      "   !! You can FIX IT by @LIB_NAME@_STATIC/@LIB_NAME@_SHARED variables !! \n"
      "   !! Configure It By CMake DEFINITON !! \n"
      "   !! Actual @LIB_NAME@_SHARED=${@LIB_NAME@_SHARED} and @LIB_NAME@_STATIC=${@LIB_NAME@_STATIC} !! \n"
      "\n"
    )
    set(@LIB_NAME@_FOUND OFF)
    return()
  endif()
else()
  if(@LIB_NAME@_LIBRARY_STATIC)
    set(@LIB_NAME@_STATIC ON)
  elseif(@LIB_NAME@_LIBRARY_SHARED)
    set(@LIB_NAME@_SHARED ON)
  else()
    message(FATAL_ERROR "Require configuration file with at least one of variable @LIB_NAME@_LIBRARY_STATIC or @LIB_NAME@_LIBRARY_SHARED")
  endif()
endif()

#
##
if(@LIB_NAME@_STATIC)
  set(@LIB_NAME@_LIB_TYPE STATIC)
  set(@LIB_NAME@_LIBRARIES "@LIBRARY_STATIC@")
elseif(@LIB_NAME@_SHARED)
  set(@LIB_NAME@_LIB_TYPE SHARED)
  set(@LIB_NAME@_LIBRARIES "@LIBRARY_SHARED@")
endif()
set(@LIB_NAME@_LIBRARY "${@LIB_NAME@_LIBRARIES}")


#
##
add_library(@LIB_NAME@ ${@LIB_NAME@_LIB_TYPE} IMPORTED)
set_target_properties(@LIB_NAME@ PROPERTIES
  IMPORTED_LOCATION             "${@LIB_NAME@_LOCATION}"
  INTERFACE_LINK_LIBRARIES      "${@LIB_NAME@_LIBRARIES}"
  INTERFACE_COMPILE_DEFINITIONS "${@LIB_NAME@_DEFINITIONS}"
  INTERFACE_INCLUDE_DIRECTORIES "${@LIB_NAME@_INCLUDE_DIRS}"
  INTERFACE_LINK_DIRECTORIES    "${@LIB_NAME@_DIRECTORIES}"
)


