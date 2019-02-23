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


#
## HEAD VARS
set( @LIB_NAME@_FOUND           1 )
set( @LIB_NAME@_ROOT_DIR        "@ROOT_DIR@" )
set( @LIB_NAME@_VERSION_STRING  "@VERSION_STRING@" )
set( @LIB_NAME@_INCLUDE_DIR     "${@LIB_NAME@_ROOT_DIR}/include" )
set( @LIB_NAME@_INCLUDE_DIRS    "${@LIB_NAME@_ROOT_DIR}/include" )
set( @LIB_NAME@_LIBRARY_DIRS    "${@LIB_NAME@_ROOT_DIR}/lib" )
set( @LIB_NAME@_DEFINITIONS     "" )
set( @LIB_NAME@_DIRECTORIES     "" )

