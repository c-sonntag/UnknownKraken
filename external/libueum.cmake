 ##########################################################################################
 # Copyright (C) 2018 by Charly Lamothe													  #
 #																						  #
 # This file is part of LibUnknownEcho.										  			  #
 #																						  #
 #   LibUnknownEcho is free software: you can redistribute it and/or modify   			  #
 #   it under the terms of the GNU General Public License as published by				  #
 #   the Free Software Foundation, either version 3 of the License, or					  #
 #   (at your option) any later version.												  #
 #																						  #
 #   LibUnknownEcho is distributed in the hope that it will be useful,        			  #
 #   but WITHOUT ANY WARRANTY; without even the implied warranty of						  #
 #   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the						  #
 #   GNU General Public License for more details.										  #
 #																						  #
 #   You should have received a copy of the GNU General Public License					  #
 #   along with LibUnknownEcho.  If not, see <http://www.gnu.org/licenses/>.  			  #
 ##########################################################################################

if (systemlib_LIBUEUM)
    if (WIN32)
        set(LIBUNKNOWNECHOUTILSMODULE_INCLUDE_DIR "C:\\LibUnknownEchoUtilsModule\\$ENV{name}\\include")
        set(LIBUNKNOWNECHOUTILSMODULE_LIBRARIES "C:\\LibUnknownEchoUtilsModule\\$ENV{name}\\lib\\ueum_static.lib")
    elseif (UNIX)
        set(LIBUNKNOWNECHOUTILSMODULE_LIBRARIES "-lueum")
	endif ()
	set(LIBUNKNOWNECHOUTILSMODULE_SET true)
else (systemlib_LIUEUM)
	set(found FALSE)
	set(LIBUNKNOWNECHOUTILSMODULE_SET false)

	if (UNIX)
		find_library(LIBUNKNOWNECHOUTILSMODULE_LIBRARIES ueum)
		find_path(LIBUNKNOWNECHOUTILSMODULE_INCLUDE_DIR NAMES ueum)
		if (LIBUNKNOWNECHOUTILSMODULE_LIBRARIES)
			set(found TRUE)
		else ()
			set(LIBUNKNOWNECHOUTILSMODULE_LIBRARIES "")
			set(LIBUNKNOWNECHOUTILSMODULE_INCLUDE_DIR "")
		endif ()
	elseif (WIN32)
		if (EXISTS "C:\\LibUnknownEchoUtilsModule\\$ENV{name}")
			set(LIBUNKNOWNECHOUTILSMODULE_INCLUDE_DIR "C:\\LibUnknownEchoUtilsModule\\$ENV{name}\\include")
			set(LIBUNKNOWNECHOUTILSMODULE_LIBRARIES "C:\\LibUnknownEchoUtilsModule\\$ENV{name}\\lib\\ueum_static.lib")
		endif ()
	endif ()

	if (NOT found)
		include (ExternalProject)

		set(LIBUEUM_URL https://github.com/swasun/LibUnknownEchoUtilsModule.git)
		set(LIBUNKNOWNECHOUTILSMODULE_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/external/libueum_archive)
		set(LIBUEUM_BUILD ${CMAKE_CURRENT_BINARY_DIR}/libueum/src/libueum)
		set(LIBUEUM_INSTALL ${CMAKE_CURRENT_BINARY_DIR}/libueum/install)

		if (WIN32)
			set(libueum_STATIC_LIBRARIES "${CMAKE_CURRENT_BINARY_DIR}\\ueum_static.lib")
		else()
			set(libueum_STATIC_LIBRARIES ${CMAKE_CURRENT_BINARY_DIR}/libueum/install/lib/libueum.a)
		endif()

		ExternalProject_Add(libueum
			PREFIX libueum
			GIT_REPOSITORY ${LIBUEUM_URL}	
			BUILD_IN_SOURCE 1
			BUILD_BYPRODUCTS ${libueum_STATIC_LIBRARIES}
			DOWNLOAD_DIR "${DOWNLOAD_LOCATION}"
			CMAKE_CACHE_ARGS
				-DCMAKE_BUILD_TYPE:STRING=Release
				-DCMAKE_INSTALL_PREFIX:STRING=${LIBUEUM_INSTALL}
		)

		if (WIN32)
			set(LIBUNKNOWNECHOUTILSMODULE_INCLUDE_DIR "${CMAKE_CURRENT_BINARY_DIR}\\libueum\\install\\include")
			set(LIBUNKNOWNECHOUTILSMODULE_LIBRARIES "${CMAKE_CURRENT_BINARY_DIR}\\libueum\\install\\lib\\ueum_static.lib")
		elseif (UNIX)
			set(LIBUNKNOWNECHOUTILSMODULE_LIBRARIES "-lueum")
		endif ()

		set(LIBUNKNOWNECHOUTILSMODULE_SET true)
	endif ()
endif (systemlib_LIBUEUM)
