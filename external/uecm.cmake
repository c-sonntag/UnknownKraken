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

#add_custom_target(libuecm)

if (systemlib_LIBUECM)
    if (WIN32)
        set(LIBUNKNOWNECHOCRYPTOMODULE_INCLUDE_DIR "C:\\LibUnknownEchoCryptoModule\\$ENV{name}\\include")
        set(LIBUNKNOWNECHOCRYPTOMODULE_LIBRARIES "C:\\LibUnknownEchoCryptoModule\\$ENV{name}\\lib\\uecm_static.lib")
    elseif (UNIX)
        set(LIBUNKNOWNECHOCRYPTOMODULE_LIBRARIES "-luecm")
    endif ()
else (systemlib_LIUECM)
    set(found FALSE)

    if (UNIX)
        find_library(LIBUNKNOWNECHOCRYPTOMODULE_LIBRARIES uecm)
        find_path(LIBUNKNOWNECHOCRYPTOMODULE_INCLUDE_DIR NAMES uecm)
        if (LIBUNKNOWNECHOCRYPTOMODULE_LIBRARIES)
            set(found TRUE)
        else ()
            set(LIBUNKNOWNECHOCRYPTOMODULE_LIBRARIES "")
            set(LIBUNKNOWNECHOCRYPTOMODULE_INCLUDE_DIR "")
        endif ()
    elseif (WIN32)
        if (EXISTS "C:\\LibUnknownEchoCryptoModule\\$ENV{name}")
            set(LIBUNKNOWNECHOCRYPTOMODULE_INCLUDE_DIR "C:\\LibUnknownEchoCryptoModule\\$ENV{name}\\include")
            set(LIBUNKNOWNECHOCRYPTOMODULE_LIBRARIES "C:\\LibUnknownEchoCryptoModule\\$ENV{name}\\lib\\uecm_static.lib")
        endif ()
    endif ()

    if (NOT found)
        include (ExternalProject)

        set(LIBUECM_URL https://github.com/swasun/LibUnknownEchoCryptoModule.git)
        set(LIBUNKNOWNECHOCRYPTOMODULE_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/external/libuecm_archive)
        set(LIBUECM_BUILD ${CMAKE_CURRENT_BINARY_DIR}/libuecm/src/libuecm)
        set(LIBUECM_INSTALL ${CMAKE_CURRENT_BINARY_DIR}/libuecm/install)

        if (WIN32)
            set(libuecm_STATIC_LIBRARIES "${CMAKE_CURRENT_BINARY_DIR}\\uecm_static.lib")
        else()
            set(libuecm_STATIC_LIBRARIES ${CMAKE_CURRENT_BINARY_DIR}/libuecm/install/lib/libuecm.a)
        endif()

        ExternalProject_Add(libuecm
            PREFIX libuecm
            GIT_REPOSITORY ${LIBUECM_URL}	
            BUILD_IN_SOURCE 1
            BUILD_BYPRODUCTS ${libuecm_STATIC_LIBRARIES}
            DOWNLOAD_DIR "${DOWNLOAD_LOCATION}"
            CMAKE_CACHE_ARGS
                -DCMAKE_BUILD_TYPE:STRING=Release
                -DCMAKE_INSTALL_PREFIX:STRING=${LIBUECM_INSTALL}
        )

        if (WIN32)
            set(LIBUNKNOWNECHOCRYPTOMODULE_INCLUDE_DIR "${CMAKE_CURRENT_BINARY_DIR}\\libuecm\\install\\include")
            set(LIBUNKNOWNECHOCRYPTOMODULE_LIBRARIES "${CMAKE_CURRENT_BINARY_DIR}\\libuecm\\install\\lib\\uecm_static.lib")
        elseif (UNIX)
            set(LIBUNKNOWNECHOCRYPTOMODULE_LIBRARIES "-luecm")
        endif ()
    endif ()
endif (systemlib_LIBUECM)
