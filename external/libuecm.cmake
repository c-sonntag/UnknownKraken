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

set(LIBUNKNOWNECHOUTILSMODULE_SET false)

if (systemlib_LIBUECM)
    if (WIN32)
        set(LIBUNKNOWNECHOCRYPTOMODULE_INCLUDE_DIR "C:\\LibUnknownEchoCryptoModule\\$ENV{name}\\include")
        set(LIBUNKNOWNECHOCRYPTOMODULE_LIBRARIES "C:\\LibUnknownEchoCryptoModule\\$ENV{name}\\lib\\uecm_static.lib")
    elseif (UNIX)
        set(LIBUNKNOWNECHOCRYPTOMODULE_LIBRARIES "-luecm")
    endif ()
    set(LIBUNKNOWNECHOUTILSMODULE_SET true)
else (systemlib_LIUECM)
    include (ExternalProject)

    set(LIBUECM_URL https://github.com/swasun/LibUnknownEchoCryptoModule.git)
    set(LIBUNKNOWNECHOCRYPTOMODULE_INCLUDE_DIR ${ROOT_BUILD_DIR}/external/libuecm_archive)
    set(LIBUECM_BUILD ${ROOT_BUILD_DIR}/libuecm/src/libuecm)
    set(LIBUECM_INSTALL ${ROOT_BUILD_DIR}/libuecm/install)

    if (WIN32)
        set(LIBUNKNOWNECHOCRYPTOMODULE_LIBRARIES "${ROOT_BUILD_DIR}\\uecm_static.lib")
    else()
        set(LIBUNKNOWNECHOCRYPTOMODULE_LIBRARIES ${ROOT_BUILD_DIR}/libuecm/install/lib/libuecm_static.a)
    endif()

    message(STATUS "ROOT_BUILD_DIR: " ${ROOT_BUILD_DIR})

    ExternalProject_Add(libuecm
        PREFIX libuecm
        GIT_REPOSITORY ${LIBUECM_URL}
        BUILD_BYPRODUCTS ${LIBUNKNOWNECHOCRYPTOMODULE_LIBRARIES}
        DOWNLOAD_DIR "${DOWNLOAD_LOCATION}"
        BUILD_IN_SOURCE 1
        CMAKE_CACHE_ARGS
            -DCMAKE_BUILD_TYPE:STRING=Release
            -DCMAKE_INSTALL_PREFIX:STRING=${LIBUECM_INSTALL}
            -DROOT_BUILD_DIR:STRING=${ROOT_BUILD_DIR}
    )
endif (systemlib_LIBUECM)
