 ##########################################################################################
 # Copyright (C) 2018 by Charly Lamothe                                                   #
 #                                                                                        #
 # This file is part of LibMemoryPlugin.                                                  #
 #                                                                                        #
 #   LibMemoryPlugin is free software: you can redistribute it and/or modify              #
 #   it under the terms of the GNU General Public License as published by                 #
 #   the Free Software Foundation, either version 3 of the License, or                    #
 #   (at your option) any later version.                                                  #
 #                                                                                        #
 #   LibMemoryPlugin is distributed in the hope that it will be useful,                   #
 #   but WITHOUT ANY WARRANTY; without even the implied warranty of                       #
 #   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the                        #
 #   GNU General Public License for more details.                                         #
 #                                                                                        #
 #   You should have received a copy of the GNU General Public License                    #
 #   along with LibMemoryPlugin.  If not, see <http://www.gnu.org/licenses/>.             #
 ##########################################################################################

if (LIBSMO_SYSTEM)
    if (WIN32)
        set(LIBSHAREDMEMORYOBJECT_INCLUDE_DIR "C:\\LibSharedMemoryObject\\$ENV{name}\\include")
        set(LIBSHAREDMEMORYOBJECT_LIBRARIES "C:\\LibSharedMemoryObject\\$ENV{name}\\lib\\smo_static.lib")
    elseif (UNIX)
        find_library(LIBSHAREDMEMORYOBJECT_LIBRARIES
            NAMES smo_static libsmo_static smo libsmo
            HINTS ${CMAKE_INSTALL_PREFIX}/lib)
        find_path(LIBSHAREDMEMORYOBJECT_INCLUDE_DIR smo)
    endif ()
else (LIBSMO_SYSTEM)
    include (ExternalProject)

    set(LIBSMO_URL https://github.com/swasun/LibSharedMemoryObject.git)
    set(LIBSHAREDMEMORYOBJECT_INCLUDE_DIR ${LIBSMO_INSTALL}/external/libsmo_archive)
    set(LIBSMO_BUILD ${ROOT_BUILD_DIR}/libsmo/src/libsmo)

    if (WIN32)
        set(LIBSHAREDMEMORYOBJECT_LIBRARIES "${LIBSMO_INSTALL}\\lib\\smo_static.lib")
    else()
        set(LIBSHAREDMEMORYOBJECT_LIBRARIES ${LIBSMO_INSTALL}/lib/libsmo_static.a)
    endif()

    ExternalProject_Add(libsmo
        PREFIX libsmo
        GIT_REPOSITORY ${LIBSMO_URL}    
        BUILD_IN_SOURCE 1
        BUILD_BYPRODUCTS ${LIBSHAREDMEMORYOBJECT_LIBRARIES}
        DOWNLOAD_DIR "${DOWNLOAD_LOCATION}"
        CMAKE_CACHE_ARGS
            -DCMAKE_BUILD_TYPE:STRING=Release
            -DCMAKE_INSTALL_PREFIX:STRING=${LIBSMO_INSTALL}
            -DROOT_BUILD_DIR:STRING=${ROOT_BUILD_DIR}
            -DCMAKE_C_FLAGS:STRING=-fPIC
    )
endif (LIBSMO_SYSTEM)
