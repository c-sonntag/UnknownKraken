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

if (LIBMS_SYSTEM)
    if (WIN32)
        set(LIBMEMORYSLOT_INCLUDE_DIR "C:\\LibMemorySlot\\$ENV{name}\\include")
        set(LIBMEMORYSLOT_LIBRARIES "C:\\LibMemorySlot\\$ENV{name}\\lib\\ms_static.lib")
    elseif (UNIX)
        find_library(LIBMEMORYSLOT_LIBRARIES
            NAMES ms_static libms_static ms libms
            HINTS ${CMAKE_INSTALL_PREFIX}/lib)
        find_path(LIBMEMORYSLOT_INCLUDE_DIR ms)
    endif ()
else (LIBMS_SYSTEM)
    include (ExternalProject)

    set(LIBMS_URL https://github.com/swasun/LibMemorySlot.git)
    set(LIBMEMORYSLOT_INCLUDE_DIR ${LIBMS_INSTALL}/external/libms_archive)
    set(LIBMS_BUILD ${ROOT_BUILD_DIR}/libms/src/libms)

    if (WIN32)
        set(LIBMEMORYSLOT_LIBRARIES "${LIBMS_INSTALL}\\lib\\ms_static.lib")
    else()
        set(LIBMEMORYSLOT_LIBRARIES ${LIBMS_INSTALL}/lib/libms_static.a)
    endif()

    ExternalProject_Add(libms
        PREFIX libms
        GIT_REPOSITORY ${LIBMS_URL}    
        BUILD_IN_SOURCE 1
        BUILD_BYPRODUCTS ${LIBMEMORYSLOT_LIBRARIES}
        DOWNLOAD_DIR "${DOWNLOAD_LOCATION}"
        CMAKE_CACHE_ARGS
            -DCMAKE_BUILD_TYPE:STRING=Release
            -DCMAKE_INSTALL_PREFIX:STRING=${LIBMS_INSTALL}
            -DROOT_BUILD_DIR:STRING=${ROOT_BUILD_DIR}
            -DCMAKE_C_FLAGS:STRING=-fPIC
    )
endif (LIBMS_SYSTEM)
