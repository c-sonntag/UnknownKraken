 ###############################################################################
 # Copyright (C) 2018 Charly Lamothe                                           #
 #                                                                             #
 # This file is part of LibMemoryPlugin.                                       #
 #                                                                             #
 #   Licensed under the Apache License, Version 2.0 (the "License");           #
 #   you may not use this file except in compliance with the License.          #
 #   You may obtain a copy of the License at                                   #
 #                                                                             #
 #   http://www.apache.org/licenses/LICENSE-2.0                                #
 #                                                                             #
 #   Unless required by applicable law or agreed to in writing, software       #
 #   distributed under the License is distributed on an "AS IS" BASIS,         #
 #   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  #
 #   See the License for the specific language governing permissions and       #
 #   limitations under the License.                                            #
 ###############################################################################

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
