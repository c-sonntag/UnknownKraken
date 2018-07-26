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
