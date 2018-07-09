 ##########################################################################################
 # Copyright (C) 2018 by Charly Lamothe													  #
 #																						  #
 # This file is part of LibUnknownEchoCryptoModule.										  #
 #																						  #
 #   LibUnknownEchoCryptoModule is free software: you can redistribute it and/or modify   #
 #   it under the terms of the GNU General Public License as published by				  #
 #   the Free Software Foundation, either version 3 of the License, or					  #
 #   (at your option) any later version.												  #
 #																						  #
 #   LibUnknownEchoCryptoModule is distributed in the hope that it will be useful,        #
 #   but WITHOUT ANY WARRANTY; without even the implied warranty of						  #
 #   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the						  #
 #   GNU General Public License for more details.										  #
 #																						  #
 #   You should have received a copy of the GNU General Public License					  #
 #   along with LibUnknownEchoCryptoModule.  If not, see <http://www.gnu.org/licenses/>.  #
 ##########################################################################################

if (systemlib_LIBEI)
	if (WIN32)
		set(LIBERRORINTERCEPTOR_INCLUDE_DIR "C:\\LibErrorInterceptor\\$ENV{name}\\include")
		set(LIBERRORINTERCEPTOR_LIBRARIES "C:\\LibErrorInterceptor\\$ENV{name}\\lib\\ei_static.lib")
	elseif (UNIX)
		set(LIBERRORINTERCEPTOR_LIBRARIES "-lei")
	endif ()
else (systemlib_LIBEI)
	include (ExternalProject)

	set(LIBEI_URL https://github.com/swasun/LibErrorInterceptor.git)
	set(LIBERRORINTERCEPTOR_INCLUDE_DIR ${ROOT_BUILD_DIR}/external/libei_archive)
	set(LIBEI_BUILD ${ROOT_BUILD_DIR}/libei/src/libei)
	set(LIBEI_INSTALL ${ROOT_BUILD_DIR}/libei/install)

	if (WIN32)
		set(LIBERRORINTERCEPTOR_LIBRARIES "${ROOT_BUILD_DIR}\\ei_static.lib")
	else()
		set(LIBERRORINTERCEPTOR_LIBRARIES ${ROOT_BUILD_DIR}/libei/install/lib/libei.a)
	endif()

	ExternalProject_Add(libei
		PREFIX libei
		GIT_REPOSITORY ${LIBEI_URL}
		BUILD_IN_SOURCE 1
		BUILD_BYPRODUCTS ${LIBERRORINTERCEPTOR_LIBRARIES}
		DOWNLOAD_DIR "${DOWNLOAD_LOCATION}"
		CMAKE_CACHE_ARGS
			-DCMAKE_BUILD_TYPE:STRING=Release
			-DCMAKE_INSTALL_PREFIX:STRING=${LIBEI_INSTALL}
	)
endif (systemlib_LIBEI)