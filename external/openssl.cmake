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

include (ExternalProject)

if (UNIX)
    ExternalProject_Add(openssl
        PREFIX openssl
        URL http://www.openssl.org/source/openssl-1.1.0h.tar.gz
        CONFIGURE_COMMAND ./config no-crypto-mdebug no-shared
            no-crypto-mdebug-backtrace no-unit-test no-weak-ssl-ciphers
            no-zlib no-zlib-dynamic no-idea no-mdc2 no-rc5 --prefix=${ROOT_BUILD_DIR}
        BUILD_COMMAND make depend && make
        INSTALL_COMMAND make install_sw
        BUILD_IN_SOURCE 1
        DOWNLOAD_DIR "${DOWNLOAD_LOCATION}"
    )
else ()
    ExternalProject_Add(openssl
        PREFIX openssl
        URL http://www.openssl.org/source/openssl-1.1.0h.tar.gz
        CONFIGURE_COMMAND perl Configure VC-WIN64A "--prefix=${CMAKE_INSTALL_PREFIX}"
        BUILD_COMMAND "ms\\do_win64a.bat"
        COMMAND nmake -f "ms\\ntdll.mak"
        BUILD_IN_SOURCE 1
        INSTALL_COMMAND nmake -f "ms\\ntdll.mak" install
        DOWNLOAD_DIR "${DOWNLOAD_LOCATION}"
    )
endif ()

set(OPENSSL_INCLUDE_DIR ${ROOT_BUILD_DIR}/openssl/src/openssl/)
set(OPENSSL_LIBRARIES
    ${ROOT_BUILD_DIR}/openssl/src/openssl/libssl.a
    ${ROOT_BUILD_DIR}/openssl/src/openssl/libcrypto.a
)