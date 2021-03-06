/*******************************************************************************
 * Copyright (C) 2018 Charly Lamothe                                           *
 *                                                                             *
 * This file is part of LibUnknownEcho.                                        *
 *                                                                             *
 *   Licensed under the Apache License, Version 2.0 (the "License");           *
 *   you may not use this file except in compliance with the License.          *
 *   You may obtain a copy of the License at                                   *
 *                                                                             *
 *   http://www.apache.org/licenses/LICENSE-2.0                                *
 *                                                                             *
 *   Unless required by applicable law or agreed to in writing, software       *
 *   distributed under the License is distributed on an "AS IS" BASIS,         *
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  *
 *   See the License for the specific language governing permissions and       *
 *   limitations under the License.                                            *
 *******************************************************************************/

 
#include <uk/unknownecho/network/factory/tor_proxy_factory.h>
#include <uk/unknownecho/network/api/proxy/socks5_proxy.h>

int uk_ue_tor_proxy_connect(char *host, char *port) {
    return uk_ue_socks5_proxy_connect(host, port, "127.0.0.1", "9050", "", "");
}

int uk_ue_tor_proxy_connect_user(char *host, char *port, char *proxy_username, char *proxy_password) {
    return uk_ue_socks5_proxy_connect(host, port, "127.0.0.1", "9050", proxy_username, proxy_password);
}
