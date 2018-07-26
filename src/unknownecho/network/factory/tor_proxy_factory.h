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

 /**
  *  @file      tor_proxy_factory.h
  *  @brief
  *  @author    Charly Lamothe
  *  @copyright GNU Public License.
  */

#ifndef UNKNOWNECHO_TOR_PROXY_FACTORY_H
#define UNKNOWNECHO_TOR_PROXY_FACTORY_H

int ue_tor_proxy_connect(char *host, char *port);

int ue_tor_proxy_connect_user(char *host, char *port, char *proxy_username, char *proxy_password);

#endif
