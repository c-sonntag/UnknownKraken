/*******************************************************************************
 * Copyright (C) 2018 by Charly Lamothe                                        *
 *                                                                             *
 * This file is part of UnknownEchoLib.                                        *
 *                                                                             *
 *   UnknownEchoLib is free software: you can redistribute it and/or modify    *
 *   it under the terms of the GNU General Public License as published by      *
 *   the Free Software Foundation, either version 3 of the License, or         *
 *   (at your option) any later version.                                       *
 *                                                                             *
 *   UnknownEchoLib is distributed in the hope that it will be useful,         *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of            *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the             *
 *   GNU General Public License for more details.                              *
 *                                                                             *
 *   You should have received a copy of the GNU General Public License         *
 *   along with UnknownEchoLib.  If not, see <http://www.gnu.org/licenses/>.   *
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
