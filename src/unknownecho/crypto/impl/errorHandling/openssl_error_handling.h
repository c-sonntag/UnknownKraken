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

#ifndef UNKNOWNECHO_OPENSSL_ERROR_HANDLING_H
#define UNKNOWNECHO_OPENSSL_ERROR_HANDLING_H

#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/system/alloc.h>

char *ue_openssl_error_handling_impl(char *begin_msg);

#define ue_openssl_error_handling(error_buffer, begin_msg) \
	do { \
		error_buffer = ue_openssl_error_handling_impl(begin_msg); \
		ue_stacktrace_push_msg(error_buffer) \
		ue_safe_str_free(error_buffer) \
	} while (0); \

#endif
