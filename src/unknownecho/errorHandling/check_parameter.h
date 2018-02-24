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
 *  @file      check_parameter.h
 *  @brief     Provides macro to record UNKNOWNECHO_INVALID_PARAMETER error code
 *             and return if specified parameter is null.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 */

#ifndef CHECK_PARAMETER_H
#define CHECK_PARAMETER_H

#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/errorHandling/error.h>

#define ue_unused(x) (void)(x);

#define ue_check_parameter(p) \
    if (!(p)) { \
        ue_stacktrace_push_code(UNKNOWNECHO_INVALID_PARAMETER) \
        return; \
    } \

#define ue_check_parameter_or_return(p) \
    if (!(p)) { \
        ue_stacktrace_push_code(UNKNOWNECHO_INVALID_PARAMETER) \
        return 0; \
    } \

#define ue_check_parameter_or_goto(p, label) \
    if (!(p)) { \
        ue_stacktrace_push_code(UNKNOWNECHO_INVALID_PARAMETER) \
        goto label; \
    } \

#endif /* CHECK_PARAMETER_H */
