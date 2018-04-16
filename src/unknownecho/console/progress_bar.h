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

/**********************************************************************************
 * MIT License                                                                    *
 *                                                                                *
 * Copyright (c) 2016 Hemant Tailor                                               *
 *                                                                                *
 * Permission is hereby granted, free of charge, to any person obtaining a copy   *
 * of this software and associated documentation files (the "Software"), to deal  *
 * in the Software without restriction, including without limitation the rights   *
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell      *
 * copies of the Software, and to permit persons to whom the Software is          *
 * furnished to do so, subject to the following conditions:                       *
 *                                                                                *
 * The above copyright notice and this permission notice shall be included in all *
 * copies or substantial portions of the Software.                                *
 *                                                                                *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR     *
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,       *
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE    *
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER         *
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,  *
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE  *
 * SOFTWARE.                                                                      *
 **********************************************************************************/

#ifndef UNKNOWNECHO_PROGRESS_BAR_H
#define UNKNOWNECHO_PROGRESS_BAR_H

#include <unknownecho/bool.h>

#include <stdio.h>

typedef struct {
    float total_percentage;
    int character_width_percentage;
    unsigned long n;
    unsigned int desc_width;
    unsigned long frequency_update;
    FILE *fd;
    const char *description;
    char *unit_bar;
    char *unit_space;
    char *left_delimiter, *right_delimiter;
    int color_attribute, color_foreground, color_background;
} ue_progress_bar;

ue_progress_bar *ue_progress_bar_create(unsigned long n, const char *description, FILE *fd);

void ue_progress_bar_destroy(ue_progress_bar *progress_bar);

void ue_progress_bar_set_frequency_update(ue_progress_bar *progress_bar, unsigned long frequency_update);

void ue_progress_bar_set_style(ue_progress_bar *progress_bar, const char *unit_bar, const char *unit_space);

void ue_progress_bar_set_left_delimiter(ue_progress_bar *progress_bar, char *delimiter);

void ue_progress_bar_set_right_delimiter(ue_progress_bar *progress_bar, char *delimiter);

void ue_progress_bar_set_colors(ue_progress_bar *progress_bar, int color_attribute, int color_foreground, int color_background);

bool ue_progress_bar_update(ue_progress_bar *progress_bar, int idx);

#endif
