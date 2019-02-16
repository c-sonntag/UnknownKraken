/*******************************************************************************
 * Copyright (C) 2018 Charly Lamothe                                           *
 *                                                                             *
 * This file is part of LibUnknownEchoUtilsModule.                             *
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

#ifndef UNKNOWNECHOUTILSMODULE_PROGRESS_BAR_H
#define UNKNOWNECHOUTILSMODULE_PROGRESS_BAR_H

#include <ueum/compiler/bool.h>

#include <stdio.h>

typedef struct {
    float total_percentage;
    unsigned int character_width_percentage;
    unsigned int n;
    unsigned int desc_width;
    unsigned long frequency_update;
    FILE *fd;
    const char *description;
    char *unit_bar;
    char *unit_space;
    char *left_delimiter, *right_delimiter;
    int color_attribute, color_foreground, color_background;
    unsigned int current_position;
    bool use_return_chariot;
    unsigned int current_bar_size;
    double current_progress_percent, current_percent_per_unit_bar;
} ueum_progress_bar;

ueum_progress_bar *ueum_progress_bar_create(unsigned int n, const char *description, FILE *fd);

void ueum_progress_bar_destroy(ueum_progress_bar *progress_bar);

void ueum_progress_bar_set_frequency_update(ueum_progress_bar *progress_bar, unsigned long frequency_update);

void ueum_progress_bar_set_style(ueum_progress_bar *progress_bar, const char *unit_bar, const char *unit_space);

void ueum_progress_bar_set_left_delimiter(ueum_progress_bar *progress_bar, char *delimiter);

void ueum_progress_bar_set_right_delimiter(ueum_progress_bar *progress_bar, char *delimiter);

void ueum_progress_bar_set_colors(ueum_progress_bar *progress_bar, int color_attribute, int color_foreground, int color_background);

void ueum_progress_bar_use_return_chariot(ueum_progress_bar *progress_bar, bool use);

bool ueum_progress_bar_update(ueum_progress_bar *progress_bar, unsigned int idx);

bool ueum_progress_bar_update_by_increasing(ueum_progress_bar *progress_bar, unsigned int idx);

bool ueum_progress_bar_finish(ueum_progress_bar *progress_bar);

bool ueum_progress_bar_print(ueum_progress_bar *progress_bar);

bool ueum_progress_bar_finish_and_print(ueum_progress_bar *progress_bar);

bool ueum_progress_bar_update_and_print(ueum_progress_bar *progress_bar, unsigned int idx);

bool ueum_progress_bar_update_by_increasing_and_print(ueum_progress_bar *progress_bar, unsigned int idx);

#endif
