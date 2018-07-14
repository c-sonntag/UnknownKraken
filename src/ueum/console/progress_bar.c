/******************************************************************************************
 * Copyright (C) 2018 by Charly Lamothe													  *
 *																						  *
 * This file is part of LibUnknownEchoUtilsModule.										  *
 *																						  *
 *   LibUnknownEchoUtilsModule is free software: you can redistribute it and/or modify    *
 *   it under the terms of the GNU General Public License as published by				  *
 *   the Free Software Foundation, either version 3 of the License, or					  *
 *   (at your option) any later version.												  *
 *																						  *
 *   LibUnknownEchoUtilsModule is distributed in the hope that it will be useful,         *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of						  *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the						  *
 *   GNU General Public License for more details.										  *
 *																						  *
 *   You should have received a copy of the GNU General Public License					  *
 *   along with LibUnknownEchoUtilsModule.  If not, see <http://www.gnu.org/licenses/>.   *
 ******************************************************************************************/

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

#include <ueum/console/progress_bar.h>
#include <ueum/console/console.h>
#include <ueum/console/color.h>
#include <ueum/alloc.h>
#include <ueum/string/string_utility.h>

#include <ei/ei.h>

#include <stdlib.h>
#include <string.h>
#include <limits.h>

ueum_progress_bar *ueum_progress_bar_create(unsigned int n, const char *description, FILE *fd) {
    ueum_progress_bar *progress_bar;

    progress_bar = NULL;

    ueum_safe_alloc(progress_bar, ueum_progress_bar, 1);

    progress_bar->total_percentage = 100.0;
    progress_bar->character_width_percentage = 4;
    progress_bar->n = n;
    progress_bar->frequency_update = n;
    progress_bar->description = ueum_string_create_from(description);
    progress_bar->fd = fd;
    progress_bar->unit_bar = ueum_string_create_from("=");
    progress_bar->unit_space = ueum_string_create_from(" ");
    progress_bar->desc_width = (unsigned int)strlen(progress_bar->description);
    progress_bar->left_delimiter = ueum_string_create_from("[");
    progress_bar->right_delimiter = ueum_string_create_from("]");
    progress_bar->color_attribute = -1;
    progress_bar->color_foreground = -1;
    progress_bar->color_background = -1;
    progress_bar->current_position = 0;
    progress_bar->use_return_chariot = true;

    return progress_bar;
}

void ueum_progress_bar_destroy(ueum_progress_bar *progress_bar) {
    if (progress_bar) {
        ueum_safe_free(progress_bar->description);
        ueum_safe_free(progress_bar->unit_bar);
        ueum_safe_free(progress_bar->unit_space);
        ueum_safe_free(progress_bar->left_delimiter);
        ueum_safe_free(progress_bar->right_delimiter);
        ueum_safe_free(progress_bar);
    }
}

void ueum_progress_bar_set_frequency_update(ueum_progress_bar *progress_bar, unsigned long frequency_update) {
    /* Prevents out of bound crash if freqency_update > n */
    if (frequency_update > progress_bar->n){
		progress_bar->frequency_update = progress_bar->n;
	}
	else {
		progress_bar->frequency_update = frequency_update;
    }
}

void ueum_progress_bar_set_style(ueum_progress_bar *progress_bar, const char *unit_bar, const char *unit_space) {
    ueum_safe_free(progress_bar->unit_bar);
    ueum_safe_free(progress_bar->unit_space);
    progress_bar->unit_bar = ueum_string_create_from(unit_bar);
    progress_bar->unit_space = ueum_string_create_from(unit_space);
}

void ueum_progress_bar_set_left_delimiter(ueum_progress_bar *progress_bar, char *delimiter) {
    ueum_safe_free(progress_bar->left_delimiter);
    progress_bar->left_delimiter = ueum_string_create_from(delimiter);
}

void ueum_progress_bar_set_right_delimiter(ueum_progress_bar *progress_bar, char *delimiter) {
    ueum_safe_free(progress_bar->right_delimiter);
    progress_bar->right_delimiter = ueum_string_create_from(delimiter);
}

void ueum_progress_bar_set_colors(ueum_progress_bar *progress_bar, int color_attribute, int color_foreground, int color_background) {
    progress_bar->color_attribute = color_attribute;
    progress_bar->color_foreground = color_foreground;
    progress_bar->color_background = color_background;
}

void ueum_progress_bar_use_return_chariot(ueum_progress_bar *progress_bar, bool use) {
    progress_bar->use_return_chariot = use;
}

static void ueum_progress_bar_clear_field(ueum_progress_bar *progress_bar) {
    int i;

    for (i = 0; i < ueum_console_get_width(); i++) {
        fprintf(progress_bar->fd, " ");
    }
    fprintf(progress_bar->fd, "\r");
    fflush(progress_bar->fd);
}

static unsigned int ueum_progress_bar_compute_length(ueum_progress_bar *progress_bar) {
    unsigned int bar_length;
	int width;

	width = ueum_console_get_width();

	if (width < 0) {
		ei_stacktrace_push_msg("Cannot cast a signed int to unsigned int");
		return 0;
	}

    bar_length = (unsigned int)((unsigned int)width - progress_bar->desc_width - progress_bar->character_width_percentage) / 2;

    return bar_length;
}

static bool ueum_progress_bar_colored(ueum_progress_bar *progress_bar) {
    return progress_bar->color_attribute != -1 || progress_bar->color_foreground != -1 || progress_bar->color_background != -1;
}

static void progress_bar_print(ueum_progress_bar *progress_bar, const char *space, const char *string, bool color_if_possible) {
    char *colored_string;

    colored_string = NULL;

    if (color_if_possible && ueum_progress_bar_colored(progress_bar)) {
        colored_string = ueum_colorize_string(string, progress_bar->color_attribute,
            progress_bar->color_foreground, progress_bar->color_background);
        fprintf(progress_bar->fd, "%s%s", space, colored_string);
        ueum_safe_free(colored_string);
    } else {
        fprintf(progress_bar->fd, "%s%s", space, string);
    }
}

bool ueum_progress_bar_update(ueum_progress_bar *progress_bar, unsigned int idx) {
    ei_check_parameter_or_return(progress_bar);

    if (idx > progress_bar->n) {
        ei_stacktrace_push_msg("idx cannot be > n");
        ueum_progress_bar_clear_field(progress_bar);
        return false;
    }

    /* Determine whether to update the progress bar from frequency update */
    if ((idx != progress_bar->n) && (idx % (progress_bar->n/progress_bar->frequency_update) != 0)) {
        return true;
    }

    progress_bar->current_position = idx;

    /* Calculate the size of the progress bar */
    progress_bar->current_bar_size = ueum_progress_bar_compute_length(progress_bar);

    /* Calculate percentage of progress */
    progress_bar->current_progress_percent = idx * progress_bar->total_percentage / progress_bar->n;

    /* Calculate the percentage value of a unit bar */
    progress_bar->current_percent_per_unit_bar = progress_bar->total_percentage / progress_bar->current_bar_size;



    return true;
}

bool ueum_progress_bar_update_by_increasing(ueum_progress_bar *progress_bar, unsigned int idx) {
    if (!ueum_progress_bar_update(progress_bar, progress_bar->current_position + idx)) {
        ei_stacktrace_push_msg("Failed to update rpogress bar by increasing of %d", idx);
        return false;
    }

    return true;
}

bool ueum_progress_bar_finish(ueum_progress_bar *progress_bar) {
    ei_check_parameter_or_return(progress_bar);

    ueum_progress_bar_update(progress_bar, progress_bar->n);

    return true;
}

bool ueum_progress_bar_print(ueum_progress_bar *progress_bar) {
    unsigned int bar_length;

    ei_check_parameter_or_return(progress_bar);

    progress_bar_print(progress_bar, "", progress_bar->description, false);

    progress_bar_print(progress_bar, " ", progress_bar->left_delimiter, false);

    for (bar_length = 0; bar_length <= progress_bar->current_bar_size -1; bar_length++) {
        if (bar_length * progress_bar->current_percent_per_unit_bar < progress_bar->current_progress_percent) {
            progress_bar_print(progress_bar, "", progress_bar->unit_bar, true);
        } else {
            progress_bar_print(progress_bar, "", progress_bar->unit_space, true);
        }
    }

    progress_bar_print(progress_bar, "", progress_bar->right_delimiter, false);
    fprintf(progress_bar->fd, " %0.2lf%%", progress_bar->current_progress_percent);
    if (progress_bar->use_return_chariot) {
        fprintf(progress_bar->fd, "\r");
        fflush(progress_bar->fd);
    } else {
        fprintf(progress_bar->fd, "\n");
    }

    return true;
}

bool ueum_progress_bar_finish_and_print(ueum_progress_bar *progress_bar) {
    return ueum_progress_bar_finish(progress_bar) && ueum_progress_bar_print(progress_bar);
}

bool ueum_progress_bar_update_and_print(ueum_progress_bar *progress_bar, unsigned int idx) {
    return ueum_progress_bar_update(progress_bar, idx) && ueum_progress_bar_print(progress_bar);
}

bool ueum_progress_bar_update_by_increasing_and_print(ueum_progress_bar *progress_bar, unsigned int idx) {
    return ueum_progress_bar_update_by_increasing(progress_bar, idx) && ueum_progress_bar_print(progress_bar);
}
