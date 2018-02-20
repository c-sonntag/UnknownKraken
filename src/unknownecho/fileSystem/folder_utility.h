#ifndef UNKNOWNECHO_FOLDER_UTILITY_H
#define UNKNOWNECHO_FOLDER_UTILITY_H

#include <unknownecho/bool.h>

bool ue_is_dir_exists(const char *file_name);

int ue_count_dir_files(const char *dir_name, bool recursively);

char **ue_list_directory(char *dir_name, int *files, bool recursively);

char *ue_get_current_dir();

#endif
