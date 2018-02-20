#include <unknownecho/byte/byte_split.h>
#include <unknownecho/system/alloc.h>

#include <string.h>

unsigned char **byte_split(unsigned char *bytes, size_t bytes_len, unsigned char *delimiter, size_t delimiter_len, size_t *count, size_t **sizes) {
	unsigned char **result;
	size_t i, j, k, l, *tmp_sizes, tmp_count;

	result = NULL;
	tmp_count = 0;
	k = 0;
	l = 0;
	tmp_sizes = NULL;

	if (delimiter_len > bytes_len) {
		return NULL;
	}

	for (i = 0, j = 0; i < bytes_len; i++) {
		if (delimiter_len == 1) {
			if (bytes[i] == delimiter[0]) {
				if (!result) {
					ue_safe_alloc(result, unsigned char *, 1);
					ue_safe_alloc(tmp_sizes, size_t, 1);
				} else {
					ue_safe_realloc(result, unsigned char *, tmp_count, 1);
					ue_safe_realloc(tmp_sizes, size_t, tmp_count, 1);
				}
				tmp_sizes[tmp_count] = k - l + 1;
				ue_safe_alloc(result[tmp_count], unsigned char, tmp_sizes[tmp_count]);
				memcpy(result[tmp_count], bytes + l, (k - l) * sizeof(unsigned char));
				tmp_count = tmp_count + 1;
				k = i+1;
				l = i+1;
			} else {
				k = i+1;
			}
		}
		else if (j == delimiter_len-1) {
			if (!result) {
				ue_safe_alloc(result, unsigned char *, 1);
				ue_safe_alloc(tmp_sizes, size_t, 1);
			} else {
				ue_safe_realloc(result, unsigned char *, tmp_count, 1);
				ue_safe_realloc(tmp_sizes, size_t, tmp_count, 1);
			}
			tmp_sizes[tmp_count] = k - l + 1;
			ue_safe_alloc(result[tmp_count], unsigned char, tmp_sizes[tmp_count]);
			memcpy(result[tmp_count], bytes + k, (k - l) * sizeof(unsigned char));
			tmp_count += 1;
			k = i+1;
			l = i+1;
			j = 0;
		} else {
			if (bytes[i] == delimiter[j]) {
				j++;
				l++;
			} else {
				k = i+1;
				l = i+1;
				j = 0;
			}
		}
	}

	if (l < bytes_len) {
		ue_safe_realloc(result, unsigned char *, tmp_count, 1);
		ue_safe_realloc(tmp_sizes, size_t, tmp_count, 1);
		tmp_sizes[tmp_count] = bytes_len - l;
		ue_safe_alloc(result[tmp_count], unsigned char, tmp_sizes[tmp_count]);
		memcpy(result[tmp_count], bytes + l, (bytes_len - l) * sizeof(unsigned char));
		tmp_count += 1;
	}

	*sizes = tmp_sizes;
	*count = tmp_count;

	return result;
}
