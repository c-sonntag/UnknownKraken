#ifndef MEMORYPLUGIN_ENTRY_H
#define MEMORYPLUGIN_ENTRY_H

#include <ueum/ueum.h>

#include <stddef.h>

typedef struct {
	ueum_byte_stream *data;
} mp_entry;

mp_entry *mp_entry_create();

void mp_entry_destroy(mp_entry *entry);

bool mp_entry_add_stream(mp_entry *entry, ueum_byte_stream *data);

bool mp_entry_add_bytes(mp_entry *entry, unsigned char *data, size_t data_size);

bool mp_entry_add_file(mp_entry *entry, const char *file_name);

ueum_byte_stream *mp_entry_get_data(mp_entry *entry);

#endif
