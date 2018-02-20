#ifndef UNKNOWNECHO_SOCKET_H
#define UNKNOWNECHO_SOCKET_H

#include <unknownecho/bool.h>
#include <unknownecho/string/string_builder.h>
#include <unknownecho/byte/byte_stream.h>
#include <unknownecho/network/api/tls/tls_connection.h>

#include <stddef.h>

bool ue_socket_is_valid_domain(int domain);

int ue_socket_str_to_domain(const char *domain);

int ue_socket_open(int domain, int type);

int ue_socket_open_s(const char *domain, const char *type);

int ue_socket_open_tcp();

bool ue_socket_close(int fd);

bool ue_socket_destroy(int fd);

bool ue_socket_is_valid(int fd);

size_t ue_socket_send_string(int fd, const char *string, ue_tls_connection *tls);

size_t ue_socket_send_data(int fd, unsigned char *data, size_t size, ue_tls_connection *tls);

size_t ue_socket_receive_string_sync(int fd, ue_string_builder *sb, bool blocking, ue_tls_connection *tls);

size_t ue_socket_receive_bytes_sync(int fd, ue_byte_stream *stream, bool blocking, ue_tls_connection *tls);

size_t ue_socket_receive_data_async(int fd, bool (*flow_consumer)(void *flow, size_t flow_size), ue_tls_connection *tls);

#endif
