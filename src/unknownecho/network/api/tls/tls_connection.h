#ifndef UNKNOWNECHO_TLS_UNKNOWNECHO_CONNECTION_H
#define UNKNOWNECHO_TLS_UNKNOWNECHO_CONNECTION_H

#include <unknownecho/network/api/tls/tls_context.h>
#include <unknownecho/crypto/api/certificate/x509_certificate.h>
#include <unknownecho/bool.h>
#include <unknownecho/string/string_builder.h>
#include <unknownecho/byte/byte_stream.h>

#include <stddef.h>

typedef struct ue_tls_connection ue_tls_connection;

ue_tls_connection *ue_tls_connection_create(ue_tls_context *context);

void ue_tls_connection_destroy(ue_tls_connection *connection);

bool ue_tls_connection_set_fd(ue_tls_connection *connection, int fd);

bool ue_tls_connection_connect(ue_tls_connection *connection);

bool ue_tls_connection_accept(ue_tls_connection *connection);

ue_x509_certificate *ue_tls_connection_get_peer_certificate(ue_tls_connection *connection);

bool ue_tls_connection_verify_peer_certificate(ue_tls_connection *connection);

size_t ue_tls_connection_write_sync(ue_tls_connection *connection, const void *data, int size);

size_t ue_tls_connection_read_string_sync(ue_tls_connection *connection, ue_string_builder *sb, bool blocking);

size_t ue_tls_connection_read_bytes_sync(ue_tls_connection *connection, ue_byte_stream *stream, bool blocking);

size_t ue_tls_connection_read_async(ue_tls_connection *connection, bool (*flow_consumer)(void *flow, size_t flow_size));

#endif
