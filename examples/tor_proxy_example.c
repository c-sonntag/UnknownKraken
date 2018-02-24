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

#include <unknownecho/init.h>
#include <unknownecho/bool.h>
#include <unknownecho/network/api/socket/socket.h>
#include <unknownecho/network/factory/tor_proxy_factory.h>
#include <unknownecho/string/string_builder.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/byte/byte_stream.h>
#include <unknownecho/fileSystem/file_utility.h>

#include <stddef.h>
#include <stdio.h>

int main() {
	size_t bytes;
	ue_string_builder *request;
	ue_byte_stream *response;
	int fd;

	ue_init();

	request = ue_string_builder_create();
	response = ue_byte_stream_create();

	if ((fd = ue_tor_proxy_connect("checkip.dyndns.org", "80")) == -1) {
		ue_stacktrace_push_msg("Failed to connect to site through local TOR proxy");
		goto clean_up;
	}

	ue_string_builder_append_variadic(request, "GET /checkip.dyndns.org HTTP/1.1\r\n\r\n");
	bytes = ue_socket_send_string(fd, (char *)ue_string_builder_get_data(request), NULL);
	ue_logger_info("Sent : %ld", bytes);
	if (bytes <= 0) {
		ue_stacktrace_push_msg("Failed to send HTTP GET request");
		goto clean_up;
	}
	ue_logger_info("Request successfully sent.");

	bytes = ue_socket_receive_bytes_sync(fd, response, true, NULL);
	ue_logger_info("Received : %ld", bytes);
	if (bytes <= 0) {
		ue_stacktrace_push_msg("Failed to receive HTTP GET response");
		goto clean_up;
	}
	ue_logger_info("Response successfully reveived.");

	//ue_write_binary_file("out.html", ue_byte_stream_get_data(response), ue_byte_stream_get_size(response));
	fprintf(stdout, "%s\n", (char *)ue_byte_stream_get_data(response));

clean_up:
	ue_socket_close(fd);
	ue_string_builder_destroy(request);
	ue_byte_stream_destroy(response);
	if (ue_stacktrace_is_filled()) {
		ue_logger_error("Error(s) occurred with the following stacktrace(s) :");
		ue_stacktrace_print_all();
	}
	ue_uninit();
	return 0;
}
