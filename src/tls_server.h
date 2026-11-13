// SPDX-License-Identifier: GPL-3.0-or-later
/*
 *  tvheadend, TLS server side support
 *  Copyright (C) 2026 Tvheadend contributors
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef TLS_SERVER_H_
#define TLS_SERVER_H_

#include <stddef.h>

/*
 * Server side TLS for stream protocols (HTSP).
 *
 * The server code is not TLS aware. tls_server_accept() runs the TLS
 * handshake on the accepted socket and hands back one end of a local
 * socket pair. A pump thread moves the data between the TLS session
 * and the socket pair, so the protocol code keeps using plain read(),
 * write() and shutdown() on the returned descriptor.
 *
 * The certificate and the private key are PEM files. When no path is
 * configured, a self-signed certificate is generated in the
 * configuration directory on first use. The files are checked for
 * changes on each new connection, so a renewed certificate is picked up
 * without a restart.
 */

typedef struct tls_conn tls_conn_t;

/* Load the certificate (generate it if needed). Returns 0 on success. */
int tls_server_init(const char *cert_path, const char *key_path);

void tls_server_done(void);

/*
 * Reload the certificate if the configured paths or the files changed.
 * Returns 0 when a usable certificate is loaded.
 */
int tls_server_check(const char *cert_path, const char *key_path);

/* SHA-256 fingerprint of the loaded certificate ("AB:CD:..."), or "". */
void tls_server_fingerprint(char *dst, size_t dstsize);

/*
 * Accept a TLS session on the connected socket fd (the caller keeps
 * owning fd and closes it after tls_conn_destroy()).
 *
 * Returns the descriptor the protocol code uses instead of fd, or -1
 * when the handshake failed. The protocol code closes the returned
 * descriptor when it is done; tls_conn_destroy() then waits for the
 * pump thread and frees the session.
 */
int tls_server_accept(int fd, const char *peer, tls_conn_t **conn);

void tls_conn_destroy(tls_conn_t *conn);

#endif /* TLS_SERVER_H_ */
