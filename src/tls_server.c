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

#include <ctype.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include "tvheadend.h"
#include "settings.h"
#include "tls_server.h"

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

/* The handshake must finish within this time. */
#define TLS_HANDSHAKE_TIMEOUT  10
/* Same limit as the send timeout of plain TCP connections (tcp.c). */
#define TLS_WRITE_TIMEOUT      30
/* Validity of the generated self-signed certificate. */
#define TLS_CERT_DAYS          3650

#define TLS_AUTO_CERT          "tls/htsp-cert.pem"
#define TLS_AUTO_KEY           "tls/htsp-key.pem"

/* One TLS record worth of payload. */
#define TLS_BUF_SIZE           16384

struct tls_conn {
  SSL       *ssl;
  int        sock;      /* the TCP socket (owned by the caller) */
  int        pfd;       /* pump end of the socket pair */
  pthread_t  tid;
  char      *peer;
};

typedef struct tls_file_id {
  dev_t     dev;
  ino_t     ino;
  off_t     size;
  time_t    mtime;
  long      mtime_nsec;
} tls_file_id_t;

typedef struct tls_source {
  char          *cert;       /* resolved file names */
  char          *key;
  tls_file_id_t  cert_id;
  tls_file_id_t  key_id;
} tls_source_t;

static tvh_mutex_t   tls_lock;
static int           tls_lock_init;
static SSL_CTX      *tls_ctx;
static tls_source_t  tls_loaded;   /* what tls_ctx was built from */
static tls_source_t  tls_failed;   /* last source that did not load */
static char          tls_fp[3 * EVP_MAX_MD_SIZE + 1];

/*
 *
 */
static void
tls_log_errors(int level, const char *peer, const char *what)
{
  unsigned long e;
  char buf[256];
  int logged = 0;

  while ((e = ERR_get_error()) != 0) {
    ERR_error_string_n(e, buf, sizeof(buf));
    tvhlog(level, LS_TLS, "%s%s%s: %s", peer ?: "", peer ? ": " : "", what, buf);
    logged = 1;
  }
  if (!logged)
    tvhlog(level, LS_TLS, "%s%s%s", peer ?: "", peer ? ": " : "", what);
}

static void
tls_source_free(tls_source_t *s)
{
  free(s->cert);
  free(s->key);
  memset(s, 0, sizeof(*s));
}

static int
tls_file_id(const char *path, tls_file_id_t *id)
{
  struct stat st;

  memset(id, 0, sizeof(*id));
  if (stat(path, &st))
    return -1;
  id->dev   = st.st_dev;
  id->ino   = st.st_ino;
  id->size  = st.st_size;
  id->mtime = st.st_mtime;
#if defined(PLATFORM_DARWIN)
  id->mtime_nsec = st.st_mtimespec.tv_nsec;
#else
  id->mtime_nsec = st.st_mtim.tv_nsec;
#endif
  return 0;
}

static int
tls_source_equal(const tls_source_t *a, const tls_source_t *b)
{
  return a->cert && b->cert && a->key && b->key &&
         !strcmp(a->cert, b->cert) && !strcmp(a->key, b->key) &&
         !memcmp(&a->cert_id, &b->cert_id, sizeof(a->cert_id)) &&
         !memcmp(&a->key_id, &b->key_id, sizeof(a->key_id));
}

/*
 * Self-signed certificate
 */
static int
tls_add_ext(X509 *x, int nid, const char *value)
{
  X509V3_CTX ctx;
  X509_EXTENSION *ext;
  char buf[256];

  strlcpy(buf, value, sizeof(buf));
  X509V3_set_ctx_nodb(&ctx);
  X509V3_set_ctx(&ctx, x, x, NULL, NULL, 0);
  ext = X509V3_EXT_conf_nid(NULL, &ctx, nid, buf);
  if (ext == NULL)
    return -1;
  X509_add_ext(x, ext, -1);
  X509_EXTENSION_free(ext);
  return 0;
}

static int
tls_valid_dns_name(const char *s)
{
  if (*s == '\0' || *s == '-' || *s == '.')
    return 0;
  for ( ; *s; s++)
    if (!isalnum((unsigned char)*s) && *s != '-' && *s != '.')
      return 0;
  return 1;
}

static int
tls_write_pem(const char *path, int mode, EVP_PKEY *pkey, X509 *x)
{
  char tmp[PATH_MAX];
  FILE *f;
  int fd, ok;

  snprintf(tmp, sizeof(tmp), "%s.tmp", path);
  fd = tvh_open(tmp, O_CREAT | O_TRUNC | O_WRONLY, mode);
  if (fd < 0) {
    tvherror(LS_TLS, "unable to create %s: %s", tmp, strerror(errno));
    return -1;
  }
  f = fdopen(fd, "w");
  if (f == NULL) {
    close(fd);
    unlink(tmp);
    return -1;
  }
  if (pkey)
    ok = PEM_write_PrivateKey(f, pkey, NULL, NULL, 0, NULL, NULL);
  else
    ok = PEM_write_X509(f, x);
  if (fclose(f))
    ok = 0;
  if (!ok || rename(tmp, path)) {
    tvherror(LS_TLS, "unable to write %s", path);
    unlink(tmp);
    return -1;
  }
  return 0;
}

static int
tls_generate(const char *cert_path, const char *key_path)
{
  EVP_PKEY_CTX *pctx = NULL;
  EVP_PKEY *pkey = NULL;
  X509 *x = NULL;
  X509_NAME *name;
  BIGNUM *bn = NULL;
  uint8_t serial[16];
  char host[256], san[300];
  int r = -1;

  tvhinfo(LS_TLS, "generating a self-signed certificate %s", cert_path);

  if (hts_settings_makedirs(cert_path) || hts_settings_makedirs(key_path))
    return -1;

  pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
  if (pctx == NULL ||
      EVP_PKEY_keygen_init(pctx) <= 0 ||
      EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0 ||
      EVP_PKEY_keygen(pctx, &pkey) <= 0) {
    tls_log_errors(LOG_ERR, NULL, "key generation failed");
    goto end;
  }
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  EC_KEY_set_asn1_flag(EVP_PKEY_get0(pkey), OPENSSL_EC_NAMED_CURVE);
#endif

  if (gethostname(host, sizeof(host)) || !tls_valid_dns_name(host))
    strlcpy(host, "tvheadend", sizeof(host));
  host[sizeof(host) - 1] = '\0';

  x = X509_new();
  if (x == NULL || RAND_bytes(serial, sizeof(serial)) != 1)
    goto fail;
  serial[0] &= 0x7f;
  bn = BN_bin2bn(serial, sizeof(serial), NULL);
  if (bn == NULL ||
      !X509_set_version(x, 2) ||
      !BN_to_ASN1_INTEGER(bn, X509_get_serialNumber(x)) ||
      !X509_gmtime_adj(X509_get_notBefore(x), -86400) ||
      !X509_gmtime_adj(X509_get_notAfter(x), (long)TLS_CERT_DAYS * 86400) ||
      !X509_set_pubkey(x, pkey))
    goto fail;

  name = X509_get_subject_name(x);
  if (!X509_NAME_add_entry_by_txt(name, "O", MBSTRING_UTF8,
                                  (const unsigned char *)"Tvheadend", -1, -1, 0) ||
      !X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_UTF8,
                                  (const unsigned char *)host, -1, -1, 0) ||
      !X509_set_issuer_name(x, name))
    goto fail;

  snprintf(san, sizeof(san), "DNS:%s", host);
  if (tls_add_ext(x, NID_basic_constraints, "critical,CA:FALSE") ||
      tls_add_ext(x, NID_key_usage, "critical,digitalSignature") ||
      tls_add_ext(x, NID_ext_key_usage, "serverAuth") ||
      tls_add_ext(x, NID_subject_alt_name, san))
    goto fail;

  if (!X509_sign(x, pkey, EVP_sha256()))
    goto fail;

  /* The key first: a certificate without its key is useless. */
  if (tls_write_pem(key_path, S_IRUSR | S_IWUSR, pkey, NULL) ||
      tls_write_pem(cert_path, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH, NULL, x))
    goto end;

  r = 0;
  goto end;

fail:
  tls_log_errors(LOG_ERR, NULL, "certificate generation failed");
end:
  BN_free(bn);
  X509_free(x);
  EVP_PKEY_free(pkey);
  EVP_PKEY_CTX_free(pctx);
  return r;
}

/*
 * Context
 */
static SSL_CTX *
tls_ctx_create(const tls_source_t *src)
{
  static const unsigned char sid_ctx[] = "tvheadend";
  SSL_CTX *ctx;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
  ctx = SSL_CTX_new(SSLv23_server_method());
  if (ctx == NULL)
    goto fail;
  SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
                           SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
  SSL_CTX_set_ecdh_auto(ctx, 1);
#else
  ctx = SSL_CTX_new(TLS_server_method());
  if (ctx == NULL)
    goto fail;
  if (!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION))
    goto fail;
#endif
  SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION |
                           SSL_OP_CIPHER_SERVER_PREFERENCE
#ifdef SSL_OP_NO_RENEGOTIATION
                           | SSL_OP_NO_RENEGOTIATION
#endif
#ifdef SSL_OP_IGNORE_UNEXPECTED_EOF
                           /* HTSP messages carry their length, a
                            * truncation cannot go unnoticed: treat a
                            * close without close_notify as a close */
                           | SSL_OP_IGNORE_UNEXPECTED_EOF
#endif
                           );
  SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE |
                        SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
  /* TLS 1.2 cipher suites: forward secrecy and AEAD/strong ciphers only */
  if (SSL_CTX_set_cipher_list(ctx, "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4:!3DES") != 1)
    goto fail;
  if (!SSL_CTX_set_session_id_context(ctx, sid_ctx, sizeof(sid_ctx) - 1))
    goto fail;

  if (SSL_CTX_use_certificate_chain_file(ctx, src->cert) != 1) {
    tls_log_errors(LOG_ERR, NULL, "unable to load the certificate");
    goto err;
  }
  if (SSL_CTX_use_PrivateKey_file(ctx, src->key, SSL_FILETYPE_PEM) != 1) {
    tls_log_errors(LOG_ERR, NULL, "unable to load the private key");
    goto err;
  }
  if (SSL_CTX_check_private_key(ctx) != 1) {
    tls_log_errors(LOG_ERR, NULL, "the private key does not match the certificate");
    goto err;
  }
  return ctx;

fail:
  tls_log_errors(LOG_ERR, NULL, "unable to create the TLS context");
err:
  SSL_CTX_free(ctx);
  return NULL;
}

static void
tls_update_fingerprint(SSL_CTX *ctx)
{
  unsigned char md[EVP_MAX_MD_SIZE];
  unsigned int i, len = 0;
  X509 *x = SSL_CTX_get0_certificate(ctx);
  char *p = tls_fp;

  tls_fp[0] = '\0';
  if (x == NULL || !X509_digest(x, EVP_sha256(), md, &len))
    return;
  for (i = 0; i < len; i++)
    p += sprintf(p, i ? ":%02X" : "%02X", md[i]);
}

/*
 * The configuration is checked on each connection; a persisting error
 * is logged once (tls_lock held).
 */
static char tls_last_error[512];

static void __attribute__((format(printf, 1, 2)))
tls_resolve_error(const char *fmt, ...)
{
  char buf[sizeof(tls_last_error)];
  va_list ap;

  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  if (strcmp(buf, tls_last_error)) {
    strlcpy(tls_last_error, buf, sizeof(tls_last_error));
    tvherror(LS_TLS, "%s", buf);
  }
}

/*
 * Resolve the configured paths into the files to load. An empty
 * certificate path selects the generated certificate. An empty key path
 * means that the key is stored in the certificate file.
 */
static int
tls_resolve(const char *cert_cfg, const char *key_cfg, tls_source_t *src)
{
  char path[PATH_MAX];
  tls_file_id_t id;

  memset(src, 0, sizeof(*src));

  if (cert_cfg == NULL || *cert_cfg == '\0') {
    if (key_cfg && *key_cfg) {
      tls_resolve_error("a private key is configured without a certificate");
      return -1;
    }
    if (hts_settings_buildpath(path, sizeof(path), TLS_AUTO_CERT))
      return -1;
    src->cert = strdup(path);
    hts_settings_buildpath(path, sizeof(path), TLS_AUTO_KEY);
    src->key = strdup(path);
    if (tls_file_id(src->cert, &id) || tls_file_id(src->key, &id))
      if (tls_generate(src->cert, src->key))
        return -1;
  } else {
    src->cert = strdup(cert_cfg);
    src->key  = strdup(key_cfg && *key_cfg ? key_cfg : cert_cfg);
  }

  if (tls_file_id(src->cert, &src->cert_id)) {
    tls_resolve_error("certificate %s: %s", src->cert, strerror(errno));
    return -1;
  }
  if (tls_file_id(src->key, &src->key_id)) {
    tls_resolve_error("private key %s: %s", src->key, strerror(errno));
    return -1;
  }
  tls_last_error[0] = '\0';
  return 0;
}

int
tls_server_check(const char *cert_cfg, const char *key_cfg)
{
  tls_source_t src;
  SSL_CTX *ctx;
  int r;

  tvh_mutex_lock(&tls_lock);

  if (tls_resolve(cert_cfg, key_cfg, &src))
    goto end;

  /* Nothing changed since the last (successful or failed) attempt */
  if (tls_source_equal(&src, &tls_loaded) || tls_source_equal(&src, &tls_failed))
    goto end;

  ctx = tls_ctx_create(&src);
  if (ctx == NULL) {
    tvherror(LS_TLS, "%s: certificate not loaded%s", src.cert,
             tls_ctx ? ", keeping the previous one" : "");
    tls_source_free(&tls_failed);
    tls_failed = src;
    memset(&src, 0, sizeof(src));
    goto end;
  }

  SSL_CTX_free(tls_ctx);
  tls_ctx = ctx;
  tls_source_free(&tls_loaded);
  tls_source_free(&tls_failed);
  tls_loaded = src;
  memset(&src, 0, sizeof(src));
  tls_update_fingerprint(ctx);
  tvhinfo(LS_TLS, "using certificate %s (SHA-256 fingerprint %s)",
          tls_loaded.cert, tls_fp);

end:
  tls_source_free(&src);
  r = tls_ctx ? 0 : -1;
  tvh_mutex_unlock(&tls_lock);
  return r;
}

int
tls_server_init(const char *cert_cfg, const char *key_cfg)
{
  if (!tls_lock_init) {
    tvh_mutex_init(&tls_lock, NULL);
    tls_lock_init = 1;
  }
  return tls_server_check(cert_cfg, key_cfg);
}

void
tls_server_done(void)
{
  if (!tls_lock_init)
    return;
  tvh_mutex_lock(&tls_lock);
  SSL_CTX_free(tls_ctx);
  tls_ctx = NULL;
  tls_source_free(&tls_loaded);
  tls_source_free(&tls_failed);
  tls_fp[0] = '\0';
  tvh_mutex_unlock(&tls_lock);
}

void
tls_server_fingerprint(char *dst, size_t dstsize)
{
  if (!tls_lock_init) {
    if (dstsize)
      *dst = '\0';
    return;
  }
  tvh_mutex_lock(&tls_lock);
  strlcpy(dst, tls_fp, dstsize);
  tvh_mutex_unlock(&tls_lock);
}

/*
 * Connections
 */
static int
tls_set_nonblock(int fd)
{
  int fl = fcntl(fd, F_GETFL);
  return fl < 0 ? -1 : fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static int
tls_want(SSL *ssl, int r, short *events)
{
  switch (SSL_get_error(ssl, r)) {
  case SSL_ERROR_WANT_READ:
    *events |= POLLIN;
    return 0;
  case SSL_ERROR_WANT_WRITE:
    *events |= POLLOUT;
    return 0;
  default:
    return -1;
  }
}

/*
 * Move data between the TLS session and the socket pair until either
 * side is closed. The protocol code sees an EOF when this returns.
 */
static void *
tls_pump(void *aux)
{
  tls_conn_t *tc = aux;
  SSL *ssl = tc->ssl;
  uint8_t *in, *out;        /* in: from the client, out: to the client */
  size_t in_off = 0, in_len = 0, out_off = 0, out_len = 0;
  int app_eof = 0, app_hup = 0, sock_hup = 0, clean = 0;
  int64_t stall = 0;
  const char *reason = "closed";
  struct pollfd pfd[2];
  ssize_t n;
  int r, progress;

  in  = malloc(TLS_BUF_SIZE);
  out = malloc(TLS_BUF_SIZE);
  if (in == NULL || out == NULL) {
    reason = "out of memory";
    goto done;
  }

  while (1) {
    progress = 0;
    pfd[0].fd = tc->sock;
    pfd[0].events = 0;
    pfd[1].fd = app_hup ? -1 : tc->pfd;
    pfd[1].events = 0;

    /* client -> TLS -> in */
    if (in_len == 0 && !app_hup) {
      ERR_clear_error();
      r = SSL_read(ssl, in, TLS_BUF_SIZE);
      if (r > 0) {
        in_off = 0;
        in_len = r;
        progress = 1;
      } else if (SSL_get_error(ssl, r) == SSL_ERROR_ZERO_RETURN) {
        reason = "closed by the client";
        clean = 1;
        goto done;
      } else if (SSL_get_error(ssl, r) == SSL_ERROR_SYSCALL &&
                 ERR_peek_error() == 0 && (r == 0 || errno == 0 ||
                 errno == ECONNRESET)) {
        /* OpenSSL < 3.0: EOF without close_notify, or a reset */
        reason = "closed by the client";
        goto done;
      } else if (tls_want(ssl, r, &pfd[0].events)) {
        reason = "read failed";
        if (ERR_peek_error())
          tls_log_errors(LOG_DEBUG, tc->peer, "TLS read");
        goto done;
      }
    }

    /* in -> protocol */
    if (in_len) {
      n = send(tc->pfd, in + in_off, in_len, MSG_NOSIGNAL | MSG_DONTWAIT);
      if (n > 0) {
        in_off += n;
        in_len -= n;
        progress = 1;
      } else if (n < 0 && ERRNO_AGAIN(errno)) {
        pfd[1].events |= POLLOUT;
      } else {
        reason = "closed by the server";
        goto done;
      }
    }

    /* protocol -> out */
    if (out_len == 0 && !app_eof) {
      n = recv(tc->pfd, out, TLS_BUF_SIZE, MSG_DONTWAIT);
      if (n > 0) {
        out_off = 0;
        out_len = n;
        progress = 1;
      } else if (n < 0 && ERRNO_AGAIN(errno)) {
        pfd[1].events |= POLLIN;
      } else {
        app_eof = 1;
        progress = 1;
      }
    }

    /* out -> TLS -> client */
    if (out_len) {
      ERR_clear_error();
      r = SSL_write(ssl, out + out_off, out_len);
      if (r > 0) {
        out_off += r;
        out_len -= r;
        stall = 0;
        progress = 1;
      } else if (tls_want(ssl, r, &pfd[0].events)) {
        reason = "write failed";
        if (ERR_peek_error())
          tls_log_errors(LOG_DEBUG, tc->peer, "TLS write");
        goto done;
      }
    }

    if (app_eof && out_len == 0) {
      reason = "closed by the server";
      clean = 1;
      goto done;
    }

    if (progress)
      continue;

    if (out_len) {
      if (stall == 0) {
        stall = mclk();
      } else if (mclk() - stall > sec2mono(TLS_WRITE_TIMEOUT)) {
        reason = "write timeout";
        goto done;
      }
    }

    /* A hung up socket stays readable: poll it only when the TLS
     * session waits for it (the next TLS call then fails), not while
     * the decrypted data waits for the server side. */
    if (sock_hup && pfd[0].events == 0)
      pfd[0].fd = -1;

    r = poll(pfd, 2, 1000);
    if (r < 0 && !ERRNO_AGAIN(errno)) {
      reason = "poll failed";
      goto done;
    }
    if (r > 0 && (pfd[0].revents & (POLLHUP | POLLERR | POLLNVAL)))
      sock_hup = 1;
    if (r > 0 && (pfd[1].revents & (POLLHUP | POLLERR | POLLNVAL))) {
      /* The server side is gone, nothing can be delivered to it any
       * more. What it wrote before is still sent to the client. */
      app_hup = 1;
      in_len = 0;
    }
  }

done:
  if (clean) {
    ERR_clear_error();
    SSL_shutdown(ssl);
  }
  tvhdebug(LS_TLS, "%s: connection %s", tc->peer, reason);
  ERR_clear_error();
  shutdown(tc->pfd, SHUT_RDWR);
  close(tc->pfd);
  tc->pfd = -1;
  free(in);
  free(out);
  return NULL;
}

int
tls_server_accept(int fd, const char *peer, tls_conn_t **conn)
{
  struct pollfd pfd;
  struct timeval to;
  tls_conn_t *tc;
  SSL *ssl = NULL;
  int64_t deadline;
  int r, ms, sv[2] = { -1, -1 };

  *conn = NULL;

  tvh_mutex_lock(&tls_lock);
  if (tls_ctx)
    ssl = SSL_new(tls_ctx);
  tvh_mutex_unlock(&tls_lock);
  if (ssl == NULL) {
    tvherror(LS_TLS, "%s: no TLS context", peer);
    return -1;
  }

  if (tls_set_nonblock(fd) || !SSL_set_fd(ssl, fd)) {
    tvherror(LS_TLS, "%s: unable to set up the TLS session", peer);
    goto fail;
  }

  deadline = mclk() + sec2mono(TLS_HANDSHAKE_TIMEOUT);
  while (1) {
    ERR_clear_error();
    r = SSL_accept(ssl);
    if (r == 1)
      break;
    pfd.fd = fd;
    pfd.events = 0;
    if (tls_want(ssl, r, &pfd.events)) {
      tls_log_errors(LOG_INFO, peer, "TLS handshake failed");
      goto fail;
    }
    ms = (deadline - mclk()) / (MONOCLOCK_RESOLUTION / 1000);
    if (ms <= 0 || !tvheadend_is_running()) {
      tvhinfo(LS_TLS, "%s: TLS handshake timeout", peer);
      goto fail;
    }
    r = poll(&pfd, 1, MIN(ms, 1000));
    if (r < 0 && !ERRNO_AGAIN(errno))
      goto fail;
  }

  tvhdebug(LS_TLS, "%s: %s connection, cipher %s", peer,
           SSL_get_version(ssl), SSL_get_cipher_name(ssl));

  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) {
    tvherror(LS_TLS, "%s: socketpair: %s", peer, strerror(errno));
    goto fail;
  }
  fcntl(sv[0], F_SETFD, FD_CLOEXEC);
  fcntl(sv[1], F_SETFD, FD_CLOEXEC);
  if (tls_set_nonblock(sv[0]))
    goto fail;
  /* The protocol code expects the send timeout of tcp.c */
  to.tv_sec  = TLS_WRITE_TIMEOUT;
  to.tv_usec = 0;
  setsockopt(sv[1], SOL_SOCKET, SO_SNDTIMEO, &to, sizeof(to));

  tc = calloc(1, sizeof(*tc));
  tc->ssl  = ssl;
  tc->sock = fd;
  tc->pfd  = sv[0];
  tc->peer = strdup(peer);
  if (tvh_thread_create(&tc->tid, NULL, tls_pump, tc, "tls-pump")) {
    free(tc->peer);
    free(tc);
    goto fail;
  }

  *conn = tc;
  return sv[1];

fail:
  if (sv[0] >= 0)
    close(sv[0]);
  if (sv[1] >= 0)
    close(sv[1]);
  SSL_free(ssl);
  ERR_clear_error();
  return -1;
}

void
tls_conn_destroy(tls_conn_t *tc)
{
  if (tc == NULL)
    return;
  pthread_join(tc->tid, NULL);
  SSL_free(tc->ssl);
  free(tc->peer);
  free(tc);
}
