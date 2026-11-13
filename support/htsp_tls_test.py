#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Copyright (C) 2026 Tvheadend contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
"""
Integration test of the encrypted (TLS) HTSP port.

Starts tvheadend with a temporary configuration directory on free local
ports and talks to it over HTSP, plain and encrypted.

  support/htsp_tls_test.py [-b build.linux/tvheadend] [--valgrind] [-v]

Requires python 3.7+ and the openssl command line tool.
"""

import argparse
import hashlib
import json
import os
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
import urllib.request
import warnings

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'lib', 'py'))

from tvh.htsp import HTSPClient, cert_fingerprint  # noqa: E402
import tvh.htsmsg as htsmsg                         # noqa: E402

OPTS = None
SERVER = None
VALGRIND_REPORTS = []

USER = 'tlsuser'
PASSWD = 'tls-secret'


def free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Server(object):

    def __init__(self, binary, tls=True, valgrind=False):
        self.binary = binary
        self.confdir = tempfile.mkdtemp(prefix='tvh-tls-test-')
        self.http_port = free_port()
        self.htsp_port = free_port()
        self.tls_port = free_port() if tls else None
        self.log = os.path.join(self.confdir, 'tvheadend.log')
        self.valgrind = valgrind
        self.proc = None

    def start(self):
        cmd = [self.binary, '-c', self.confdir, '-C', '-B', '-a', '-1',
               '--nosatipcli', '-b', '127.0.0.1',
               '--http_port', str(self.http_port),
               '--htsp_port', str(self.htsp_port),
               '-l', self.log, '--debug', 'tls,htsp']
        if self.tls_port:
            cmd += ['--htsp_tls_port', str(self.tls_port)]
        if self.valgrind:
            cmd = ['valgrind', '--error-exitcode=99', '--leak-check=no',
                   '--log-file=' + os.path.join(self.confdir, 'valgrind.%p.log')] + cmd
        self.proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL)
        deadline = time.time() + (120 if self.valgrind else 30)
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise Exception('tvheadend exited with %d\n%s' %
                                (self.proc.returncode, self.log_tail()))
            try:
                self.api('serverinfo')
                return
            except Exception:
                time.sleep(0.2)
        raise Exception('tvheadend did not start\n' + self.log_tail())

    def stop(self):
        rc = None
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                rc = self.proc.wait(60 if self.valgrind else 20)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
                raise Exception('tvheadend did not stop\n' + self.log_tail())
        return rc

    def cleanup(self):
        shutil.rmtree(self.confdir, ignore_errors=True)

    def valgrind_report(self):
        """(errors in the TLS/HTSP code, any other errors) of all runs."""
        ours, other = [], False
        for name in sorted(os.listdir(self.confdir)):
            if name.startswith('valgrind.') and name.endswith('.log'):
                with open(os.path.join(self.confdir, name)) as f:
                    vg = f.read()
                ours += valgrind_errors(vg, ('tls_server.c', 'htsp_server.c'))
                other = other or 'ERROR SUMMARY: 0 errors' not in vg
        return ours, other

    def log_tail(self, lines=40):
        try:
            with open(self.log, errors='replace') as f:
                return ''.join(f.readlines()[-lines:])
        except OSError:
            return '(no log)'

    def log_text(self):
        try:
            with open(self.log, errors='replace') as f:
                return f.read()
        except OSError:
            return ''

    def api(self, path, **args):
        data = urllib.parse.urlencode(
            {k: json.dumps(v) if isinstance(v, (dict, list)) else v
             for k, v in args.items()}).encode()
        url = 'http://127.0.0.1:%d/api/%s' % (self.http_port, path)
        with urllib.request.urlopen(url, data, timeout=10) as r:
            body = r.read()
        return json.loads(body) if body else None

    def config(self, key, attr='value'):
        for p in self.api('config/load')['entries'][0]['params']:
            if p['id'] == key:
                return p.get(attr)
        raise KeyError(key)

    def connections(self):
        return self.api('status/connections').get('entries', [])

    def connect(self, tls=True, **kw):
        port = self.tls_port if tls else self.htsp_port
        return HTSPClient(('127.0.0.1', port), name='tls-test', tls=tls,
                          timeout=kw.pop('timeout', 20), **kw)


def recv_or_none(sock, n=1):
    """recv() that maps a reset to b'' (both mean: closed)."""
    try:
        return sock.recv(n)
    except (ConnectionResetError, ssl.SSLError):
        return b''


def make_cert(directory, name, keytype='rsa:2048'):
    cert = os.path.join(directory, name + '.crt')
    key = os.path.join(directory, name + '.key')
    subprocess.check_call(['openssl', 'req', '-x509', '-newkey', keytype,
                           '-nodes', '-days', '2', '-subj', '/CN=' + name,
                           '-keyout', key, '-out', cert],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    with open(cert) as f:
        der = ssl.PEM_cert_to_DER_cert(f.read())
    return cert, key, cert_fingerprint(der)


def valgrind_errors(log, files):
    """Error records of a valgrind log with a stack frame in one of files."""
    blocks, cur = [], []
    for line in log.splitlines():
        text = line.split('== ', 1)[-1] if line.startswith('==') else line
        if not text.strip():
            if cur:
                blocks.append(cur)
            cur = []
        else:
            cur.append(text)
    if cur:
        blocks.append(cur)
    return ['\n'.join(b) for b in blocks
            if b[0].strip() and not b[0].startswith((' ', 'Memcheck', 'Copyright',
                                                      'Using', 'Command', 'Parent',
                                                      'HEAP', 'For ', 'Use ', 'ERROR'))
            and any(f in line for line in b for f in files)]


def wait_for(cond, timeout=10, step=0.1):
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = cond()
        if r:
            return r
        time.sleep(step)
    return cond()


class HTSPTLSTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        srv = SERVER
        srv.api('access/entry/create', conf={
            'enabled': True, 'username': USER, 'prefix': '127.0.0.1/32',
            'streaming': ['basic', 'htsp'], 'dvr': ['basic', 'htsp'],
            'webui': True, 'admin': False})
        srv.api('passwd/entry/create', conf={
            'enabled': True, 'username': USER, 'password': PASSWD})

    def tearDown(self):
        # every test must leave no connection behind
        left = wait_for(lambda: not [c for c in SERVER.connections()
                                     if c.get('type', '').startswith('HTSP')])
        self.assertTrue(left, 'HTSP connections left: %s' % SERVER.connections())

    # -- certificate --------------------------------------------------------

    def test_01_generated_certificate(self):
        """A self-signed certificate is generated and its fingerprint shown."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection(('127.0.0.1', SERVER.tls_port), 10) as s:
            with ctx.wrap_socket(s) as t:
                der = t.getpeercert(binary_form=True)
        self.assertEqual(cert_fingerprint(der), SERVER.config('htsp_tls_fingerprint'))
        key = os.path.join(SERVER.confdir, 'tls', 'htsp-key.pem')
        cert = os.path.join(SERVER.confdir, 'tls', 'htsp-cert.pem')
        self.assertTrue(os.path.isfile(cert))
        self.assertEqual(stat.S_IMODE(os.stat(key).st_mode), 0o600)

    def test_02_fingerprint_pinning(self):
        """The client accepts the right fingerprint only."""
        fp = SERVER.config('htsp_tls_fingerprint')
        c = SERVER.connect(fingerprint=fp.lower().replace(':', ''))
        c.hello()
        c.disconnect()
        with self.assertRaisesRegex(Exception, 'fingerprint mismatch'):
            SERVER.connect(fingerprint='00' * 32)

    def test_03_untrusted_without_pinning(self):
        """Without a fingerprint, the self-signed certificate is refused."""
        with self.assertRaises(ssl.SSLCertVerificationError):
            SERVER.connect()

    # -- protocol -----------------------------------------------------------

    def test_10_hello_and_authenticate(self):
        """HTSP over TLS: hello, authentication, connection type HTSPS."""
        c = SERVER.connect(fingerprint=SERVER.config('htsp_tls_fingerprint'))
        try:
            msg = c.hello()
            self.assertIn('challenge', msg)
            self.assertEqual(len(msg['challenge']), 32)
            c.authenticate(USER, PASSWD)
            c.send('getSysTime')
            self.assertIn('time', c.recv())
            conns = [x for x in SERVER.connections() if x.get('type') == 'HTSPS']
            self.assertEqual(len(conns), 1, SERVER.connections())
            self.assertEqual(conns[0].get('user'), USER)
        finally:
            c.disconnect()

    def test_11_wrong_password(self):
        """A wrong password does not grant the user's account."""
        c = SERVER.connect(fingerprint=SERVER.config('htsp_tls_fingerprint'))
        try:
            c.hello()
            c._user = USER
            c._pass = hashlib.sha1(b'wrong' + c._auth).digest()
            c.send('getSysTime')
            c.recv()
            conns = [x for x in SERVER.connections() if x.get('type') == 'HTSPS']
            self.assertNotIn(USER, conns[0].get('user') or '')
            self.assertIn('Unauthorized access', SERVER.log_text())
        finally:
            c.disconnect()

    def test_12_plain_port_unaffected(self):
        """The plain port still speaks plain HTSP."""
        c = SERVER.connect(tls=False)
        try:
            c.hello()
            c.authenticate(USER, PASSWD)
            conns = [x for x in SERVER.connections() if x.get('type', '').startswith('HTSP')]
            self.assertEqual([x.get('type') for x in conns], ['HTSP'])
        finally:
            c.disconnect()

    def test_13_large_transfer(self):
        """Many and large messages (~1.2 MB) pass the TLS layer intact."""
        # channel tags need no tuner (channels without services are not sent)
        names = []
        for i in range(300):
            name = 'TLS test tag %03d %s' % (i, ''.join(
                chr(0x41 + (i + j) % 26) for j in range(4000)))
            names.append(name)
            SERVER.api('channeltag/create', conf={'name': name, 'enabled': True})
        try:
            # (tls, slow): a slow reader fills all buffers on the way
            for tls, slow in ((False, False), (True, False), (True, True)):
                kw = {'fingerprint': SERVER.config('htsp_tls_fingerprint')} if tls else {}
                c = SERVER.connect(tls=tls, **kw)
                try:
                    c.hello()
                    c.authenticate(USER, PASSWD)
                    c.enableAsyncMetadata()
                    if slow:
                        time.sleep(3)
                    got = []
                    while True:
                        m = c.recv()
                        if m.get('method') == 'tagAdd':
                            got.append(m['tagName'])
                        if m.get('method') == 'initialSyncCompleted':
                            break
                    self.assertEqual(sorted(got), sorted(names), 'tls=%s' % tls)
                finally:
                    c.disconnect()
        finally:
            for ct in SERVER.api('channeltag/grid', limit=1000)['entries']:
                SERVER.api('idnode/delete', uuid=ct['uuid'])

    def test_14_parallel_clients(self):
        """Concurrent sessions do not interfere."""
        fp = SERVER.config('htsp_tls_fingerprint')
        errors = []

        def worker():
            try:
                c = SERVER.connect(fingerprint=fp)
                try:
                    c.hello()
                    c.authenticate(USER, PASSWD)
                    for i in range(20):
                        c.send('getSysTime', {'seq': i})
                        m = c.recv()
                        if m.get('seq') != i or 'time' not in m:
                            raise Exception('bad reply %r' % m)
                finally:
                    c.disconnect()
            except Exception as e:
                errors.append(repr(e))

        threads = [threading.Thread(target=worker) for _ in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(60)
        self.assertEqual(errors, [])

    # -- failure handling ---------------------------------------------------

    def test_20_plaintext_client_on_tls_port(self):
        """A plain HTSP client on the TLS port is disconnected."""
        s = socket.create_connection(('127.0.0.1', SERVER.tls_port), 15)
        try:
            s.sendall(htsmsg.serialize({'method': 'hello', 'htspversion': 34}))
            data = b''
            while True:
                chunk = recv_or_none(s, 4096)
                if not chunk:
                    break
                data += chunk
            # nothing, or a TLS alert record (content type 21): never HTSP
            self.assertTrue(data == b'' or data[0] == 21, data[:16])
        finally:
            s.close()
        # the server is still fine
        c = SERVER.connect(fingerprint=SERVER.config('htsp_tls_fingerprint'))
        c.hello()
        c.disconnect()
        self.assertIn('TLS handshake failed', SERVER.log_text())

    def test_21_handshake_timeout(self):
        """An idle connection is closed when the handshake does not start."""
        s = socket.create_connection(('127.0.0.1', SERVER.tls_port), 30)
        try:
            t0 = time.time()
            self.assertEqual(recv_or_none(s), b'')
            elapsed = time.time() - t0
            self.assertGreater(elapsed, 8)
            self.assertLess(elapsed, 20)
        finally:
            s.close()

    def test_22_client_drops_connection(self):
        """Abrupt client disconnects (with pending data) are cleaned up."""
        fp = SERVER.config('htsp_tls_fingerprint')
        for _ in range(5):
            c = SERVER.connect(fingerprint=fp)
            c.hello()
            c.enableAsyncMetadata({'epg': 1})
            # reset instead of close_notify
            c._sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                               b'\x01\x00\x00\x00\x00\x00\x00\x00')
            c._rfile.close()
            c._sock.close()
        # tearDown checks that nothing is left over

    def test_23_server_drops_connection(self):
        """Drop in the Connections UI ends the TLS session."""
        c = SERVER.connect(fingerprint=SERVER.config('htsp_tls_fingerprint'))
        try:
            c.hello()
            conns = wait_for(lambda: [x for x in SERVER.connections()
                                      if x.get('type') == 'HTSPS'])
            SERVER.api('connections/cancel', id=conns[0]['id'])
            c._sock.settimeout(10)
            with self.assertRaises((StopIteration, ConnectionError, ssl.SSLError, OSError)):
                c.recv()
        finally:
            c.disconnect()

    def test_24_tls_versions(self):
        """TLS 1.2 and 1.3 are accepted, older versions are not."""
        for ver in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ctx.maximum_version = ver
            with socket.create_connection(('127.0.0.1', SERVER.tls_port), 10) as s:
                with ctx.wrap_socket(s) as t:
                    self.assertEqual(t.version(), {ssl.TLSVersion.TLSv1_2: 'TLSv1.2',
                                                   ssl.TLSVersion.TLSv1_3: 'TLSv1.3'}[ver])
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        warnings.simplefilter('ignore', DeprecationWarning)
        try:
            ctx.minimum_version = ssl.TLSVersion.TLSv1
            ctx.maximum_version = ssl.TLSVersion.TLSv1_1
            ctx.set_ciphers('ALL:@SECLEVEL=0')
        except (ValueError, ssl.SSLError):
            self.skipTest('the local OpenSSL cannot offer TLS 1.1')
        with socket.create_connection(('127.0.0.1', SERVER.tls_port), 10) as s:
            with self.assertRaises((ssl.SSLError, ConnectionError)):
                ctx.wrap_socket(s)

    # -- configuration ------------------------------------------------------

    def test_29_command_line_locks_web_config(self):
        """--htsp_tls_port overrides the web configuration (read-only)."""
        self.assertEqual(SERVER.config('htsp_tls_status'),
                         'Listening on TCP port %d (command line option '
                         '--htsp_tls_port)' % SERVER.tls_port)
        self.assertTrue(SERVER.config('htsp_tls_enabled', 'rdonly'))
        self.assertTrue(SERVER.config('htsp_tls_port', 'rdonly'))
        SERVER.api('config/save', node={'htsp_tls_enabled': False,
                                        'htsp_tls_port': free_port()})
        self.assertTrue(listening(SERVER.tls_port))
        self.assertEqual(SERVER.config('htsp_tls_status'),
                         'Listening on TCP port %d (command line option '
                         '--htsp_tls_port)' % SERVER.tls_port)

    def test_30_custom_certificate(self):
        """A configured certificate is used, renewed in place, and a broken
        configuration keeps the previous certificate."""
        tmp = tempfile.mkdtemp(prefix='tvh-tls-cert-')
        try:
            cert, key, fp1 = make_cert(tmp, 'one')
            SERVER.api('config/save', node={'htsp_tls_cert': cert, 'htsp_tls_key': key})
            self.assertEqual(SERVER.config('htsp_tls_fingerprint'), fp1)
            c = SERVER.connect(fingerprint=fp1)
            c.hello()
            c.disconnect()

            # renewal: same paths, new content
            time.sleep(1.1)
            _, _, fp2 = make_cert(tmp, 'two')
            os.replace(os.path.join(tmp, 'two.crt'), cert)
            os.replace(os.path.join(tmp, 'two.key'), key)
            c = SERVER.connect(fingerprint=fp2)
            c.hello()
            c.disconnect()
            self.assertEqual(SERVER.config('htsp_tls_fingerprint'), fp2)

            # a combined PEM file (key in the certificate file)
            both = os.path.join(tmp, 'both.pem')
            with open(both, 'w') as f, open(cert) as fc, open(key) as fk:
                f.write(fc.read() + fk.read())
            SERVER.api('config/save', node={'htsp_tls_cert': both, 'htsp_tls_key': ''})
            c = SERVER.connect(fingerprint=fp2)
            c.hello()
            c.disconnect()

            # a broken path keeps the loaded certificate
            SERVER.api('config/save', node={'htsp_tls_cert': os.path.join(tmp, 'missing.pem')})
            self.assertEqual(SERVER.config('htsp_tls_fingerprint'), fp2)
            c = SERVER.connect(fingerprint=fp2)
            c.hello()
            c.disconnect()
            self.assertEqual(SERVER.log_text().count('missing.pem: No such file'), 1)

            # mismatched key and certificate
            _, key3, _ = make_cert(tmp, 'three')
            SERVER.api('config/save', node={'htsp_tls_cert': cert, 'htsp_tls_key': key3})
            self.assertEqual(SERVER.config('htsp_tls_fingerprint'), fp2)
            self.assertIn('certificate not loaded', SERVER.log_text())
        finally:
            # back to the generated certificate
            SERVER.api('config/save', node={'htsp_tls_cert': '', 'htsp_tls_key': ''})
            shutil.rmtree(tmp, ignore_errors=True)
        fp = SERVER.config('htsp_tls_fingerprint')
        c = SERVER.connect(fingerprint=fp)
        c.hello()
        c.disconnect()


def listening(port):
    try:
        socket.create_connection(('127.0.0.1', port), 5).close()
        return True
    except ConnectionRefusedError:
        return False


class WebConfigTest(unittest.TestCase):
    """The encrypted port enabled in the web configuration (no command
    line option)."""

    @classmethod
    def setUpClass(cls):
        cls.srv = Server(OPTS.binary, tls=False, valgrind=OPTS.valgrind)
        cls.srv.start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.stop()
        if OPTS.valgrind:
            VALGRIND_REPORTS.append(cls.srv.valgrind_report())
        cls.srv.cleanup()

    def save(self, **conf):
        self.srv.api('config/save', node=conf)
        return self.srv.config('htsp_tls_status')

    def connect(self, port):
        fp = self.srv.config('htsp_tls_fingerprint')
        c = HTSPClient(('127.0.0.1', port), tls=True, fingerprint=fp, timeout=20)
        c.hello()
        return c

    def test_0_field_metadata(self):
        """The UI metadata of the configuration is consistent (a broken
        integer range blocks Save of the whole page in the web UI)."""
        params = self.srv.api('config/load', meta=1)['entries'][0]['params']
        for p in params:
            if 'intmin' in p and 'intmax' in p:
                self.assertLessEqual(p['intmin'], p['intmax'], p['id'])
        tls = {p['id']: p for p in params if p['id'].startswith('htsp_tls')}
        self.assertEqual(sorted(tls), sorted([
            'htsp_tls_enabled', 'htsp_tls_port', 'htsp_tls_status',
            'htsp_tls_fingerprint', 'htsp_tls_cert', 'htsp_tls_key']))
        self.assertTrue(tls['htsp_tls_status'].get('rdonly'))
        self.assertTrue(tls['htsp_tls_fingerprint'].get('rdonly'))
        self.assertFalse(tls['htsp_tls_enabled'].get('rdonly'))
        self.assertFalse(tls['htsp_tls_port'].get('rdonly'))

    def test_1_disabled_by_default(self):
        """Disabled by default: nothing listens and no key is generated."""
        srv = self.srv
        self.assertIs(srv.config('htsp_tls_enabled'), False)
        self.assertEqual(srv.config('htsp_tls_port'), 9984)
        self.assertEqual(srv.config('htsp_tls_status'), 'Disabled')
        self.assertEqual(srv.config('htsp_tls_fingerprint'), '')
        self.assertFalse(os.path.exists(os.path.join(srv.confdir, 'tls')))

    def test_2_enable_move_disable(self):
        """The port opens, moves and closes on save; sessions survive."""
        p1, p2 = free_port(), free_port()
        self.assertEqual(self.save(htsp_tls_enabled=True, htsp_tls_port=p1),
                         'Listening on TCP port %d' % p1)
        self.assertTrue(self.srv.config('htsp_tls_fingerprint'))
        c = self.connect(p1)
        try:
            # move
            self.assertEqual(self.save(htsp_tls_port=p2),
                             'Listening on TCP port %d' % p2)
            self.assertFalse(listening(p1))
            self.connect(p2).disconnect()
            # the session on the old port goes on
            c.send('getSysTime')
            self.assertIn('time', c.recv())

            # not a TCP port: ignored
            for bad in (0, -1, 65536):
                self.assertEqual(self.save(htsp_tls_port=bad),
                                 'Listening on TCP port %d' % p2)
                self.assertEqual(self.srv.config('htsp_tls_port'), p2)

            # a port in use
            status = self.save(htsp_tls_port=self.srv.http_port)
            self.assertEqual(status, 'Not started: TCP port %d cannot be opened '
                             '(see the log)' % self.srv.http_port)
            self.assertEqual(self.save(htsp_tls_port=p2),
                             'Listening on TCP port %d' % p2)

            # disable
            self.assertEqual(self.save(htsp_tls_enabled=False), 'Disabled')
            self.assertFalse(listening(p2))
            self.assertEqual(self.srv.config('htsp_tls_fingerprint'), '')
            c.send('getSysTime')
            self.assertIn('time', c.recv())
        finally:
            c.disconnect()

    def test_3_certificate_error(self):
        """Without a usable certificate the port stays closed until fixed.

        (A certificate loaded before is kept when the configured one
        breaks, so this needs a fresh start.)"""
        port = free_port()
        self.save(htsp_tls_enabled=False,
                  htsp_tls_cert='/nonexistent/cert.pem', htsp_tls_key='')
        self.srv.stop()
        self.srv.start()
        try:
            self.assertEqual(self.save(htsp_tls_enabled=True, htsp_tls_port=port),
                             'Not started: no usable certificate (see the log)')
            self.assertFalse(listening(port))
            self.assertEqual(self.save(htsp_tls_cert=''),
                             'Listening on TCP port %d' % port)
            self.connect(port).disconnect()
        finally:
            self.save(htsp_tls_enabled=False, htsp_tls_cert='')

    def test_4_persistent(self):
        """The setting survives a restart."""
        port = free_port()
        self.save(htsp_tls_enabled=True, htsp_tls_port=port)
        fp = self.srv.config('htsp_tls_fingerprint')
        self.srv.stop()
        self.srv.start()
        try:
            self.assertEqual(self.srv.config('htsp_tls_status'),
                             'Listening on TCP port %d' % port)
            self.assertEqual(self.srv.config('htsp_tls_fingerprint'), fp)
            self.connect(port).disconnect()
        finally:
            self.save(htsp_tls_enabled=False)


def main():
    global OPTS, SERVER
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('-b', '--binary', default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)), '..', 'build.linux', 'tvheadend'))
    p.add_argument('--valgrind', action='store_true',
                   help='run tvheadend under valgrind (memcheck)')
    p.add_argument('--keep', action='store_true',
                   help='keep the temporary configuration directory')
    p.add_argument('-v', '--verbose', action='store_true')
    OPTS, rest = p.parse_known_args()

    SERVER = Server(OPTS.binary, valgrind=OPTS.valgrind)
    SERVER.start()
    ok = False
    try:
        prog = unittest.main(argv=[sys.argv[0]] + rest, exit=False,
                             verbosity=2 if OPTS.verbose else 1)
        ok = prog.result.wasSuccessful()
    finally:
        rc = SERVER.stop()
        if not ok:
            sys.stderr.write('--- tvheadend log (tail) ---\n%s' % SERVER.log_tail(80))
        if OPTS.valgrind:
            VALGRIND_REPORTS.append(SERVER.valgrind_report())
            ours = [e for r in VALGRIND_REPORTS for e in r[0]]
            if ours:
                sys.stderr.write('--- valgrind errors in the TLS/HTSP code ---\n%s\n'
                                 % '\n\n'.join(ours))
                ok = False
            elif any(r[1] for r in VALGRIND_REPORTS):
                sys.stderr.write('note: valgrind reports errors outside the TLS/HTSP '
                                 'code (see --keep)\n')
            # memcheck exits with 99 on any error; judged above
            if rc == 99:
                rc = 0
        if rc not in (0, None):
            sys.stderr.write('tvheadend exit code %s\n' % rc)
            ok = False
        if OPTS.keep:
            sys.stderr.write('configuration kept in %s\n' % SERVER.confdir)
        else:
            SERVER.cleanup()
    sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
