### Notes

* The out-of-the-box default settings should suit most set-ups, you should rarely need to change the them.
* Changing some of these settings **may** cause unexpected results, you have been warned!

### Encrypted HTSP (TLS)

HTSP on the standard port (9982) is not encrypted: the user name, the
EPG, the recordings and the streams can be read by anyone on the network
path, and the session can be tampered with. Only the password is
protected (challenge-response).

Tick *Enable encrypted HTSP port* to accept HTSP over TLS on a separate
TCP port (standard port 9984). The change is applied on *Save*, without
a restart, and the *Status* shows whether the port is open. The plain
port keeps working, so existing clients are not affected. The client has
to support TLS.

* The command line option `--htsp_tls_port` overrides these settings
  (they are read-only then). Use it for ports below 1024, which can
  only be opened before Tvheadend drops the root privileges.

* With no *Certificate file* set, Tvheadend generates a self-signed
  certificate in the configuration directory (`tls/htsp-cert.pem` and
  `tls/htsp-key.pem`). Compare the *Certificate fingerprint* shown here
  with the one the client shows on the first connection. Delete both
  files and restart Tvheadend to get a new certificate.
* To use a certificate from a certificate authority (e.g. Let's
  Encrypt), set the *Certificate file* (full chain) and the *Private key
  file*. The files are checked on each new connection, so a renewed
  certificate is used without a restart.
* TLS 1.2 or newer is required.
* Access rights, users and passwords are the same as on the plain port.
  To allow only encrypted connections from outside your network, do not
  forward the plain port on your router (or restrict it with a firewall).\n