# Provisioning

Sidetone can fill one account from an XML file served over HTTP or HTTPS.
Open the account in Settings, press **Provision** (on an empty phone the same
button sits next to **Add account**), paste the URL, and save. A file that
fails verification leaves the form unchanged.

This is a Sidetone account file, not a Yealink (or any other desk-phone)
configuration. The root is `<sidetone-provision version="1">`. One file
describes one account, always index `1`. Unknown keys, a wrong version, a
wrong root, or a second account reject the whole file.

## File shape

```xml
<?xml version="1.0" encoding="UTF-8"?>
<sidetone-provision version="1">
  <account.1.user>2001</account.1.user>
  <account.1.display_name>Lab phone</account.1.display_name>
  <account.1.domain>pbx.example.com</account.1.domain>
</sidetone-provision>
```

Rules:

- The root element is `sidetone-provision` and its only attribute is
  `version="1"`.
- Every setting is a direct child of the root. Nested elements are rejected.
  Child elements have no attributes.
- The element name is the key: `account.1.` plus the field name.
- A key may appear once. Indexed lists (`codec`, `blf`, `header`) start at
  `1` and have no gaps.
- Text is plain. Standard XML entities (`&amp;`, `&lt;`, `&gt;`, `&quot;`,
  `&apos;`) are decoded. `<!DOCTYPE>`, `<!ENTITY>`, and `CDATA` are rejected.
  Comments are allowed. The body must be UTF-8.
- Booleans are `0` / `1` or `true` / `false` (any case).
- Enumerations (`transport`, `dtmf_mode`, `srtp`, `srtp_keys`,
  `sdp_direction`) are matched without regard to case.
- An omitted optional string is left unset. An empty element for those
  strings (`auth_user`, `password`, `outbound_proxy`, `q_value`, `local_ip`,
  `proxy_require`, `sdp_ip_override`) is also unset.
- Omitted booleans and numbers use the defaults below. The file does not
  inherit the built-in account name “Sidetone” or the user “sidetone”.
- `user`, `domain`, and `display_name` are required and must be non-empty.
  A missing or empty `display_name` fails the file.
- The account id, the profile name, the stored provisioning URL, and the
  “check the TLS certificate” choice are not keys. A later resync keeps them.

The desktop app and the browser phone do not accept the same keys. A desktop
file that contains `ws`, `ice`, or `remember_password` is rejected. A browser
file that contains a desktop-only key (`transport`, `codec.1`, `blf.1`,
`header.1.name`, and the rest of the desktop tables) is rejected.

## Desktop keys

### Identity and registration

| Key | Default if omitted | Values |
|---|---|---|
| `label` | empty | Name shown in the phone |
| `enabled` | `1` | `0` or `1` |
| `user` | required | SIP user / extension |
| `display_name` | required | Caller name |
| `auth_user` | unset | Digest username when it differs from `user` |
| `password` | unset | Registration password |
| `domain` | required | Registrar host or `host:port`. With no port, DNS SRV is tried |
| `register` | `1` | `0` for a trunk or a phone that only dials SIP URIs |
| `outbound_proxy` | unset | `host:port`. Every request is sent here |
| `expires` | `300` | Registration expiry, seconds |
| `retry_s` | `30` | Delay before retrying a failed registration |
| `q_value` | unset | Contact `q` value, as text |

### Transport

| Key | Default if omitted | Values |
|---|---|---|
| `transport` | `udp` | `udp`, `tcp`, `tls` |
| `tls_verify` | `1` | Check the PBX certificate against public roots |
| `local_ip` | unset | Address in Via, Contact, and SDP. Empty uses the route to the server |
| `local_port` | `0` | Local SIP port. `0` picks a free port |
| `rport` | `1` | Add `;rport` to Via |
| `symmetric_rtp` | `1` | Send audio back to the source of incoming RTP |
| `rtp_port_start` | `40000` | First RTP port. If both ends are set, the end must be greater or equal |
| `rtp_port_end` | `49999` | Last RTP port |
| `dscp_sip` | `0` | DSCP for SIP, `0`–`63` |
| `dscp_rtp` | `0` | DSCP for RTP, `0`–`63` |
| `sdp_ip_override` | unset | Address written in SDP `c=` |
| `t1_ms` | `500` | SIP timer T1 in milliseconds. Must be greater than `0` |
| `keepalive_interval` | `0` | CRLF keepalive period in seconds. `0` is off |
| `filter_registrar` | `0` | Ignore SIP requests that do not come from the registrar |

### Media

| Key | Default if omitted | Values |
|---|---|---|
| `codec.N` | `PCMU`, then `PCMA` | `PCMU`, `PCMA`, or `opus`. Any `codec.N` replaces the default list |
| `ptime_ms` | `20` | `10`, `20`, `30`, `40`, or `60` |
| `sdp_direction` | `sendrecv` | `sendrecv`, `sendonly`, `recvonly`, `inactive` |
| `srtp` | `off` | `off`, `optional`, `mandatory` |
| `srtp_keys` | `sdes` | `sdes` or `dtls` |
| `rtcp` | `0` | Send RTCP |
| `dtmf_mode` | `rfc4733` | `rfc4733`, `info`, `inband` |
| `dtmf_payload_type` | `101` | `0`–`127` |

### SIP behavior

| Key | Default if omitted | Values |
|---|---|---|
| `user_agent` | keep the account’s current value | A present element is used as written, including an empty one. A new account with no key uses `Sidetone/` plus the version |
| `max_forwards` | `70` | `1`–`255` |
| `session_timer` | `0` | `Session-Expires` in seconds. `0` is off |
| `user_phone` | `0` | Add `;user=phone` to numeric request URIs |
| `compact_headers` | `0` | Compact header names |
| `require_prack` | `0` | Send `Require: 100rel` |
| `offer_gruu` | `0` | Advertise GRUU |
| `long_contact` | `0` | Long Contact with `+sip.instance` |
| `proxy_require` | unset | Value of `Proxy-Require` |
| `skip_ack` | `0` | Omit the ACK for a 2xx (lab use) |
| `blf.N` | none | Extension to watch |
| `header.N.name` | none | Extra header name. Each index needs both `name` and `value` |
| `header.N.value` | none | Extra header value |

## Browser keys

The browser phone registers over WebSocket and plays audio with WebRTC. It
has no transport, codec, BLF, or header keys.

| Key | Default if omitted | Values |
|---|---|---|
| `label` | empty | Name shown in the phone |
| `enabled` | `1` | `0` or `1` |
| `register` | `1` | `0` or `1` |
| `user` | required | SIP user / extension |
| `password` | empty | Registration password |
| `display_name` | required | Caller name |
| `domain` | required | SIP domain |
| `ws` | required | `ws://` or `wss://` URL of the PBX WebSocket |
| `ice` | empty | ICE server URL, usually `stun:…` |
| `expires` | `300` | Registration expiry, seconds |
| `remember_password` | `0` | `0` keeps the password for this page load only. `1` stores it in the browser |

## Samples

### Desktop, small file

```xml
<?xml version="1.0" encoding="UTF-8"?>
<sidetone-provision version="1">
  <account.1.label>Lab</account.1.label>
  <account.1.user>2001</account.1.user>
  <account.1.auth_user>2001</account.1.auth_user>
  <account.1.password>secret</account.1.password>
  <account.1.display_name>Lab phone</account.1.display_name>
  <account.1.domain>pbx.example.com</account.1.domain>
  <account.1.transport>tcp</account.1.transport>
</sidetone-provision>
```

### Desktop, with media, BLF, and an extra header

```xml
<?xml version="1.0" encoding="UTF-8"?>
<sidetone-provision version="1">
  <account.1.label>Front desk</account.1.label>
  <account.1.enabled>1</account.1.enabled>
  <account.1.user>2001</account.1.user>
  <account.1.password>secret</account.1.password>
  <account.1.display_name>Front desk</account.1.display_name>
  <account.1.domain>pbx.example.com</account.1.domain>
  <account.1.register>1</account.1.register>
  <account.1.outbound_proxy>sbc.example.com:5061</account.1.outbound_proxy>
  <account.1.expires>600</account.1.expires>
  <account.1.transport>tls</account.1.transport>
  <account.1.tls_verify>1</account.1.tls_verify>
  <account.1.codec.1>opus</account.1.codec.1>
  <account.1.codec.2>PCMU</account.1.codec.2>
  <account.1.ptime_ms>20</account.1.ptime_ms>
  <account.1.srtp>optional</account.1.srtp>
  <account.1.srtp_keys>sdes</account.1.srtp_keys>
  <account.1.dtmf_mode>rfc4733</account.1.dtmf_mode>
  <account.1.blf.1>2002</account.1.blf.1>
  <account.1.blf.2>2003</account.1.blf.2>
  <account.1.header.1.name>X-Site</account.1.header.1.name>
  <account.1.header.1.value>lab</account.1.header.1.value>
</sidetone-provision>
```

### Desktop, every key

Omitted keys in the samples above take the defaults in the tables. This file
sets each desktop key once. `user_agent` is present on purpose: an empty or
custom value replaces the account’s current User-Agent. Delete that element
to keep the current one.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<sidetone-provision version="1">
  <account.1.label>Reference</account.1.label>
  <account.1.enabled>1</account.1.enabled>
  <account.1.user>2001</account.1.user>
  <account.1.display_name>Reference phone</account.1.display_name>
  <account.1.auth_user>2001</account.1.auth_user>
  <account.1.password>secret</account.1.password>
  <account.1.domain>pbx.example.com</account.1.domain>
  <account.1.register>1</account.1.register>
  <account.1.outbound_proxy>sbc.example.com:5061</account.1.outbound_proxy>
  <account.1.expires>300</account.1.expires>
  <account.1.retry_s>30</account.1.retry_s>
  <account.1.q_value>0.5</account.1.q_value>
  <account.1.transport>tls</account.1.transport>
  <account.1.tls_verify>1</account.1.tls_verify>
  <account.1.local_ip>10.0.0.20</account.1.local_ip>
  <account.1.local_port>5060</account.1.local_port>
  <account.1.rport>1</account.1.rport>
  <account.1.symmetric_rtp>1</account.1.symmetric_rtp>
  <account.1.rtp_port_start>40000</account.1.rtp_port_start>
  <account.1.rtp_port_end>49999</account.1.rtp_port_end>
  <account.1.dscp_sip>26</account.1.dscp_sip>
  <account.1.dscp_rtp>46</account.1.dscp_rtp>
  <account.1.sdp_ip_override></account.1.sdp_ip_override>
  <account.1.t1_ms>500</account.1.t1_ms>
  <account.1.keepalive_interval>30</account.1.keepalive_interval>
  <account.1.filter_registrar>0</account.1.filter_registrar>
  <account.1.codec.1>opus</account.1.codec.1>
  <account.1.codec.2>PCMU</account.1.codec.2>
  <account.1.codec.3>PCMA</account.1.codec.3>
  <account.1.ptime_ms>20</account.1.ptime_ms>
  <account.1.sdp_direction>sendrecv</account.1.sdp_direction>
  <account.1.srtp>off</account.1.srtp>
  <account.1.srtp_keys>sdes</account.1.srtp_keys>
  <account.1.rtcp>0</account.1.rtcp>
  <account.1.dtmf_mode>rfc4733</account.1.dtmf_mode>
  <account.1.dtmf_payload_type>101</account.1.dtmf_payload_type>
  <account.1.user_agent>Sidetone</account.1.user_agent>
  <account.1.max_forwards>70</account.1.max_forwards>
  <account.1.session_timer>0</account.1.session_timer>
  <account.1.user_phone>0</account.1.user_phone>
  <account.1.compact_headers>0</account.1.compact_headers>
  <account.1.require_prack>0</account.1.require_prack>
  <account.1.offer_gruu>0</account.1.offer_gruu>
  <account.1.long_contact>0</account.1.long_contact>
  <account.1.proxy_require></account.1.proxy_require>
  <account.1.skip_ack>0</account.1.skip_ack>
  <account.1.blf.1>2002</account.1.blf.1>
  <account.1.header.1.name>X-Site</account.1.header.1.name>
  <account.1.header.1.value>lab</account.1.header.1.value>
</sidetone-provision>
```

The empty `sdp_ip_override` and `proxy_require` elements clear those fields.
Leave the elements out to keep them unset as well.

### Browser

```xml
<?xml version="1.0" encoding="UTF-8"?>
<sidetone-provision version="1">
  <account.1.label>Web lab</account.1.label>
  <account.1.user>2001</account.1.user>
  <account.1.password>secret</account.1.password>
  <account.1.display_name>Lab phone</account.1.display_name>
  <account.1.domain>pbx.example.com</account.1.domain>
  <account.1.ws>wss://pbx.example.com:8089/ws</account.1.ws>
  <account.1.ice>stun:stun.l.google.com:19302</account.1.ice>
  <account.1.expires>300</account.1.expires>
  <account.1.remember_password>0</account.1.remember_password>
</sidetone-provision>
```

## Fetching the file

**Provision** downloads immediately, even during a call. A valid file is
saved and applied at once: the account is stored and registration starts.
If saving fails, the loaded values stay on the form as unsaved changes.
The URL shown on the account is stored, but the username and password in
the URL are not shown.

Desktop download:

- The URL must be `http` or `https`. Private and LAN addresses are allowed.
  The request `User-Agent` is `Sidetone/` plus the app version.
- The request times out after 15 seconds. The body must be at most 256 KiB
  and UTF-8.
- Redirects stay on `http` or `https`. An `https` URL does not follow a
  redirect to `http`.
- Credentials in the URL (`https://user:secret@host/acct.xml`) are removed
  from the request URL and sent as `Authorization: Basic`. That header is
  sent again only when a redirect stays on the same host. Logs and the
  account form omit the userinfo.
- `HTTP_PROXY` and `HTTPS_PROXY` are not used.
- HTTPS is checked against public roots. Turn off **Check the server's TLS
  certificate** in the dialog for a lab server with a private certificate.
  That choice is stored on the account and used again on resync.

The browser phone downloads with `fetch` and the page’s own TLS rules. It
cannot turn certificate checks off. The provisioning server must allow this
page’s origin (CORS). A page served over HTTPS cannot fetch an `http://`
URL; use the desktop app for a LAN HTTP server.

## Resync

A SIP NOTIFY whose event is `check-sync` or `resync` asks Sidetone to
download the stored URL again. The token is the text before the first `;`
or space, so `Event: check-sync;reboot=true` counts. `reboot=true` does not
exit the process: Sidetone downloads again and re-registers when the file
changed. Other event names are left alone.

Sidetone answers `200` immediately. If that account has a live line (calling,
ringing, early, incoming, connected, or ending), the download waits until
that account’s last line has ended. Another account’s call does not hold it.
Further NOTIFYs while one resync is waiting collapse into a single download.
A call that starts during the download holds the parsed file until the
account is idle again; the new settings are not applied mid-call.

Two attempts for the same account are at least 10 seconds apart, measured
from the start of the last HTTP request. A resync that was waiting on a call
uses whatever part of those 10 seconds is left.

With **Accept requests only from the registrar** on, a NOTIFY from anywhere
else is ignored before this runs.

If the new file matches the saved account, registration is left as it is. A
real change is applied only once the account is idle, and that account
registers again. If the account was deleted before the download finished, the
file is discarded. A background resync does not overwrite an account form
that still has unsaved edits; Sidetone tells you the saved account changed
and leaves the form alone.
