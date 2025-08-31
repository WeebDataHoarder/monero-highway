# monero-highway


## cmd/dns-checkpoints

A simple TCP/UDP DNS server that acts as a zone server for a subdomain whose only purpose is serve DNSSEC signed TXT records.

Effectively it is designed to serve MoneroPulse DNS Checkpoints as fast and cheap as possible while keeping full control of signing keys.

Supports ECDSA, Ed25519, RSA keys. Zone transfers (AXFR) are supported via TCP. Slave DNS servers can be hosted this way.

Simple update HTTP API. Adjustable TTL.

Written via [meikg/dns](https://github.com/miekg/dns) as DNS library, [used by many](https://github.com/miekg/dns?tab=readme-ov-file#users)

### Usage

If `-key` or `MONERO_HIGHWAY_KEY` env var is not specified, a random ECDSA key will be generated and printed to console, which can be used in future invocations.

State can be stored for startup via `-state`, otherwise new state needs to get fed via the HTTP api.

Example with multiple NS while authority is at `ns1-checkpoints.example.com` for the zone `checkpoints.example.com`

```
go run ./cmd/dns-checkpoints  \
-bind 0.0.0.0:15353 \
-api-bind 127.0.0.1:19080 \
-key key.sample \
-state state.sample.json \
-zone checkpoints.example.com \
-mailbox admin.example.com \
-ns ns1-checkpoints.example.com \
-ns ns0.1984.is \
-ns ns2.1984hosting.com \
-ns ns1.he.net \
-axfr
```

The server will start and produce some logs. Take note of the `DNS KSK` message, you will need it.

It looks something like `msg="DS KSK" record="checkpoints.example.com. 3600 IN DS 7820 13 2 821887C3654ACCD2DEA3AC14E7E05C9D324B9EFBF26ECBF30047B3DDB4DBF4F3"`

You need to bind to port 53 or alternatively map requests on TCP/UDP port 53 to your bound port.

On your DNS provider, create the following DNS records.

Add the DNS server IP on your slave DNS servers so they can fetch AXFR from your server. You might want to add IP allowlist on your firewall for these, or leave it open.

* A/AAAA or CNAME `ns1-checkpoints.example.com` Point to your main nameserver IP/host. Optional if hidden.
* DS `checkpoints.example.com` Composed of the key tag, algorithm, digest and fingerprint. In our DS KSK example, it's 7820, 13, 2 (SHA256) and `821887C3654ACCD2DEA3AC14E7E05C9D324B9EFBF26ECBF30047B3DDB4DBF4F3` respectively.
* NS `checkpoints.example.com` One for each primary and secondary nameserver. In current example, one for each of `ns1-checkpoints.example.com, ns0.1984.is, ns2.1984hosting.com, ns1.he.net`

With this (and after records have passed over) you should be able to verify it working with a dns utility like `dig`

```
$ dig +dnssec +multi checkpoints.example.com SOA @1.1.1.1

; <<>> DiG 9.18.36 <<>> +dnssec +multi checkpoints.example.com SOA @1.1.1.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 16829
;; flags: qr rd ra ad; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags: do; udp: 1232
;; QUESTION SECTION:
;checkpoints.example.com. IN SOA

;; ANSWER SECTION:
checkpoints.example.com. 3600 IN SOA ns1-checkpoints.example.com. admin.example.com. (
                                1756662356 ; serial
                                60         ; refresh (1 minute)
                                30         ; retry (30 seconds)
                                6000       ; expire (1 hour 40 minutes)
                                1800       ; minimum (30 minutes)
                                )
checkpoints.example.com. 3600 IN RRSIG SOA 13 3 3600 (
                                20250831184556 20250831174556 7819 checkpoints.example.com.
                                HByikdoFmsKnMwmCyOzLcjZILe7a8n41xqicQezF8yeK
                                1hLWKePxTyhiz8i/giZjUMMdL+o0q2KoUd7KRUHQQA== )

;; Query time: 12 msec
;; SERVER: 1.1.1.1#53(1.1.1.1) (UDP)
;; WHEN: Sun Aug 31 19:50:13 CEST 2025
;; MSG SIZE  rcvd: 250
```

### HTTP API

If enabled via `-api-bind 127.0.0.1:19080`, an HTTP API will be set on that port for writing new TXT records.

POST to the main HTTP endpoint with each record within the `txt` keys, in desired order. Multiple can be specified.

Example:

```
$ curl --verbose -XPOST "http://127.0.0.1:19080/?txt=abc123&txt=def567&txt=ghi890"
*   Trying 127.0.0.1:19080...
* Connected to 127.0.0.1 (127.0.0.1) port 19080
* using HTTP/1.x
> POST /?txt=abc123&txt=def567&txt=ghi890 HTTP/1.1
> Host: 127.0.0.1:19080
> User-Agent: curl/8.11.1
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 200 OK
< Date: Sun, 31 Aug 2025 18:07:08 GMT
< Content-Length: 0
< 
* Connection #0 to host 127.0.0.1 left intact
```

These records will be set atomically as a single unit, pre-signed with DNSSEC keys.

After this, the TXT records will be the three txt arguments in provided order.

```
dig checkpoints.example.com TXT @1.1.1.1

; <<>> DiG 9.18.36 <<>> checkpoints.example.com TXT @1.1.1.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 16783
;; flags: qr rd ra ad; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
;; QUESTION SECTION:
;checkpoints.example.com. IN      TXT

;; ANSWER SECTION:
checkpoints.example.com. 300 IN   TXT     "abc123"
checkpoints.example.com. 300 IN   TXT     "def567"
checkpoints.example.com. 300 IN   TXT     "ghi890"

;; Query time: 12 msec
;; SERVER: 1.1.1.1#53(1.1.1.1) (UDP)
;; WHEN: Sun Aug 31 20:08:30 CEST 2025
;; MSG SIZE  rcvd: 115
```

### FreeDNS slave providers

Via Zone transfers (AXFR) slave servers are supported. This can allow to maintain control of keys but have a wide DNS network, or keep the master server hidden.

You can also run your own slave nameservers with your preferred DNS server software and setting the main DNS server as master.

#### 1984 Hosting
 * Free of charge
 * https://1984.hosting/product/freedns/
 * Nameservers
   * ns0.1984.is
   * ns1.1984.is
   * ns1.1984hosting.com
   * ns2.1984.is
   * ns1.1984hosting.com
   
#### Hurricane Electric
* Free of charge
* https://dns.he.net/
* Nameservers
    * ns1.he.net
    * ns2.he.net
    * ns3.he.net
    * ns4.he.net
    * ns5.he.net

#### FreeDNS Afraid.org
* Free of charge
* Slow updates, TTL of one hour
* https://freedns.afraid.org/
* Nameservers
    * ns2.afraid.org