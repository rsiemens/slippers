# slippers

Slippers is a lightweight, zero-dependency SOCKS5 proxy that runs locally and transparently forwards traffic to an upstream SOCKS5 proxy requiring authentication.
It allows clients that don't support SOCKS5 authentication (like some browsers) to use an authenticated proxy indirectly.

## Usage

```
python slippers.py "socks5://username:password@my-socks-server.net:1080"
```

By default, slippers listens on localhost:1080

You can now use your local unauthenticated SOCKS5 endpoint

```
curl --socks5-hostname "socks5://127.0.0.1:1080" https://ifconfig.io/country_code
US
```

```
python slippers.py "socks5://username:password@my-socks-server.net:1080"
22:16:12 [INFO] Listening on localhost:1080
22:16:19 [INFO] 127.0.0.1 connected
22:16:19 [INFO] my-socks-server.net:1080 connected
22:16:19 [INFO] Tunnel between 127.0.0.1:49967 -> my-socks-server.net:1080 established
22:16:19 [INFO] 127.0.0.1:49967 disconnected
```
