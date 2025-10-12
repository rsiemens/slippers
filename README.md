Slippers is a lightweight, zero-dependency SOCKS5 proxy that runs locally and transparently forwards traffic to an upstream SOCKS5 proxy requiring authentication.
It allows clients that don't support SOCKS5 authentication (like some browsers) to use an authenticated proxy indirectly.

## CLI Usage

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


## Programmatic Usage


### Sync

```python
import os
import slippers
from playwright.sync_api import sync_playwright

username = os.getenv("SOCKS_USERNAME")
password = os.getenv("SOCKS_PASSWORD")


def main():
    with (
        sync_playwright() as p,
        slippers.proxy(
            f"socks5://{username}:{password}@my-socks-server.net:1080"
        ) as socks_host,
    ):
        browser = p.chromium.launch(
            headless=True,
            proxy={"server": socks_host},  # point to slippers local server
        )
        page = browser.new_page()
        page.goto("https://ifconfig.io/country_code", wait_until="domcontentloaded")
        print(page.text_content("body").strip())
        browser.close()


if __name__ == "__main__":
    main()
