Slippers is a lightweight, zero-dependency SOCKS5 proxy that runs locally and transparently forwards traffic to an upstream SOCKS5 proxy requiring authentication.
It allows clients that don't support SOCKS5 authentication (like some browsers) to use an authenticated proxy indirectly.

## Installation

```
pip install slippers-proxy
```

## CLI Usage

```
python -m slippers "socks5://username:password@my-socks-server.net:1080"
```

By default, slippers listens on localhost:1080

You can now use your local unauthenticated SOCKS5 endpoint

```
curl --socks5-hostname "socks5://127.0.0.1:1080" https://ifconfig.io/country_code
US
```

```
python -m slippers "socks5://username:password@my-socks-server.net:1080"
16:04:07 [INFO] Listening on localhost:1080 (4)
16:04:09 [INFO] Tunnel from 127.0.0.1:64633 (7) to my-socks-server.net:1080 (8) established
16:04:10 [INFO] Tunnel from 127.0.0.1:64633 (7) to my-socks-server.net:1080 (8) closed
```


## Programmatic Usage


```python
import os
import slippers
from playwright.sync_api import sync_playwright

username = os.getenv("SOCKS_USERNAME")
password = os.getenv("SOCKS_PASSWORD")


def main():
    with (
        sync_playwright() as p,
        slippers.Proxy(
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
```

## API

**`class slippers.Proxy(proxy: str, host: str = "localhost", port: int = 1080)`**

Create a handler for a local, unauthenticated SOCKS5 server which forwards traffic to an upstream authenticated SOCKS5 proxy.

&nbsp;&nbsp;**`start() -> None`**

&nbsp;&nbsp;Start the local proxy in a background process. Once started it can start accepting connections.

&nbsp;&nbsp;**`stop() -> None`**

&nbsp;&nbsp;Stop the background proxy process (if running).

&nbsp;&nbsp;**`__enter__() -> str`**

&nbsp;&nbsp;Start the proxy and return the local SOCSK5 uri.

&nbsp;&nbsp;**`__exit__(exc_type, exc_value, traceback) -> None`**

&nbsp;&nbsp;Stop the proxy when exiting the `with` block.
