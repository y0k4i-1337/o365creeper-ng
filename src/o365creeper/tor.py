import aiohttp
from o365creeper.utils import print_error, print_success
from aiohttp_socks import ProxyConnector, ProxyType


async def test_tor(socks_port: int):
    # test Tor socks port
    test_url = "https://check.torproject.org"
    timeout = aiohttp.ClientTimeout(total=10)
    connector = ProxyConnector("127.0.0.1", socks_port, rdns=True)
    async with aiohttp.request(
        method="GET", url=test_url, connector=connector, timeout=timeout
    ) as resp:
        text = await resp.text()
        await connector.close()

        if "Sorry. You are not using Tor." in text:
            print_error("Tor is not working correctly.")
        elif "Congratulations. This browser is configured to use Tor." in text:
            print_success("Tor is working correctly.")
        else:
            raise Exception("Unexpected response from Tor check page: " + text)


async def test_circuits(socks_port: int, count: int):
    test_url = "https://api.ipify.org"
    # get max number of digits in count
    digits = len(str(count))
    for i in range(count):
        connector = ProxyConnector(
            host="127.0.0.1",
            port=socks_port,
            proxy_type=ProxyType.SOCKS5,
            rdns=True,
            username=f"tor{i}",
            password="password",
        )
        async with aiohttp.request(
            method="GET", url=test_url, connector=connector
        ) as resp:
            text = await resp.text()
            if resp.status != 200:
                print_error(f"Tor circuit {i+1:>{digits}} failed with status {resp.status}")
            else:
                print_success(f"Tor circuit {i+1:>{digits}}: {text.strip()}")
        await connector.close()


async def create_tor_sessions(socks_port: int, count: int, timeout: int):
    sessions = []
    for i in range(count):
        connector = ProxyConnector(
            host="127.0.0.1",
            port=socks_port,
            proxy_type=ProxyType.SOCKS5,
            rdns=True,
            username=f"tor{i}",
            password="password",
        )
        client_timeout = aiohttp.ClientTimeout(total=timeout)
        sessions.append(
            aiohttp.ClientSession(connector=connector, timeout=client_timeout)
        )
    return sessions
