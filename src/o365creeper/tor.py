import aiohttp
from o365creeper.utils import print_error, print_success
from aiohttp_socks import ProxyConnector, ProxyType


async def test_tor(socks_port: int):
    # test Tor socks port
    test_url = "http://check.torproject.org"
    connector = ProxyConnector("127.0.0.1", socks_port, rdns=True)
    async with aiohttp.request(method="GET", url=test_url, connector=connector) as resp:
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
    for i in range(count):
        connector = ProxyConnector(
            host="127.0.0.1",
            port=socks_port,
            proxy_type=ProxyType.SOCKS5,
            rdns=True,
            username=f"tor{i}",
            password="password",
        )
        async with aiohttp.request(method="GET", url=test_url, connector=connector) as resp:
            text = await resp.text()
            if resp.status != 200:
                print_error(f"Tor circuit {i+1} failed with status {resp.status}")
            else:
                print_success(f"Tor circuit {i+1}: {text.strip()}")
        await connector.close()
