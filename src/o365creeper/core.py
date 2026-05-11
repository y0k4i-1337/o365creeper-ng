import asyncio
import random
import re
from typing import Dict

import aiohttp
from aiohttp_socks import ProxyConnector

from o365creeper.utils import (
    print_debug,
    print_error,
    print_info,
    print_success,
    print_warning,
)
from o365creeper.constants import UAS


async def verify_domain(
    domain: str,
    baseurl: str = "https://login.microsoftonline.com",
    tor_config=None,
    **kwargs,
) -> bool:
    if tor_config and tor_config["use"]:
        connector = ProxyConnector(
            host="127.0.0.1", port=tor_config["socks_port"], rdns=True
        )
        kwargs["connector"] = connector
    async with aiohttp.ClientSession(**kwargs) as session:
        params = {"login": f"user@{domain}", "xml": 1}
        url = baseurl + "/getuserrealm.srf"
        async with session.get(url, params=params) as resp:
            xml = await resp.text()
            return re.search("<NameSpaceType>Managed</NameSpaceType>", xml) is not None


async def need_retry(status: dict) -> bool:
    return status["throttle"] or status["error"]


async def check_email(
    session: aiohttp.ClientSession,
    config: Dict,
    email: str,
    headers: Dict,
):
    """
    Check if a given email exists at O365
    """
    ret = {}
    headers["User-Agent"] = random.choice(UAS)
    payload = {"Username": email}
    try:
        async with session.post(
            config["url"], headers=headers, json=payload
        ) as resp:
            text = await resp.text()
            ret["valid"] = re.search('"IfExistsResult":0,', text) is not None
            ret["throttle"] = re.search('"ThrottleStatus":1,', text) is not None
            ret["error"] = False
            ret["exception"] = None
    except BaseException as e:
        ret["valid"] = False
        ret["throttle"] = False
        ret["error"] = True
        ret["exception"] = e

    return ret
