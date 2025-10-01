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
    uid: int,
    semaphore: asyncio.Semaphore,
    sleep: int = 0,
):
    """
    Check if a given email exists at O365
    """
    async with semaphore:
        if uid > 0 and sleep > 0:
            await asyncio.sleep(sleep)
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
        finally:
            # is endpoint throttling requests or some error occured?
            if await need_retry(ret):
                new_check = {}
                n = config["retry"]
                while n > 0:
                    new_check = {}

                    try:
                        async with session.post(
                            config["url"], headers=headers, json=payload
                        ) as resp:
                            text = await resp.text()
                            new_check["valid"] = (
                                re.search('"IfExistsResult":0,', text) is not None
                            )
                            new_check["throttle"] = (
                                re.search('"ThrottleStatus":1,', text) is not None
                            )
                            new_check["error"] = False
                            new_check["exception"] = None
                    except BaseException as e:
                        new_check["valid"] = False
                        new_check["throttle"] = False
                        new_check["error"] = True
                        new_check["exception"] = e

                    if await need_retry(new_check):
                        n -= 1
                    else:
                        break

                # still throttling or error occurring :(
                if await need_retry(new_check):
                    if new_check["throttle"]:
                        print_warning(f"{email} - THROTTLED")
                    else:
                        print_error(f'{email} - {new_check["exception"]}')
                    if config["files"]["output_fail"] is not None:
                        with config["files"]["output_fail"].open(mode="a") as fail_file:
                            fail_file.write(email + "\n")
                # didn't throttle this time (nor error)
                else:
                    # is valid email?
                    if new_check["valid"]:
                        print_success(f"{email} - VALID")
                        if config["files"]["output"] is not None:
                            with config["files"]["output"].open(
                                mode="a"
                            ) as output_file:
                                output_file.write(email + "\n")
                    else:
                        print_info(f"{email} - INVALID")

            # response was not throttled
            else:
                # is valid email?
                if ret["valid"]:
                    print_success(f"{email} - VALID")
                    if config["files"]["output"] is not None:
                        with config["files"]["output"].open(mode="a") as output_file:
                            output_file.write(email + "\n")
                else:
                    print_info(f"{email} - INVALID")
