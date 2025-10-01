#!/usr/bin/env python3

# Fork from o365creeper created by Korey McKinley
# (https://github.com/LMGsec/o365creeper)

# This tool will query the Microsoft Office 365 web server to determine
# if an email account is valid or not. It does not need a password and
# should not show up in the logs of a client's O365 tenant.

# Note: Microsoft has implemented some throttling on this service, so
# quick, repeated attempts to validate the same username over and over
# may produce false positives. This tool is best ran after you've gathered
# as many email addresses as possible through OSINT in a list with the
# -f argument.

# In order to bypass the behaviour above, this program can use tor circuits
# which will be regenerated every time it detects throttling.

import argparse
import asyncio
import sys
from pathlib import Path

import aiohttp
from colorama import Fore

from o365creeper.core import check_email, verify_domain
from o365creeper.tor import test_tor, test_circuits
from o365creeper.utils import (
    get_list_from_file,
    print_error,
    print_info,
    print_success,
    print_warning,
)


async def main():
    parser = argparse.ArgumentParser(
        description=(
            "Enumerates valid email addresses from "
            + "Office 365 without submitting login attempts."
        )
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-e",
        "--email",
        help="Single email address to validate.",
    )
    group.add_argument(
        "-f",
        "--file",
        type=Path,
        help="List of email addresses to validate, one per line.",
    )
    group.add_argument(
        "--tor-test",
        action="store_true",
        help="Test Tor connectivity and exit.",
    )
    group.add_argument(
        "-d",
        "--domain",
        type=str,
        metavar="DOMAIN",
        help="Check if %(metavar)s is managed by MicrosoftOnline and exit.",
    )
    parser.add_argument(
        "-u",
        "--baseurl",
        type=str,
        help="Base URL (default: %(default)s).",
        default="https://login.microsoftonline.com",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Output valid email addresses to the specified file.",
    )
    parser.add_argument(
        "--output-fail",
        type=Path,
        help="Output failed validations to the specified file.",
    )
    parser.add_argument(
        "--tor",
        action="store_true",
        help="Use tor for requests.",
    )
    parser.add_argument(
        "-p",
        "--tor-port",
        dest="socks_port",
        default=9050,
        type=int,
        help="Tor socks port to use (default: %(default)s).",
    )
    parser.add_argument(
        "--tor-pool",
        dest="tor_pool",
        default=10,
        type=int,
        help="Number of Tor circuits to create (default: %(default)s).",
    )
    parser.add_argument(
        "--timeout",
        default=30,
        type=int,
        metavar="TIME",
        help=(
            "Stop waiting for a response after %(metavar)s "
            + "seconds (default: %(default)s)."
        ),
    )
    parser.add_argument(
        "--retry",
        default=3,
        type=int,
        metavar="N",
        help=(
            "Retry up to %(metavar)s times in case of error "
            + "(default: %(default)s)."
        ),
    )
    parser.add_argument(
        "-t",
        "--max-connections",
        dest="maxconn",
        type=int,
        default=20,
        help="Maximum number of simultaneous connections (default: %(default)s)",
    )
    parser.add_argument(
        "-s",
        "--sleep",
        default=0,
        type=int,
        help="Sleep this many seconds between tries (default: %(default)s).",
    )
    parser.add_argument(
        "-H",
        "--header",
        help="Extra header to include in the request (can be used multiple times).",
        action="append",
        dest="headers",
    )

    args = parser.parse_args()

    headers = {"Connection": "close"}
    # include custom headers
    if args.headers:
        for header in args.headers:
            h, v = header.split(":", 1)
            headers[h.strip()] = v.strip()

    if args.domain is None and not args.tor_test:
        usernames = [args.email] if args.email else get_list_from_file(args.file)

    config = {
        "tor": {
            "use": args.tor,
            "socks_port": args.socks_port,
            "pool_size": args.tor_pool,
            "test": args.tor_test,
        },
        "files": {
            "input": args.file,
            "output": args.output,
            "output_fail": args.output_fail,
        },
        "email": args.email,
        "timeout": args.timeout,
        "retry": args.retry,
        "sleep": args.sleep,
        "headers": headers,
        "baseurl": args.baseurl.strip("/"),
        "url": args.baseurl.strip("/") + "/common/GetCredentialType",
    }

    semaphore = asyncio.Semaphore(args.maxconn)
    timeout = aiohttp.ClientTimeout(total=args.timeout)
    connector = aiohttp.TCPConnector(limit=args.maxconn)
    tor_config = config["tor"]

    # test tor configuration and exit
    if tor_config["test"]:
        try:
            print_info("Testing Tor configuration...")
            await test_tor(tor_config["socks_port"])
            print_info("Testing Tor circuits...")
            await test_circuits(tor_config["socks_port"], tor_config["pool_size"])
            print_info("Tor configuration test completed.")
            sys.exit()
        except Exception as e:
            print_error(f"Error testing Tor: {e}")
            sys.exit(1)

    if tor_config["use"]:
        try:
            await test_tor(tor_config["socks_port"])
        except Exception as e:
            print_error(f"Error testing Tor: {e}")
            sys.exit(1)

    # only verify if domain is managed
    if args.domain:
        if await verify_domain(
            args.domain,
            config["baseurl"],
            tor_config=tor_config,
            timeout=timeout,
            connector=connector,
        ):
            print_success(
                f"Domain {args.domain} is MANAGED by MicrosoftOnline."
                + " You may use this tool to enumerate users."
            )
            sys.exit()
        else:
            print_error(
                f"Domain {args.domain} is NOT MANAGED by MicrosoftOnline."
                + " Using this tool may lead to unreliable results."
            )
            sys.exit()

    username_count = len(usernames)
    # verify if domain is managed before trying to enumerate
    if username_count > 0:
        domain = usernames[0].split(sep="@")[1]
        if not await verify_domain(
            domain, config["baseurl"], tor_config=tor_config, timeout=timeout
        ):
            while True:
                c = (
                    input(
                        f"{Fore.YELLOW} Domain {domain} is NOT MANAGED "
                        + "by MicrosoftOnline. Trying to enumerate may lead to"
                        + f" unexpected results.{Fore.RESET} "
                        + "Do you wish to continue? [y/N] "
                    )
                    or "N"
                )
                if c.upper() == "Y":
                    break
                elif c.upper() == "N":
                    sys.exit()

    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
        await asyncio.gather(
            *[
                asyncio.ensure_future(
                    check_email(
                        session, config, username, headers.copy(), uid, semaphore
                    )
                )
                for uid, username in enumerate(usernames)
            ],
            return_exceptions=False,
        )


def run():
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(main())
    except KeyboardInterrupt:
        pass
