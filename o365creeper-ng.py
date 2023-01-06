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
import re
import time
import random
import asyncio
import aiohttp
from pathlib import Path
from aiohttp_socks  import ProxyConnector
from stem import Signal
from stem.control import Controller
from typing import Dict

parser = argparse.ArgumentParser(
        description=('Enumerates valid email addresses from ' +
            'Office 365 without submitting login attempts.')
        )
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument(
        '-e',
        '--email',
        help='Single email address to validate.',
        )
group.add_argument(
        '-f',
        '--file',
        type=Path,
        help='List of email addresses to validate, one per line.',
        )
parser.add_argument(
    '-u',
    '--baseurl',
    type=str,
    help='Base URL (default: %(default)s).',
    default='https://login.microsoftonline.com'
)
parser.add_argument(
        '-o',
        '--output',
        type=Path,
        help='Output valid email addresses to the specified file.',
        )
parser.add_argument(
        '--output-fail',
        type=Path,
        help='Output failed validations to the specified file.',
        )
parser.add_argument(
        '--tor',
        action='store_true',
        help='Use tor for requests.',
        )
parser.add_argument(
        '-p',
        '--tor-port',
        dest='socks_port',
        default=9050,
        type=int,
        help='Tor socks port to use (default: %(default)s).',
        )
parser.add_argument(
        '-c',
        '--tor-control-port',
        dest='control_port',
        default=9051,
        type=int,
        help='Tor control port to use (default: %(default)s).',
        )
parser.add_argument(
        '--tor-control-pw',
        dest='control_pw',
        default=None,
        type=str,
        help='Password for Tor control port (default: %(default)s).',
        )
parser.add_argument(
        '--timeout',
        default=30,
        type=int,
        metavar='TIME',
        help=('Stop waiting for a response after %(metavar)s ' +
            'seconds (default: %(default)s).'),
        )
parser.add_argument(
        '--retry',
        default=3,
        type=int,
        metavar='N',
        help=('Retry up to %(metavar)s times in case of error ' +
            '(default: %(default)s).'),
        )
parser.add_argument(
        "-t",
        "--max-connections",
        dest="maxconn",
        type=int,
        default=20,
        help="Maximum number of simultaneous connections (default: %(default)s)"
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

def get_list_from_file(file_):
    """Create a list from the contents of a file.

    Args:
        file_ (str): Input file name

    Returns:
        List[str]: Content of input file splitted by lines
    """
    with open(file_, "r") as f:
        list_ = [line.strip() for line in f]
    return list_


args = parser.parse_args()


semaphore = asyncio.Semaphore(args.maxconn)
headers = {
    "Connection": "close"
}
# include custom headers
if args.headers:
    for header in args.headers:
        h, v = header.split(":", 1)
        headers[h.strip()] = v.strip()

usernames = [args.email] if args.email else get_list_from_file(args.file)

config = {
    'tor': {
        'use': args.tor,
        'socks_port': args.socks_port,
        'control_port': args.control_port,
        'control_pw': args.control_pw,
    },
    'files': {
        'input': args.file,
        'output': args.output,
        'output_fail': args.output_fail,
    },
    'email': args.email,
    'timeout': args.timeout,
    'retry': args.retry,
    'sleep': args.sleep,
    'headers': headers,
    'url': args.baseurl.strip('/') + '/common/GetCredentialType',
}

uas = [
    "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko",
    "Mozilla/5.0 (compatible, MSIE 11, Windows NT 6.3; Trident/7.0;  rv:11.0) like Gecko",
    "Mozilla/5.0 (compatible; MSIE 10.6; Windows NT 6.1; Trident/5.0; InfoPath.2; SLCC1; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET CLR 2.0.50727) 3gpp-gba UNTRUSTED/1.0",
    "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 7.0; InfoPath.3; .NET CLR 3.1.40767; Trident/6.0; en-IN)",
    "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)",
    "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)",
    "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/5.0)",
    "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/4.0; InfoPath.2; SV1; .NET CLR 2.0.50727; WOW64)",
    "Mozilla/5.0 (compatible; MSIE 10.0; Macintosh; Intel Mac OS X 10_7_3; Trident/6.0)",
    "Mozilla/4.0 (Compatible; MSIE 8.0; Windows NT 5.2; Trident/6.0)",
    "Mozilla/4.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/5.0)",
    "Mozilla/1.22 (compatible; MSIE 10.0; Windows 3.1)",
    "Mozilla/5.0 (Windows; U; MSIE 9.0; WIndows NT 9.0; en-US))",
    "Mozilla/5.0 (Windows; U; MSIE 9.0; Windows NT 9.0; en-US)",
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 7.1; Trident/5.0)",
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; Media Center PC 6.0; InfoPath.3; MS-RTC LM 8; Zune 4.7)",
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; Media Center PC 6.0; InfoPath.3; MS-RTC LM 8; Zune 4.7",
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; Zune 4.0; InfoPath.3; MS-RTC LM 8; .NET4.0C; .NET4.0E)",
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; chromeframe/12.0.742.112)",
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET CLR 2.0.50727; Media Center PC 6.0)",
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET CLR 2.0.50727; Media Center PC 6.0)",
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0; .NET CLR 2.0.50727; SLCC2; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; Zune 4.0; Tablet PC 2.0; InfoPath.3; .NET4.0C; .NET4.0E)",
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0",
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; yie8)",
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; InfoPath.2; .NET CLR 1.1.4322; .NET4.0C; Tablet PC 2.0)",
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; FunWebProducts)",
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; chromeframe/13.0.782.215)",
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; chromeframe/11.0.696.57)",
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0) chromeframe/10.0.648.205",
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.1; SV1; .NET CLR 2.8.52393; WOW64; en-US)",
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/5.0; chromeframe/11.0.696.57)",
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/4.0; GTB7.4; InfoPath.3; SV1; .NET CLR 3.1.76908; WOW64; en-US)",
    "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.2; SV1; .NET CLR 3.3.69573; WOW64; en-US)",
    "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET CLR 1.0.3705; .NET CLR 1.1.4322)",
    "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; InfoPath.1; SV1; .NET CLR 3.8.36217; WOW64; en-US)",
    "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; .NET CLR 2.7.58687; SLCC2; Media Center PC 5.0; Zune 3.4; Tablet PC 3.6; InfoPath.3)",
    "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.2; Trident/4.0; Media Center PC 4.0; SLCC1; .NET CLR 3.0.04320)",
    "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SLCC1; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET CLR 1.1.4322)",
    "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; InfoPath.2; SLCC1; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET CLR 2.0.50727)",
    "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727)",
    "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; SLCC1; .NET CLR 1.1.4322)",
    "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.0; Trident/4.0; InfoPath.1; SV1; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET CLR 3.0.04506.30)",
    "Mozilla/5.0 (compatible; MSIE 7.0; Windows NT 5.0; Trident/4.0; FBSMTWB; .NET CLR 2.0.34861; .NET CLR 3.0.3746.3218; .NET CLR 3.5.33652; msn OptimizedIE8;ENUS)",
    "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.2; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)",
    "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; Media Center PC 6.0; InfoPath.2; MS-RTC LM 8)",
    "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; Media Center PC 6.0; InfoPath.2; MS-RTC LM 8",
    "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; Media Center PC 6.0; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET4.0C)",
    "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.3; .NET4.0C; .NET4.0E; .NET CLR 3.5.30729; .NET CLR 3.0.30729; MS-RTC LM 8)",
    "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)",
    "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; Zune 3.0)",
    "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; msn OptimizedIE8;ZHCN)",
    "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; MS-RTC LM 8; InfoPath.3; .NET4.0C; .NET4.0E) chromeframe/8.0.552.224",
    "Mozilla/4.0(compatible; MSIE 7.0b; Windows NT 6.0)",
    "Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 6.0)",
    "Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 5.2; .NET CLR 1.1.4322; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 3.0.04506.30)",
    "Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 5.1; Media Center PC 3.0; .NET CLR 1.0.3705; .NET CLR 1.1.4322; .NET CLR 2.0.50727; InfoPath.1)",
    "Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 5.1; FDM; .NET CLR 1.1.4322)",
    "Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 5.1; .NET CLR 1.1.4322; InfoPath.1; .NET CLR 2.0.50727)",
    "Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 5.1; .NET CLR 1.1.4322; InfoPath.1)",
    "Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 5.1; .NET CLR 1.1.4322; Alexa Toolbar; .NET CLR 2.0.50727)",
    "Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 5.1; .NET CLR 1.1.4322; Alexa Toolbar)",
    "Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727)",
    "Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.40607)",
    "Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 5.1; .NET CLR 1.1.4322)",
    "Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 5.1; .NET CLR 1.0.3705; Media Center PC 3.1; Alexa Toolbar; .NET CLR 1.1.4322; .NET CLR 2.0.50727)",
    "Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)",
    "Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; el-GR)",
    "Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 5.2)",
    "Mozilla/5.0 (MSIE 7.0; Macintosh; U; SunOS; X11; gu; SV1; InfoPath.2; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648)",
    "Mozilla/5.0 (compatible; MSIE 7.0; Windows NT 6.0; WOW64; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; c .NET CLR 3.0.04506; .NET CLR 3.5.30707; InfoPath.1; el-GR)",
    "Mozilla/5.0 (compatible; MSIE 7.0; Windows NT 6.0; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; c .NET CLR 3.0.04506; .NET CLR 3.5.30707; InfoPath.1; el-GR)",
    "Mozilla/5.0 (compatible; MSIE 7.0; Windows NT 6.0; fr-FR)",
    "Mozilla/5.0 (compatible; MSIE 7.0; Windows NT 6.0; en-US)",
    "Mozilla/5.0 (compatible; MSIE 7.0; Windows NT 5.2; WOW64; .NET CLR 2.0.50727)",
    "Mozilla/5.0 (compatible; MSIE 7.0; Windows 98; SpamBlockerUtility 6.3.91; SpamBlockerUtility 6.2.91; .NET CLR 4.1.89;GB)",
    "Mozilla/4.79 [en] (compatible; MSIE 7.0; Windows NT 5.0; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 1.1.4322; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648)",
    "Mozilla/4.0 (Windows; MSIE 7.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727)",
    "Mozilla/4.0 (Mozilla/4.0; MSIE 7.0; Windows NT 5.1; FDM; SV1; .NET CLR 3.0.04506.30)",
    "Mozilla/4.0 (Mozilla/4.0; MSIE 7.0; Windows NT 5.1; FDM; SV1)",
    "Mozilla/4.0 (compatible;MSIE 7.0;Windows NT 6.0)",
    "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.2; Win64; x64; Trident/6.0; .NET4.0E; .NET4.0C)",
    "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; SLCC2; .NET CLR 2.0.50727; InfoPath.3; .NET4.0C; .NET4.0E; .NET CLR 3.5.30729; .NET CLR 3.0.30729; MS-RTC LM 8)",
    "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; MS-RTC LM 8; .NET4.0C; .NET4.0E; InfoPath.3)",
    "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/6.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET4.0C; .NET4.0E)",
    "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; chromeframe/12.0.742.100)",
    "Mozilla/4.0 (compatible; MSIE 6.1; Windows XP; .NET CLR 1.1.4322; .NET CLR 2.0.50727)",
    "Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)",
    "Mozilla/4.0 (compatible; MSIE 6.01; Windows NT 6.0)",
    "Mozilla/4.0 (compatible; MSIE 6.0b; Windows NT 5.1; DigExt)",
    "Mozilla/4.0 (compatible; MSIE 6.0b; Windows NT 5.1)",
    "Mozilla/4.0 (compatible; MSIE 6.0b; Windows NT 5.0; YComp 5.0.2.6)",
    "Mozilla/4.0 (compatible; MSIE 6.0b; Windows NT 5.0; YComp 5.0.0.0) (Compatible;  ;  ; Trident/4.0)",
    "Mozilla/4.0 (compatible; MSIE 6.0b; Windows NT 5.0; YComp 5.0.0.0)",
    "Mozilla/4.0 (compatible; MSIE 6.0b; Windows NT 5.0; .NET CLR 1.1.4322)",
    "Mozilla/4.0 (compatible; MSIE 6.0b; Windows NT 5.0)",
    "Mozilla/4.0 (compatible; MSIE 6.0b; Windows NT 4.0; .NET CLR 1.0.2914)",
    "Mozilla/4.0 (compatible; MSIE 6.0b; Windows NT 4.0)",
    "Mozilla/4.0 (compatible; MSIE 6.0b; Windows 98; YComp 5.0.0.0)",
    "Mozilla/4.0 (compatible; MSIE 6.0b; Windows 98; Win 9x 4.90)",
    "Mozilla/4.0 (compatible; MSIE 6.0b; Windows 98)",
    "Mozilla/4.0 (compatible; MSIE 6.0b; Windows NT 5.1)",
    "Mozilla/4.0 (compatible; MSIE 6.0b; Windows NT 5.0; .NET CLR 1.0.3705)",
    "Mozilla/4.0 (compatible; MSIE 6.0b; Windows NT 4.0)",
    "Mozilla/5.0 (Windows; U; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727)",
    "Mozilla/5.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727)",
    "Mozilla/5.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 1.1.4325)",
    "Mozilla/5.0 (compatible; MSIE 6.0; Windows NT 5.1)",
    "Mozilla/45.0 (compatible; MSIE 6.0; Windows NT 5.1)",
    "Mozilla/4.08 (compatible; MSIE 6.0; Windows NT 5.1)",
    "Mozilla/4.01 (compatible; MSIE 6.0; Windows NT 5.1)",
    "Mozilla/4.0 (X11; MSIE 6.0; i686; .NET CLR 1.1.4322; .NET CLR 2.0.50727; FDM)",
    "Mozilla/4.0 (Windows; MSIE 6.0; Windows NT 6.0)",
    "Mozilla/4.0 (Windows; MSIE 6.0; Windows NT 5.2)",
    "Mozilla/4.0 (Windows; MSIE 6.0; Windows NT 5.0)",
    "Mozilla/4.0 (Windows;  MSIE 6.0;  Windows NT 5.1;  SV1; .NET CLR 2.0.50727)",
    "Mozilla/4.0 (MSIE 6.0; Windows NT 5.1)",
    "Mozilla/4.0 (MSIE 6.0; Windows NT 5.0)",
    "Mozilla/4.0 (compatible;MSIE 6.0;Windows 98;Q312461)",
    "Mozilla/4.0 (Compatible; Windows NT 5.1; MSIE 6.0) (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727)",
    "Mozilla/4.0 (compatible; U; MSIE 6.0; Windows NT 5.1) (Compatible;  ;  ; Trident/4.0; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET CLR 1.0.3705; .NET CLR 1.1.4322)",
    "Mozilla/4.0 (compatible; U; MSIE 6.0; Windows NT 5.1)",
    "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1) ; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; InfoPath.3; Tablet PC 2.0)",
    "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; GTB6.5; QQDownload 534; Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1) ; SLCC2; .NET CLR 2.0.50727; Media Center PC 6.0; .NET CLR 3.5.30729; .NET CLR 3.0.30729)",
    "Mozilla/4.0 (compatible; MSIE 5.5b1; Mac_PowerPC)",
    "Mozilla/4.0 (compatible; MSIE 5.50; Windows NT; SiteKiosk 4.9; SiteCoach 1.0)",
    "Mozilla/4.0 (compatible; MSIE 5.50; Windows NT; SiteKiosk 4.8; SiteCoach 1.0)",
    "Mozilla/4.0 (compatible; MSIE 5.50; Windows NT; SiteKiosk 4.8)",
    "Mozilla/4.0 (compatible; MSIE 5.50; Windows 98; SiteKiosk 4.8)",
    "Mozilla/4.0 (compatible; MSIE 5.50; Windows 95; SiteKiosk 4.8)",
    "Mozilla/4.0 (compatible;MSIE 5.5; Windows 98)",
    "Mozilla/4.0 (compatible; MSIE 6.0; MSIE 5.5; Windows NT 5.1)",
    "Mozilla/4.0 (compatible; MSIE 5.5;)",
    "Mozilla/4.0 (Compatible; MSIE 5.5; Windows NT5.0; Q312461; SV1; .NET CLR 1.1.4322; InfoPath.2)",
    "Mozilla/4.0 (compatible; MSIE 5.5; Windows NT5)",
    "Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)",
    "Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 6.1; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E)",
    "Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 6.1; chromeframe/12.0.742.100; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C)",
    "Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 6.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30618)",
    "Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 5.5)",
    "Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 5.2; .NET CLR 1.1.4322; InfoPath.2; .NET CLR 2.0.50727; .NET CLR 3.0.04506.648; .NET CLR 3.5.21022; FDM)",
    "Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 5.2; .NET CLR 1.1.4322) (Compatible;  ;  ; Trident/4.0; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET CLR 1.0.3705; .NET CLR 1.1.4322)",
    "Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 5.2; .NET CLR 1.1.4322)",
    "Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)",
    "Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 5.1; SV1; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)",
    "Mozilla/4.0 (compatible; MSIE 5.23; Mac_PowerPC)",
    "Mozilla/4.0 (compatible; MSIE 5.22; Mac_PowerPC)",
    "Mozilla/4.0 (compatible; MSIE 5.21; Mac_PowerPC)",
    "Mozilla/4.0 (compatible; MSIE 5.2; Mac_PowerPC)",
    "Mozilla/4.0 (compatible; MSIE 5.2; Mac_PowerPC)",
    "Mozilla/4.0 (compatible; MSIE 5.17; Mac_PowerPC)",
    "Mozilla/4.0 (compatible; MSIE 5.17; Mac_PowerPC Mac OS; en)",
    "Mozilla/4.0 (compatible; MSIE 5.16; Mac_PowerPC)",
    "Mozilla/4.0 (compatible; MSIE 5.16; Mac_PowerPC)",
    "Mozilla/4.0 (compatible; MSIE 5.15; Mac_PowerPC)",
    "Mozilla/4.0 (compatible; MSIE 5.15; Mac_PowerPC)",
    "Mozilla/4.0 (compatible; MSIE 5.14; Mac_PowerPC)",
    "Mozilla/4.0 (compatible; MSIE 5.13; Mac_PowerPC)",
    "Mozilla/4.0 (compatible; MSIE 5.12; Mac_PowerPC)",
    "Mozilla/4.0 (compatible; MSIE 5.12; Mac_PowerPC)",
    "Mozilla/4.0 (compatible; MSIE 5.05; Windows NT 4.0)",
    "Mozilla/4.0 (compatible; MSIE 5.05; Windows NT 3.51)",
    "Mozilla/4.0 (compatible; MSIE 5.05; Windows 98; .NET CLR 1.1.4322)",
    "Mozilla/4.0 (compatible; MSIE 5.01; Windows NT; YComp 5.0.0.0)",
    "Mozilla/4.0 (compatible; MSIE 5.01; Windows NT; Hotbar 4.1.8.0)",
    "Mozilla/4.0 (compatible; MSIE 5.01; Windows NT; DigExt)",
    "Mozilla/4.0 (compatible; MSIE 5.01; Windows NT; .NET CLR 1.0.3705)",
    "Mozilla/4.0 (compatible; MSIE 5.01; Windows NT)",
    "Mozilla/4.0 (compatible; MSIE 5.01; Windows NT 5.0; YComp 5.0.2.6; MSIECrawler)",
    "Mozilla/4.0 (compatible; MSIE 5.01; Windows NT 5.0; YComp 5.0.2.6; Hotbar 4.2.8.0)",
    "Mozilla/4.0 (compatible; MSIE 5.01; Windows NT 5.0; YComp 5.0.2.6; Hotbar 3.0)",
    "Mozilla/4.0 (compatible; MSIE 5.01; Windows NT 5.0; YComp 5.0.2.6)",
    "Mozilla/4.0 (compatible; MSIE 5.01; Windows NT 5.0; YComp 5.0.2.4)",
    "Mozilla/4.0 (compatible; MSIE 5.01; Windows NT 5.0; YComp 5.0.0.0; Hotbar 4.1.8.0)",
    "Mozilla/4.0 (compatible; MSIE 5.01; Windows NT 5.0; YComp 5.0.0.0)",
    "Mozilla/4.0 (compatible; MSIE 5.01; Windows NT 5.0; Wanadoo 5.6)",
    "Mozilla/4.0 (compatible; MSIE 5.01; Windows NT 5.0; Wanadoo 5.3; Wanadoo 5.5)",
    "Mozilla/4.0 (compatible; MSIE 5.01; Windows NT 5.0; Wanadoo 5.1)",
    "Mozilla/4.0 (compatible; MSIE 5.01; Windows NT 5.0; SV1; .NET CLR 1.1.4322; .NET CLR 1.0.3705; .NET CLR 2.0.50727)",
    "Mozilla/4.0 (compatible; MSIE 5.01; Windows NT 5.0; SV1)",
    "Mozilla/4.0 (compatible; MSIE 5.01; Windows NT 5.0; Q312461; T312461)",
    "Mozilla/4.0 (compatible; MSIE 5.01; Windows NT 5.0; Q312461)",
    "Mozilla/4.0 (compatible; MSIE 5.01; Windows NT 5.0; MSIECrawler)",
    "Mozilla/4.0 (compatible; MSIE 5.0b1; Mac_PowerPC)",
    "Mozilla/4.0 (compatible; MSIE 5.00; Windows 98)",
    "Mozilla/4.0(compatible; MSIE 5.0; Windows 98; DigExt)",
    "Mozilla/4.0 (compatible; MSIE 5.0; Windows NT;)",
    "Mozilla/4.0 (compatible; MSIE 5.0; Windows NT; DigExt; YComp 5.0.2.6)",
    "Mozilla/4.0 (compatible; MSIE 5.0; Windows NT; DigExt; YComp 5.0.2.5)",
    "Mozilla/4.0 (compatible; MSIE 5.0; Windows NT; DigExt; YComp 5.0.0.0)",
    "Mozilla/4.0 (compatible; MSIE 5.0; Windows NT; DigExt; Hotbar 4.1.8.0)",
    "Mozilla/4.0 (compatible; MSIE 5.0; Windows NT; DigExt; Hotbar 3.0)",
    "Mozilla/4.0 (compatible; MSIE 5.0; Windows NT; DigExt; .NET CLR 1.0.3705)",
    "Mozilla/4.0 (compatible; MSIE 5.0; Windows NT; DigExt)",
    "Mozilla/4.0 (compatible; MSIE 5.0; Windows NT)",
    "Mozilla/4.0 (compatible; MSIE 5.0; Windows NT 6.0; Trident/4.0; InfoPath.1; SV1; .NET CLR 3.0.04506.648; .NET4.0C; .NET4.0E)",
    "Mozilla/4.0 (compatible; MSIE 5.0; Windows NT 5.9; .NET CLR 1.1.4322)",
    "Mozilla/4.0 (compatible; MSIE 5.0; Windows NT 5.2; .NET CLR 1.1.4322)",
    "Mozilla/4.0 (compatible; MSIE 5.0; Windows NT 5.0)",
    "Mozilla/4.0 (compatible; MSIE 5.0; Windows 98;)",
    "Mozilla/4.0 (compatible; MSIE 5.0; Windows 98; YComp 5.0.2.4)",
    "Mozilla/4.0 (compatible; MSIE 5.0; Windows 98; Hotbar 3.0)",
    "Mozilla/4.0 (compatible; MSIE 5.0; Windows 98; DigExt; YComp 5.0.2.6; yplus 1.0)",
    "Mozilla/4.0 (compatible; MSIE 5.0; Windows 98; DigExt; YComp 5.0.2.6)",
    "Mozilla/4.0 (compatible; MSIE 4.5; Windows NT 5.1; .NET CLR 2.0.40607)",
    "Mozilla/4.0 (compatible; MSIE 4.5; Windows 98; )",
    "Mozilla/4.0 (compatible; MSIE 4.5; Mac_PowerPC)",
    "Mozilla/4.0 (compatible; MSIE 4.5; Mac_PowerPC)",
    "Mozilla/4.0 PPC (compatible; MSIE 4.01; Windows CE; PPC; 240x320; Sprint:PPC-6700; PPC; 240x320)",
    "Mozilla/4.0 (compatible; MSIE 4.01; Windows NT)",
    "Mozilla/4.0 (compatible; MSIE 4.01; Windows NT 5.0)",
    "Mozilla/4.0 (compatible; MSIE 4.01; Windows CE; Sprint;PPC-i830; PPC; 240x320)",
    "Mozilla/4.0 (compatible; MSIE 4.01; Windows CE; Sprint; SCH-i830; PPC; 240x320)",
    "Mozilla/4.0 (compatible; MSIE 4.01; Windows CE; Sprint:SPH-ip830w; PPC; 240x320)",
    "Mozilla/4.0 (compatible; MSIE 4.01; Windows CE; Sprint:SPH-ip320; Smartphone; 176x220)",
    "Mozilla/4.0 (compatible; MSIE 4.01; Windows CE; Sprint:SCH-i830; PPC; 240x320)",
    "Mozilla/4.0 (compatible; MSIE 4.01; Windows CE; Sprint:SCH-i320; Smartphone; 176x220)",
    "Mozilla/4.0 (compatible; MSIE 4.01; Windows CE; Sprint:PPC-i830; PPC; 240x320)",
    "Mozilla/4.0 (compatible; MSIE 4.01; Windows CE; Smartphone; 176x220)",
    "Mozilla/4.0 (compatible; MSIE 4.01; Windows CE; PPC; 240x320; Sprint:PPC-6700; PPC; 240x320)",
    "Mozilla/4.0 (compatible; MSIE 4.01; Windows CE; PPC; 240x320; PPC)",
    "Mozilla/4.0 (compatible; MSIE 4.01; Windows CE; PPC)",
    "Mozilla/4.0 (compatible; MSIE 4.01; Windows CE)",
    "Mozilla/4.0 (compatible; MSIE 4.01; Windows 98; Hotbar 3.0)",
    "Mozilla/4.0 (compatible; MSIE 4.01; Windows 98; DigExt)",
    "Mozilla/4.0 (compatible; MSIE 4.01; Windows 98)",
    "Mozilla/4.0 (compatible; MSIE 4.01; Windows 95)",
    "Mozilla/4.0 (compatible; MSIE 4.01; Mac_PowerPC)",
    "Mozilla/4.0 WebTV/2.6 (compatible; MSIE 4.0)",
    "Mozilla/4.0 (compatible; MSIE 4.0; Windows NT)",
    "Mozilla/4.0 (compatible; MSIE 4.0; Windows 98 )",
    "Mozilla/4.0 (compatible; MSIE 4.0; Windows 95; .NET CLR 1.1.4322; .NET CLR 2.0.50727)",
    "Mozilla/4.0 (compatible; MSIE 4.0; Windows 95)",
    "Mozilla/4.0 (Compatible; MSIE 4.0)",
    "Mozilla/2.0 (compatible; MSIE 4.0; Windows 98)",
    "Mozilla/2.0 (compatible; MSIE 3.03; Windows 3.1)",
    "Mozilla/2.0 (compatible; MSIE 3.02; Windows 3.1)",
    "Mozilla/2.0 (compatible; MSIE 3.01; Windows 95)",
    "Mozilla/2.0 (compatible; MSIE 3.01; Windows 95)",
    "Mozilla/2.0 (compatible; MSIE 3.0B; Windows NT)",
    "Mozilla/3.0 (compatible; MSIE 3.0; Windows NT 5.0)",
    "Mozilla/2.0 (compatible; MSIE 3.0; Windows 95)",
    "Mozilla/2.0 (compatible; MSIE 3.0; Windows 3.1)",
    "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)",
    "Mozilla/1.22 (compatible; MSIE 2.0; Windows 95)",
    "Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)"
  ]


async def need_retry(status: dict) -> bool:
    return status['throttle'] or status['error']


async def check_email(
        session: aiohttp.ClientSession,
        config: Dict,
        email: str,
        headers: Dict,
        uid: int
        ) :
    """
        Check if a given email exists at O365
    """
    async with semaphore:
        if uid > 0 and args.sleep > 0:
            await asyncio.sleep(args.sleep)
        ret = {}
        headers['User-Agent'] = random.choice(uas)
        payload = {'Username': email}
        try:
            async with session.post(config['url'], headers=headers, json=payload) as resp:
                text = await resp.text()
                ret['valid'] = re.search('"IfExistsResult":0,', text) is not None
                ret['throttle'] = re.search('"ThrottleStatus":1,', text) is not None
                ret['error'] = False
                ret['exception'] = None
        except BaseException as e:
            ret['valid'] = False
            ret['throttle'] = False
            ret['error'] = True
            ret['exception'] = e
        finally:
            # is endpoint throttling requests or some error occured?
            if await need_retry(ret):
                new_check ={}
                n = config['retry']
                while (n > 0):
                    new_check = {}
                    # generate new circuit
                    if config['tor']['use']:
                        with Controller.from_port(
                                port = config['tor']['control_port']) as c:
                            c.authenticate(password=config['tor']['control_pw'])
                            # TODO: validates auth and try other methods
                            c.signal(Signal.NEWNYM)

                    try:
                        async with session.post(config['url'],  headers=headers, json=payload) as resp:
                            text = await resp.text()
                            new_check['valid'] = re.search('"IfExistsResult":0,', text) is not None
                            new_check['throttle'] = re.search('"ThrottleStatus":1,', text) is not None
                            new_check['error'] = False
                            new_check['exception'] = None
                    except BaseException as e:
                        new_check['valid'] = False
                        new_check['throttle'] = False
                        new_check['error'] = True
                        new_check['exception'] = e

                    if await need_retry(new_check):
                        n -= 1
                    else:
                        break

                # still throttling or error occurring :(
                if  await need_retry(new_check):
                    if new_check['throttle']:
                        print(f'{email} - THROTTLED')
                    else:
                        print(f'{email} - {new_check["exception"]}')
                    if config['files']['output_fail'] is not None:
                        with config['files']['output_fail'].open(mode='a') as fail_file:
                            fail_file.write(email+'\n')
                # didn't throttle this time (nor error)
                else:
                    # is valid email?
                    if new_check['valid']:
                        print(f'{email} - VALID')
                        if config['files']['output'] is not None:
                            with config['files']['output'].open(mode='a') as output_file:
                                output_file.write(email+'\n')
                    else:
                        print(f'{email} - INVALID')

            # response was not throttled
            else:
                # is valid email?
                if ret['valid']:
                    print(f'{email} - VALID')
                    if config['files']['output'] is not None:
                        with config['files']['output'].open(mode='a') as output_file:
                            output_file.write(email+'\n')
                else:
                    print(f'{email} - INVALID')

async def main():
    username_count = len(usernames)
    timeout = aiohttp.ClientTimeout(total=args.timeout)
    tor_config = config['tor']
    if tor_config['use']:
        connector = ProxyConnector.from_url('socks5://127.0.0.1:' + str(tor_config['socks_port']), limit=args.maxconn)
    else:
        connector = aiohttp.TCPConnector(limit=args.maxconn)
    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
        await asyncio.gather(*[asyncio.ensure_future(check_email(session, config, username, headers.copy(), uid)) for uid, username in enumerate(usernames)], return_exceptions=False)


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
