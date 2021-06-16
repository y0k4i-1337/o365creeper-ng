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

import requests as req
import argparse
import re
import time
from fake_useragent import UserAgent
from pathlib import Path
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
        '-t',
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
        '-s',
        '--tor-control-pw',
        dest='control_pw',
        default=None,
        type=str,
        help='Password for Tor control port (default: %(default)s).',
        )

args = parser.parse_args()

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
    'email': args.email
}

url = 'https://login.microsoftonline.com/common/GetCredentialType'


def check_email(
        url: str,
        email: str,
        tor_config: Dict,
        ) -> Dict:
    """
        Check if a given email exists at O365
    """
    ret = {}
    proxies = None
    if tor_config['use']:
        proxy = f'socks5://127.0.0.1:{tor_config["socks_port"]}'
        proxies = {
                'http': proxy,
                'https': proxy,
                }
    headers = {'User-Agent': UserAgent().random}
    payload = {'Username': email}
    r = req.post(url, proxies=proxies, headers=headers, json=payload)

    ret['valid'] = re.search('"IfExistsResult":0,', r.text) is not None
    ret['throttle'] = re.search('"ThrottleStatus":1,', r.text) is not None

    return ret


def validate_result(
        check_res: Dict,
        email: str,
        config: Dict,
        url: str,
        ) -> None:
    """
        Validate results and redo if necessary
    """
    # is endpoint throttling requests?
    if throttle := check_res['throttle']:
        # if using tor, try new circuit(s)
        if config['tor']['use']:
            retry = 3
            while (retry > 0):
                with Controller.from_port(
                        port = config['tor']['control_port']) as c:
                    c.authenticate(password=config['tor']['control_pw'])
                    # TODO: validates auth and try other methods
                    c.signal(Signal.NEWNYM)
                new_check = check_email(url, email, config['tor'])
                if new_check['throttle']:
                    retry -= 1
                else:
                    break
            # still throttling :(
            if new_check['throttle']:
                print(f'{email} - THROTTLED')
                if config['files']['output_fail'] is not None:
                    with config['files']['output_fail'].open(mode='a') as fail_file:
                        fail_file.write(email+'\n')
            # didn't throttle this time
            else:
                # is valid email?
                if new_check['valid']:
                    print(f'{email} - VALID')
                    if config['files']['output'] is not None:
                        with config['files']['output'].open(mode='a') as output_file:
                            output_file.write(email+'\n')
                else:
                    print(f'{email} - INVALID')

        # not using tor
        # TODO: try other bypass methods
        else:
            print(f'{email} - THROTTLED')
            if config['files']['output_fail'] is not None:
                with config['files']['output_fail'].open(mode='a') as fail_file:
                    fail_file.write(email+'\n')

    # response was not throttled
    else:
        # is valid email?
        if check_res['valid']:
            print(f'{email} - VALID')
            if config['files']['output'] is not None:
                with config['files']['output'].open(mode='a') as output_file:
                    output_file.write(email+'\n')
        else:
            print(f'{email} - INVALID')

        

def main():

    if config['files']['input'] is not None:
        with config['files']['input'].open() as file:
            for line in file:
                email = line.strip()
                checked = check_email(url, email, config['tor'])
                validate_result(checked, email, config, url)

    elif config.email is not None:
        email = config.email
        checked = check_email(url, email, config['tor'])
        validate_result(checked, email, config, url)


if __name__ == "__main__":
    main()
