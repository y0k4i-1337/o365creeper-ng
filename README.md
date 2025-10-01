<a href="https://codeclimate.com/github/y0k4i-1337/o365creeper-ng/maintainability"><img src="https://api.codeclimate.com/v1/badges/f7a81aaa184ee1d019d1/maintainability" /></a>

# o365creeper-ng

Stealthy O365 user validation

## Description

This is a simple Python script used to validate email accounts that belong to Office 365 tenants.
This script takes either a single email address or a list of email addresses as input,
sends a request to Office 365 without a password, and looks for the the "IfExistsResult"
parameter to be set to 0 for a valid account. Invalid accounts will return a 1.

After repeated attempts to validate email addresses, Office 365 will flag these requests randomly,
leading to false positives. This program will therefore search for the "ThrottleStatus" parameter
in order to decide if the response can be considered as valid or not. When the parameter is set to
1, this means that the server throttled our request. In this case, and if we are using Tor, the
program will try to regenerate the tor circuit and retry the last request. This generally
allows us to get reliable results.

Furthermore, this program will also make requests with random user agents in order to be even more
stealth.


## Dependencies

The [original project](https://github.com/LMGsec/o365creeper) was completely refactored and runs
now with `python 3.9` (it probably works with later versions but that hasn't been tested yet).

This project uses [Poetry](https://python-poetry.org/) for dependency management, so you can just
run:
```
poetry install
```

## Fireprox

    Note: AWS has proibited the use of API Gateway as a rotating proxy, so this
    method may not work anymore. Also, this could be against your AWS terms of
    service, so use it at your own risk.

You may this tool in conjunction with [fireprox](https://github.com/ustayready/fireprox).
For that, you have to create a new API gateway pointing to
`https://login.microsoftonline.com`. Once you have received an URL like
`https://eid939cks.execute-api.us-east-1.amazonaws.com/fireprox`, you can pass
it in the `-u` option.

## Tor

You can also use this tool with Tor. For that, you need to have Tor installed and
running on your machine. You can then use the `--tor` option to route requests
through Tor.

In order to bypass throttling, the script can generate `N` number of different
circuits through
[IsolateSocksAuth](https://spec.torproject.org/proposals/351-socks-auth-extensions.html)
feature. For that, you need to set this sub-option in your `torrc` file
(usually located at `/etc/tor/torrc` on Linux or `/opt/homebrew/etc/tor/torrc` on MacOS):

```
SOCKSPort 9050 IsolateSOCKSAuth
```

## Usage

The script can take a domain with the `-d` option, which will make it verify if
the given domain is managed by MSOnline. You are advised to do so before
attempt to enumerate.


To enumerate users, the script can take a single email address with the `-e` parameter or a list of email
addresses,
one per line, with the `-f` parameter.
Additionally, the script can output valid email addresses to a file with the `-o` parameter and
output throttled ones to a different file with the `--output-fail` parameter, in case you wish
to retry them later.

```
usage: o365creeper [-h] (-e EMAIL | -f FILE | --tor-test | -d DOMAIN) [-u BASEURL] [-o OUTPUT]
                   [--output-fail OUTPUT_FAIL] [--tor] [-p SOCKS_PORT] [--tor-pool TOR_POOL] [--timeout TIME]
                   [--retry N] [-t MAXCONN] [-s SLEEP] [-H HEADERS]

Enumerates valid email addresses from Office 365 without submitting login attempts.

options:
  -h, --help            show this help message and exit
  -e, --email EMAIL     Single email address to validate.
  -f, --file FILE       List of email addresses to validate, one per line.
  --tor-test            Test Tor connectivity and exit.
  -d, --domain DOMAIN   Check if DOMAIN is managed by MicrosoftOnline and exit.
  -u, --baseurl BASEURL
                        Base URL (default: https://login.microsoftonline.com).
  -o, --output OUTPUT   Output valid email addresses to the specified file.
  --output-fail OUTPUT_FAIL
                        Output failed validations to the specified file.
  --tor                 Use tor for requests.
  -p, --tor-port SOCKS_PORT
                        Tor socks port to use (default: 9050).
  --tor-pool TOR_POOL   Number of Tor circuits to create (default: 10).
  --timeout TIME        Stop waiting for a response after TIME seconds (default: 30).
  --retry N             Retry up to N times in case of error (default: 3).
  -t, --max-connections MAXCONN
                        Maximum number of simultaneous connections (default: 20)
  -s, --sleep SLEEP     Sleep this many seconds between tries (default: 0).
  -H, --header HEADERS  Extra header to include in the request (can be used multiple times).
```

### Examples:

```
poetry run o365creeper -d example.com
poetry run o365creeper -e test@example.com
poetry run o365creeper -f emails.txt
poetry run o365creeper -f emails.txt -o validemails.txt
poetry run o365creeper -f emails.txt -o validemails.txt -u https://eid939cks.execute-api.us-east-1.amazonaws.com/fireprox -t 100 -H 'X-My-X-Forwarded-For: 127.0.0.1'
poetry run o365creeper -f emails.txt -o validemails.txt --output-fail retry.txt --tor
poetry run o365creeper --tor-test
```

## NOTE
This tool is offered with no warranty and is to be used at your own risk and discretion.
