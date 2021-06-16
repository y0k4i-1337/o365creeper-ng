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
program will try to regenerate the tor circuit and retry the previous request. This generally
allows us to get reliable results.

Furthermore, this program will also make requests with random user agents in order to be even more
stealth.


## Dependencies

The [original project](https://github.com/LMGsec/o365creeper) was completely refactored and runs
now with `python 3.8` (it probably works with later versions but that hasn't been tested yet).

This project uses [Poetry](https://python-poetry.org/) for dependency management, so you can just
run:
```
poetry install
```

Dependencies can also be installed with `pip`:
```
pip install -r requirements.txt
```

## Tor

It is recommended to run this tool with Tor support. For that, you will have to configure your
`torrc` to open a control port and set a password. Instructions can be found
[here](https://wiki.archlinux.org/title/Tor#Open_Tor_ControlPort) and
[here](https://wiki.archlinux.org/title/Tor#Set_a_Tor_Control_password).


## Usage
The script can take a single email address with the `-e` parameter or a list of email addresses,
one per line, with the `-f` parameter. 
Additionally, the script can output valid email addresses to a file with the `-o` parameter and
output throttled ones to a different file with the `--output-fail` parameter, in case you wish
to retry them later.

```
usage: o365creeper-ng.py [-h] (-e EMAIL | -f FILE) [-o OUTPUT] [--output-fail OUTPUT_FAIL] 
			[-t] [-p SOCKS_PORT] [-c CONTROL_PORT] [-s CONTROL_PW]

Enumerates valid email addresses from Office 365 without submitting login attempts.

optional arguments:
  -h, --help            show this help message and exit
  -e EMAIL, --email EMAIL
                        Single email address to validate.
  -f FILE, --file FILE  List of email addresses to validate, one per line.
  -o OUTPUT, --output OUTPUT
                        Output valid email addresses to the specified file.
  --output-fail OUTPUT_FAIL
                        Output failed validations to the specified file.
  -t, --tor             Use tor for requests.
  -p SOCKS_PORT, --tor-port SOCKS_PORT
                        Tor socks port to use (default: 9050).
  -c CONTROL_PORT, --tor-control-port CONTROL_PORT
                        Tor control port to use (default: 9051).
  -s CONTROL_PW, --tor-control-pw CONTROL_PW
                        Password for Tor control port (default: None).
```

### Examples:

```
o365creeper-ng.py -e test@example.com
o365creeper-ng.py -f emails.txt
o365creeper-ng.py -f emails.txt -o validemails.txt
o365creeper-ng.py -f emails.txt -o validemails.txt --output-fail retry.txt -t -s t0rpassw0rd
```

## NOTE
This tool is offered with no warranty and is to be used at your own risk and discretion.
