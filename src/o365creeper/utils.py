import logging
import colorama
from colorama import Fore, Style

colorama.init(autoreset=True)

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(message)s")

# internal color constants
_RED = Fore.RED
_GREEN = Fore.GREEN
_YELLOW = Fore.YELLOW
_CYAN = Fore.CYAN
_RESET = Style.RESET_ALL

__all__ = [
    "print_error",
    "print_success",
    "print_warning",
    "print_info",
    "print_debug",
    "get_list_from_file",
]


def _print_message(level: int, prefix: str, color: str, message: str):
    logger.log(level, f"{color}{prefix} {message}{_RESET}")


def print_error(message: str):
    _print_message(logging.ERROR, "[×]", _RED, message)


def print_success(message: str):
    _print_message(logging.INFO, "[+]", _GREEN, message)


def print_warning(message: str):
    _print_message(logging.WARNING, "[!]", _YELLOW, message)


def print_info(message: str):
    _print_message(logging.INFO, "[*]", _CYAN, message)


def print_debug(message: str):
    _print_message(logging.DEBUG, "[$]", "", message)


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
