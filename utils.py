import requests
import validators
from http.cookies import SimpleCookie
from urllib.parse import urlparse

class colors:
    OKBLUE = "\033[94m"
    OKGREEN = "\033[92m"
    RED = "\033[91m"
    ENDC = "\033[0m"

def print_message(message, type="info", prefix="+"):
    message_types = {
        "info": f"{colors.RED}[*]{colors.ENDC} {message}",
        "result": f"{colors.OKGREEN}[{prefix}]{colors.ENDC} {message}",
        "no_result": f"{colors.RED}[{prefix}]{colors.ENDC} {message}",
        "error": f"{colors.RED}[!]{colors.ENDC} {message}",
        "message": f"{colors.OKBLUE}[*]{colors.ENDC} {message}"
    }
    print(message_types.get(type, message_types["info"]))

def parse_cookies(raw):
    cookie = SimpleCookie()
    cookie.load(raw)
    return {key: morsel.value for key, morsel in cookie.items()}

def extract_base_url(url):
    parsed_url = urlparse(url)
    return f"{parsed_url.scheme}://{parsed_url.netloc}"

def check_url(url, method="HEAD"):
    if not validators.url(url):
        return False

    methods = {"POST": requests.post, "GET": requests.get, "HEAD": requests.head}
    try:
        return methods[method](url, timeout=5)
    except Exception:
        return False

def parse_headers(headers):
    headers_dict = {}
    if headers:
        try:
            for header in headers.split(","):
                key, value = header.split(":", 1)
                headers_dict[key.strip()] = value.strip()
        except ValueError:
            print_message("Invalid headers format. Use 'Header: Value' pairs separated by commas.", "error")
    return headers_dict

def parse_form_data(data):
    return {key: value for key, value in (pair.split("=") for pair in data.split("&"))}
