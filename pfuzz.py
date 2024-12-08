import requests
import argparse
import threading
import random
from utils import parse_cookies, extract_base_url, print_message, check_url, parse_headers, parse_form_data, colors

global vulns

payload_files = {
    "sqli": ["SQL Injection vulnerabilities", "payloads/sqli.txt"],
    "lfi": ["LFI vulnerabilities", "payloads/traversal.txt"],
    "ssti": ["SSTI vulnerabilities", "payloads/ssti.txt"],
    "ci": ["Command Injection vulnerabilities", "payloads/command-injection.txt"],
    "fuzzer": ["fuzzed files", "payloads/fuzzer.txt"],
    "params": ["fuzzed parameters", "payloads/parameters.txt"]
}
    
def generate_payloads(target):
    payloads = []
    
    for vuln_name, file_name in payload_files.items():
        if vuln_name in modules:          
            with open(file_name[1], "r", encoding="utf8") as file:
                for payload in file:
                    payload = payload.strip()
                    if vuln_name == "ssti":
                        payload = payload.replace("^PAYLOAD_KEY^", random_key)

                    if vuln_name == "lfi":
                        payload = payload.replace("^PAYLOAD_KEY^", traversal)

                    if vuln_name == "params":
                        new_payload = target.replace("^FUZZ^", f"{payload}={random_key}")
                    else:
                        new_payload = target.replace("^FUZZ^", payload)

                    payloads.append([vuln_name, new_payload])

    return payloads

def make_request(vuln_name, payload, base_response_size, target=False):
    try:
        if method == "POST":
            if data:
                if data.startswith("{") and data.endswith("}"):
                    json_headers = headers if headers != {} else {'Content-Type': 'application/json'}
                    
                    if target:
                        response = requests.post(target, json=eval(payload), cookies=parsed_cookies, headers=json_headers)
                    else:
                        response = requests.post(payload, json=eval(data), cookies=parsed_cookies, headers=json_headers)
                else:
                    if target:
                        response = requests.post(target, data=parse_form_data(payload), cookies=parsed_cookies, headers=headers)
                    else:
                        response = requests.post(payload, data=parse_form_data(data), cookies=parsed_cookies, headers=headers)
            else:
                response = requests.post(payload, cookies=parsed_cookies, headers=headers)
        else:
            response = requests.get(payload, cookies=parsed_cookies, headers=headers)

        try:
            content = response.content.decode("utf-8").lower()
        except UnicodeDecodeError:
            content = response.content.decode("latin-1").lower()

        if content:
            response_size = len(response.content)
            status_code = response.status_code
            check_vulnerability(vuln_name, payload, content, status_code, base_response_size, response_size)
    except requests.ConnectionError:
        if verbosity > 1:
            print_message(f"Connection error! {payload}", "error")
    except Exception as e:
        pass

def check_vulnerability(vuln_name, *args):
    handlers = {
        "sqli": handle_sqli,
        "lfi": handle_lfi,
        "ssti": handle_ssti,
        "ci": handle_ci,
        "fuzzer": handle_fuzzer,
        "params": handle_parameters
    }
    if vuln_name in handlers:
        handlers[vuln_name](*args)

def handle_sqli(url, content, status_code, base_response_size, response_size):
    if "error in your sql syntax" in content or status_code == 500:
        prefix = "Possible" if not "error in your sql syntax" in content else ""
        if verbosity > 0 or len(vulns["sqli"]) == 0:
            print_message(url, "result", f"{prefix} SQLi")
        vulns["sqli"].append(url)
    else:
        if verbosity > 1:
            print_message(url, "no_result", "SQLi")

def handle_lfi(url, content, status_code, base_response_size, response_size):
    if pattern in content:
        if verbosity > 0 or len(vulns["lfi"]) == 0:
            print_message(url, "result", "LFI")
        vulns["lfi"].append(url)
    else:
        if verbosity > 1:
            print_message(url, "no_result", "LFI")

def handle_ssti(url, content, status_code, base_response_size, response_size):
    if str(int(random_key) * 2) in content:
        if verbosity > 0 or len(vulns["ssti"]) == 0:
            print_message(url, "result", "SSTI")
        vulns["ssti"].append(url)
    else:
        if verbosity > 1:
            print_message(url, "no_result", "SSTI")

def handle_ci(url, content, status_code, base_response_size, response_size):
    if "uid=" in content or "gid=" in content:
        if verbosity > 0 or len(vulns["ci"]) == 0:
            print_message(url, "result", "Command Injection")
        vulns["ci"].append(url)
    else:
        if verbosity > 1:
            print_message(url, "no_result", "Command Injection")

def handle_fuzzer(url, content, status_code, base_response_size, response_size):
    if status_code == 200:
        print_message(url, "result", "FUZZER")
        vulns["fuzzer"].append(url)
    else:
        if verbosity > 1:
            print_message(url, "no_result", "FUZZER")

def handle_parameters(url, content, status_code, base_response_size, response_size):
    if status_code == 200 and base_response_size != response_size:
        print_message(url, "result", "PARAMS")
        vulns["params"].append(url)
    else:
        if verbosity > 1:
            print_message(url, "no_result", "PARAMS")

def main():
    base_url = extract_base_url(target)
    valid_url = check_url(base_url)

    if valid_url:
        if "^FUZZ^" in target:
            payloads = generate_payloads(target)
        elif data and "^FUZZ^" in data:
            payloads = generate_payloads(data)
        else:
            print_message(f"No fuzzing parameter were found!", "error")
            return
    
        base_response_size = False
        if "params" in modules:
            base_content = check_url(target.replace("^FUZZ^", ""), method)
            if base_content:
                base_response_size = len(base_content.content)
        print_message(f"Exploitation modules: {', '.join(modules.keys())}", "message")
        print_message(f"Starting exploitation...", "message")
    
        threads = []
        for vuln_name, payload in payloads:
            if "^FUZZ^" in target: # Fuzz URL
                thread = threading.Thread(target=make_request, args=(vuln_name, payload, base_response_size, False))
            elif "^FUZZ^" in data: # Fuzz POST body
                thread = threading.Thread(target=make_request, args=(vuln_name, payload, base_response_size, target))

            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        display_results()
    else:
        print_message(f"Invalid URL, please try again!", "error")

def print_banner():
    print(f"""{colors.OKBLUE} 
                 ___                   
                / __)                  
         ____ _| |__ _   _ _____ _____ 
        |  _ (_   __) | | (___  |___  )
        | |_| || |  | |_| |/ __/ / __/ 
        |  __/ |_|  |____/(_____|_____|
        |_|                            
            
        Author:         {colors.ENDC}Khaled Alsalmi{colors.OKBLUE}
        LinkedIn:       {colors.ENDC}linkedin.com/in/khaled-alsalmi{colors.OKBLUE}
        X:              {colors.ENDC}@0xKHD{colors.OKBLUE}
        Version:        {colors.ENDC}1.0{colors.OKBLUE}

        """)

def display_results():
    print()
    for vuln_name, print_name in payload_files.items():
        if vuln_name in modules:  
            print_message(f"Total of {print_name[0]}: {len(vulns[vuln_name])}", "info")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="pfuzz", description="A python script to exploit vulnerable web parameters")
    parser.add_argument("target", help='Example: "https://vuln.com?search=^FUZZ^"')
    parser.add_argument("-m", "--modules", default="sqli, lfi, ssti, ci, fuzzer, params", help="Exploitation modules, separated by commas. (Modules: sqli, lfi, ssti, ci, fuzzer, params. Default: all)")
    parser.add_argument("-X", "--method", default="GET", choices=["GET", "POST"], help="HTTP request method (Choose from GET, POST. Default: GET)")
    parser.add_argument("-d", "--data", help='Body data for POST request (Ex: "file_name=^FUZZ^")')
    parser.add_argument("-C", "--cookies", help='Cookies for the request (Ex: "id=1; token=abcd")')
    parser.add_argument("-H", "--headers", help='Custom headers for the request (Ex: "Authorization: Bearer token, Content-Type: application/json")')
    parser.add_argument("-t", "--traversal", default="/etc/passwd", help="File name to check for LFI (Default: /etc/passwd)")
    parser.add_argument("-p", "--pattern", default="root:", help='Pattern to match in LFI response (Default: "root:")')
    parser.add_argument("-v", "--verbosity", action="count", default=0, help="Set verbosity level")
    args = parser.parse_args()

    target = args.target if args.target.startswith("http") else f"http://{args.target}"
    modules = {item.strip().lower().strip(): True for item in args.modules.split(",")}
    method = args.method.upper()
    parsed_cookies = parse_cookies(str(args.cookies))
    data = args.data
    headers = parse_headers(args.headers) if args.headers else {}
    traversal = args.traversal
    pattern = args.pattern
    verbosity = args.verbosity

    random_key = str(random.randint(1e15, 1e16))
    vulns = {key: [] for key in payload_files}
    
    print_banner()
    
    for module in modules:
        if module not in vulns:
            print_message(f"Unrecognized module '{module}'. Choose from the following: {', '.join(vulns.keys())}", "error")
            exit()

    print_message(f"Target: {target}", "message")
    main()