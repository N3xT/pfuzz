# pfuzz

<p align="center">
  <img src="https://github.com/user-attachments/assets/88b281e1-7950-4f64-bf31-5f1eae659e0e"/>
</p>

`pfuzz` is a Python-based tool designed to exploit vulnerabilities in web applications by fuzzing parameters. It supports multiple exploitation modules, including SQL Injection, Local File Inclusion (LFI), Server-Side Template Injection (SSTI), Command Injection, and more.

<br>

Developed by **Khaled Alsalmi**  
- LinkedIn: [linkedin.com/in/khaled-alsalmi](https://linkedin.com/in/khaled-alsalmi)  
- Twitter (X): [@0xKHD](https://twitter.com/0xKHD)
  
<br>

## Features

- **Automated Vulnerability Exploitation**:
  - SQL Injection
  - Local File Inclusion (LFI)
  - Server-Side Template Injection (SSTI)
  - Command Injection
  - Fuzzing for parameters and files
- **Customizable Parameters**:
  - Support for headers, cookies, and POST body data.
- **Threaded Execution**:
  - Multi-threading for faster fuzzing and exploitation.
- **Detailed Reporting**:
  - Outputs discovered vulnerabilities categorized by type.

<br>

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/N3xT/pfuzz.git
   cd pfuzz
   ```

2. Install the required Python libraries:
   ```bash
   pip install -r requirements.txt
   ```

<br>

## Usage

Run the script with the desired parameters:

```bash
python pfuzz.py [TARGET_URL] [OPTIONS]
```

### Arguments

- **`TARGET_URL`**: The target URL containing the `^FUZZ^` parameter for fuzzing.

### Options

| Option           | Description                                                                                           |
|-------------------|------------------------------------------------------------------------------------------------------|
| `-m, --modules`  | Specify exploitation modules to use. Default: `sqli, lfi, ssti, ci, fuzzer, params`                   |
| `-X, --method`   | HTTP request method (`GET` or `POST`). Default: `GET`                                                 |
| `-d, --data`     | Body data for POST requests (e.g., `file_name=^FUZZ^`)                                                |
| `-C, --cookies`  | Cookies for the request (e.g., `id=1; token=abcd`).                                                   |
| `-H, --headers`  | Custom headers (e.g., `Authorization: Bearer token, Content-Type: application/json`)                  |
| `-t, --traversal`| File path to check for LFI. Default: `/etc/passwd`                                                    |
| `-p, --pattern`  | Pattern to match in LFI response. Default: `root:`                                                    |
| `-v, --verbosity`| Increase output verbosity. Use multiple times for more detail (e.g., `-v or -vv`)                     |

### Examples

1. SQL Injection:
   ```bash
   python pfuzz.py http://127.0.0.1:5000/sqli?query=^FUZZ^ -m sqli
   ```
   ![image](https://github.com/user-attachments/assets/870b0fcb-b7b1-4617-9ad5-81ac92a770d2)

3. Local File Inclusion (LFI)
   ```bash
    python pfuzz.py http://127.0.0.1:5000/lfi?file=^FUZZ^ -m lfi -t "/etc/passwd" -p "root:"
   ```
   ![image](https://github.com/user-attachments/assets/6704922e-047d-40f9-a9cf-d4cfb4f6d1fb)
   
5. Server-Side Template Injection (SSTI)
   ```bash
   # GET
   python pfuzz.py http://127.0.0.1:5000/ssti?name=^FUZZ^ -m ssti -vv

   # POST
   python pfuzz.py -X POST http://127.0.0.1:5000/ssti -m ssti -d "name=^FUZZ^&email=admin@gmail.com" -vv

   # POST JSON
   python pfuzz.py -X POST http://127.0.0.1:5000/ssti -m ssti -d "{'name': '^FUZZ^', 'email': 'admin@gmail.com'}" -vv
   ```
   ![image](https://github.com/user-attachments/assets/a81cd863-2811-4d77-bfef-6c45d60cec0c)

6. Command Injection
   ```bash
   python pfuzz.py http://127.0.0.1:5000/command_injection?cmd=^FUZZ^ -m ci
   ```
   ![image](https://github.com/user-attachments/assets/475b59fd-1500-45c0-b173-b44e946f9e32)

7. Files Fuzzer
   ```bash
   python pfuzz.py http://127.0.0.1:5000/^FUZZ^ -m fuzzer
   ```
   ![image](https://github.com/user-attachments/assets/c11b9388-99b2-472f-b50c-b9eca5a2d405)


8. Parameters Fuzzer
   ```bash
   # Fuzz GET Parameters
   python pfuzz.py http://127.0.0.1:5000/command_injection?^FUZZ^ -m params

   # Fuzz POST Parameters
   python pfuzz.py -X POST http://127.0.0.1:5000/ssti -d "^FUZZ^" -m params
   ```
   ![image](https://github.com/user-attachments/assets/955bd69c-879c-4b81-881d-eb607a0c5221)

<br>

## Contributions

Contributions are welcome! Please submit a pull request or open an issue for suggestions or bug reports.
