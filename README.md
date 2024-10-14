# HTTPDos: Simulate HTTP Denial of Service Attacks

HTTPDos is a Python-based tool designed to simulate HTTP Denial of Service (DoS) attacks by sending multiple requests to a target host. It allows for multiple threads, random user agents, IP generation, and optional session cookies. The tool also handles SSL connections, redirects, and can generate random referers from a file.

## Features
- Supports both HTTP and HTTPS requests.
- Handles HTTP redirects and automatically adjusts the target URL.
- Option to specify the maximum number of concurrent threads.
- Random user agent generation.
- Generates random IPs for the X-Forwarded-For header.
- Optional session cookie support.
- Continuous attack execution until stopped.

## Requirements
- Python 3.x
- `requests`, `fake_useragent`, `ssl`, `socket`, and other built-in libraries.
- Install the `fake_useragent` library:

    ```bash
    pip install fake-useragent
    ```

## Usage

```bash
python HTTPDos.py -H <hostname> -P <port> [-p <path>] [-t <threads>] [-c <cookies>]
```

### Parameters
- `-H, --hostname`: **(Required)** The target host (e.g., `example.com`).
- `-P, --port`: **(Required)** The target port (e.g., `80` for HTTP or `443` for HTTPS).
- `-p, --path`: The specific path to attack (optional, defaults to a random parameter).
- `-t, --threads`: Maximum number of concurrent threads (optional, defaults to unlimited).
- `-c, --cookies`: Session cookie (optional).

### Example
```bash
python HTTPDos.py -H example.com -P 443 -p login -t 100 -c "sessionid=123456"
```

## How It Works
- The script generates a random user agent and IP for each request, mimicking real-world traffic.
- It continuously creates socket connections to the target host, sending crafted HTTP headers.
- If the target returns a redirect (301, 302), the tool automatically follows the new host and path.
- The attack stops if a 403 Forbidden response is encountered.

## Important Notes
- **Legal Disclaimer**: This tool is designed for educational purposes only and to test your own systems. **Do not use this tool to attack any systems without permission.**

## License
This project is licensed under the [MIT License](LICENSE).
