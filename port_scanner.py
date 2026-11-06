import sys
import socket
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style, init

init(autoreset=True)

# พอร์ตยอดนิยมและชื่อบริการพื้นฐาน
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-Proxy"
}

def parse_target(target: str) -> str:
    if "://" in target:
        target = urlparse(target).netloc
    return target.split(":")[0].strip()

def grab_banner(sock: socket.socket) -> str:
    try:
        sock.settimeout(2.0)
        # ส่ง probe สำหรับ HTTP/Generic services
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        first_line = banner.split("\r\n")[0] if banner else ""
        return first_line[:40]
    except Exception:
        return "No banner returned"

def scan_port(ip: str, port: int):
    service_name = COMMON_PORTS.get(port, "Unknown")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.5)
            result = s.connect_ex((ip, port))
            if result == 0:
                banner = grab_banner(s)
                return (port, service_name, "OPEN", banner)
    except socket.error:
        pass
    return None

def main():
    if len(sys.argv) < 2:
        print("Usage: python port_scanner.py <target-domain-or-ip>")
        sys.exit(1)

    raw_target = sys.argv[1]
    target_host = parse_target(raw_target)

    try:
        target_ip = socket.gethostbyname(target_host)
    except socket.gaierror:
        print(f"{Fore.RED}[!] Could not resolve hostname: {target_host}")
        sys.exit(1)

    print(f"\n{Fore.CYAN}=== Port & Banner Scanner ==={Style.RESET_ALL}")
    print(f"Target: {Style.BRIGHT}{target_host}{Style.RESET_ALL} ({target_ip})")
    print(f"Scanning common administrative and application ports...\n")

    print(f"{'Port':<8} | {'Service':<12} | {'State':<8} | {'Banner / Header'}")
    print("-" * 65)

    open_ports = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(scan_port, target_ip, port) for port in COMMON_PORTS.keys()]
        for future in futures:
            res = future.result()
            if res:
                open_ports.append(res)
                port, service, state, banner = res
                print(f"{Fore.YELLOW}{port:<8}{Style.RESET_ALL} | {service:<12} | {Fore.GREEN}{state:<8}{Style.RESET_ALL} | {banner}")

    print("-" * 65)
    print(f"Total Open Ports Detected: {Fore.GREEN}{len(open_ports)}{Style.RESET_ALL}\n")

if __name__ == "__main__":
    main()