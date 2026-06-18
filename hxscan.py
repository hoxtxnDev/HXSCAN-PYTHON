"""
Concurrent TCP port scanner for cybersecurity auditing.
Stdlib-only, thread-safe, production-grade CLI tool.
"""

from __future__ import annotations

import argparse
import socket
import sys
import threading
from dataclasses import dataclass, field
from queue import Queue
from typing import List, Optional, Sequence

# ---------------------------------------------------------------------------
# Well-known port → service name mapping (subset)
# ---------------------------------------------------------------------------
_SERVICE_MAP: dict[int, str] = {
    20: "FTP-data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP-server",
    68: "DHCP-client",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    123: "NTP",
    135: "MS-RPC",
    137: "NetBIOS-ns",
    138: "NetBIOS-dgm",
    139: "NetBIOS-ssn",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP-trap",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    500: "IKE",
    514: "Syslog",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS",
    1194: "OpenVPN",
    1433: "MSSQL",
    1521: "Oracle-DB",
    2049: "NFS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    5901: "VNC-1",
    6379: "Redis",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
    9090: "HTTP-alt2",
    27017: "MongoDB",
}


@dataclass
class ScanResult:
    """Represents the result of a single port scan."""

    port: int
    state: str  # "open" | "closed" | "error"
    service: str = field(default="unknown")

    def __post_init__(self) -> None:
        if self.state == "open" and self.service == "unknown":
            self.service = _SERVICE_MAP.get(self.port, "unknown")


def _resolve_target(target: str) -> str:
    """Resolve a hostname to an IP address.

    Args:
        target: Hostname or IP string.

    Returns:
        Resolved IPv4 address.

    Raises:
        socket.gaierror: If resolution fails.
    """
    return socket.gethostbyname(target)


def _parse_port_spec(spec: str) -> List[int]:
    """Parse a port specification into a sorted list of unique ports.

    Supports comma-separated values and dash-delimited ranges:
        "22,80,8000-8100"

    Args:
        spec: Port specification string.

    Returns:
        Deduplicated, sorted list of port integers.
    """
    ports: set[int] = set()

    for token in spec.split(","):
        token = token.strip()
        if not token:
            continue
        if "-" in token:
            parts = token.split("-", 1)
            try:
                start, end = int(parts[0]), int(parts[1])
            except ValueError:
                raise ValueError(f"Invalid port range: {token}")
            if start < 1 or end > 65535 or start > end:
                raise ValueError(f"Invalid port range: {token}")
            ports.update(range(start, end + 1))
        else:
            p = int(token)
            if not (1 <= p <= 65535):
                raise ValueError(f"Port out of range (1-65535): {p}")
            ports.add(p)

    return sorted(ports)


def _get_service_name(port: int) -> str:
    """Return the well-known service name for *port*, or ``"unknown"``."""
    return _SERVICE_MAP.get(port, "unknown")


class PortScanner:
    """Thread-safe TCP port scanner using a producer-consumer model.

    All state is encapsulated per instance; no global mutable state is used.
    """

    def __init__(
        self,
        target: str,
        ports: List[int],
        *,
        threads: int = 10,
        timeout: float = 1.0,
        verbose: bool = False,
    ) -> None:
        """Initialise the scanner.

        Args:
            target: IP or hostname to scan.
            ports: List of port numbers to probe.
            threads: Maximum concurrent worker threads.
            timeout: Socket connection timeout in seconds.
            verbose: Enable verbose logging to stderr.
        """
        self.target: str = _resolve_target(target)
        self.ports: List[int] = ports
        self.threads: int = min(threads, len(ports))
        self.timeout: float = timeout
        self.verbose: bool = verbose
        self._results: List[ScanResult] = []
        self._lock: threading.Lock = threading.Lock()
        self._queue: Queue[int] = Queue()

    def _log(self, message: str) -> None:
        """Write *message* to stderr if verbose mode is on."""
        if self.verbose:
            sys.stderr.write(f"[*] {message}\n")
            sys.stderr.flush()

    def _scan_port(self, port: int) -> ScanResult:
        """Probe a single TCP port and return a ``ScanResult``.

        Uses a context manager to guarantee socket cleanup.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                code = sock.connect_ex((self.target, port))
                if code == 0:
                    return ScanResult(port=port, state="open", service=_get_service_name(port))
                return ScanResult(port=port, state="closed")
        except (socket.timeout, OSError) as exc:
            return ScanResult(port=port, state="error", service=str(exc))

    def _worker(self) -> None:
        """Consume ports from the shared queue and record results.

        Intended to run as a daemon thread target.
        """
        while True:
            try:
                port = self._queue.get_nowait()
            except Exception:
                break
            result = self._scan_port(port)
            with self._lock:
                self._results.append(result)
            self._queue.task_done()

    def scan(self) -> List[ScanResult]:
        """Execute the scan across all ports using a thread pool.

        Returns:
            Sorted list of ``ScanResult`` objects (by port number).
        """
        self._results.clear()

        for port in self.ports:
            self._queue.put(port)

        self._log(f"Scanning {len(self.ports)} ports on {self.target} "
                  f"({self.threads} threads, timeout={self.timeout}s)")

        workers: list[threading.Thread] = []
        for _ in range(self.threads):
            t = threading.Thread(target=self._worker, daemon=True)
            t.start()
            workers.append(t)

        self._queue.join()

        self._results.sort(key=lambda r: r.port)
        return list(self._results)

    def report(self, results: List[ScanResult]) -> None:
        """Print a formatted scan summary to stdout.

        Args:
            results: Scan results to display.
        """
        open_ports = [r for r in results if r.state == "open"]

        print(f"\n{'='*50}")
        print(f"Scan Report — {self.target}")
        print(f"{'='*50}")

        if not open_ports:
            print("No open ports found.")
        else:
            print(f"\n{'Port':<8} {'State':<10} {'Service'}")
            print("-" * 35)
            for r in results:
                if r.state == "open":
                    print(f"{r.port:<8} {r.state:<10} {r.service}")
            for r in results:
                if r.state != "open":
                    print(f"{r.port:<8} {r.state:<10} {r.service}")

        print(f"\nScanned: {len(results)} port(s) | Open: {len(open_ports)}")
        print(f"{'='*50}\n")


def _build_parser() -> argparse.ArgumentParser:
    """Construct the argument parser."""
    parser = argparse.ArgumentParser(
        prog="hxscan",
        description="Concurrent TCP port scanner for cybersecurity auditing.",
        epilog="Exit codes: 0=open found, 1=error, 2=no open ports.",
    )
    parser.add_argument(
        "-t", "--target",
        required=True,
        help="Target IP address or hostname.",
    )
    parser.add_argument(
        "-p", "--ports",
        default="21,22,23,25,80,110,143,443,445,993,995,1433,1521,2049,"
                "3306,3389,5432,5900,6379,8080,8443,27017",
        help="Comma-separated ports or ranges (e.g. 22,80,8000-8100).",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=50,
        help="Maximum concurrent threads (default: 50).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Socket connection timeout in seconds (default: 1.0).",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose diagnostic output.",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """CLI entry point.

    Args:
        argv: Argument list (defaults to ``sys.argv[1:]``).

    Returns:
        Exit code: 0=open found, 1=error, 2=no open ports.
    """
    parser = _build_parser()

    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 1

    try:
        ports = _parse_port_spec(args.ports)
    except ValueError as exc:
        print(f"[!] Port specification error: {exc}", file=sys.stderr)
        return 1

    if not ports:
        print("[!] No valid ports to scan.", file=sys.stderr)
        return 1

    try:
        scanner = PortScanner(
            target=args.target,
            ports=ports,
            threads=args.threads,
            timeout=args.timeout,
            verbose=args.verbose,
        )
    except socket.gaierror as exc:
        print(f"[!] DNS resolution failed: {exc}", file=sys.stderr)
        return 1

    try:
        results = scanner.scan()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.", file=sys.stderr)
        return 130

    scanner.report(results)

    open_count = sum(1 for r in results if r.state == "open")
    if open_count > 0:
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
