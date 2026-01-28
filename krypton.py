#!/usr/bin/env python3
"""
Krypton - General Purpose Utility Toolkit

A collection of safe, ethical command-line utilities for everyday tasks including
DNS lookups, QR code generation, password generation, file compression, and more.

MIT License

Copyright (c) 2023-2026 Zayan & Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

============================================================================
SECURITY NOTE: This version has been sanitized to remove functionality that
could be used for abuse or violate third-party Terms of Service. Removed items:
- Discord token manipulation (self-botting)
- Webhook spam/delete/info operations
- Mass DM functionality
- Automated server operations
- Friend removal automation
- Vanity URL checking
============================================================================
"""

# =============================================================================
# IMPORTS
# =============================================================================

from __future__ import annotations

import base64
import hashlib
import json
import os
import random
import shutil
import socket
import string
import sys
import time
from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path
from typing import Optional, Callable

# Third-party imports
try:
    import qrcode
    from qrcode.image.pil import PilImage
except ImportError:
    qrcode = None  # type: ignore

try:
    from pytube import YouTube
    from pytube.exceptions import PytubeError
except ImportError:
    YouTube = None  # type: ignore
    PytubeError = Exception

try:
    import dns.resolver
    from dns.resolver import Resolver, NXDOMAIN, NoAnswer
except ImportError:
    dns = None  # type: ignore

try:
    import pyfiglet
except ImportError:
    pyfiglet = None  # type: ignore

try:
    import requests
except ImportError:
    requests = None  # type: ignore

from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
from rich.panel import Panel
from rich.text import Text

# =============================================================================
# CONSTANTS
# =============================================================================

VERSION: str = "2.0.0"
APP_NAME: str = "Krypton"
AUTHOR: str = "Zayan & Contributors"
GITHUB_URL: str = "https://github.com/KiIlerDrift/Krypt0n"

# ASCII Art Banner
BANNER: str = """
[#3F88C5]██╗  ██╗██████╗[/#3F88C5]  ██╗   ██╗██████╗ ████████╗ ██████╗ ███╗   ██╗
[#3F88C5]██║ ██╔╝██╔══██╗[/#3F88C5] ╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔═████╗████╗  ██║
[#3F88C5]█████╔╝ ██████╔╝[/#3F88C5]  ╚████╔╝ ██████╔╝   ██║   ██║██╔██║██╔██╗ ██║
[#3F88C5]██╔═██╗ ██╔══██╗[/#3F88C5]   ╚██╔╝  ██╔═══╝    ██║   ████╔╝██║██║╚██╗██║
[#3F88C5]██║  ██╗██║  ██║[/#3F88C5]    ██║   ██║        ██║   ╚██████╔╝██║ ╚████║
[#3F88C5]╚═╝  ╚═╝╚═╝  ╚═╝[/#3F88C5]    ╚═╝   ╚═╝        ╚═╝    ╚═════╝ ╚═╝  ╚═══╝
"""

# Console instance (global for convenience)
console = Console()


# =============================================================================
# UTILITY CLASSES
# =============================================================================


class ConsoleUtils:
    """Helper utilities for console output and navigation."""

    @staticmethod
    def clear_screen() -> None:
        """Clear the terminal screen (cross-platform)."""
        os.system('cls' if os.name == 'nt' else 'clear')

    @staticmethod
    def get_divider() -> str:
        """Generate a divider line based on terminal width."""
        width = shutil.get_terminal_size().columns
        return "══" * (width // 2)

    @staticmethod
    def print_header() -> None:
        """Print the application header with banner and divider."""
        ConsoleUtils.clear_screen()
        console.print(BANNER, style="bold #EB5160", justify='center')
        console.print(f"\n[cyan]v{VERSION}[/cyan] | [red]{AUTHOR}[/red]\n", justify='center')
        console.print(ConsoleUtils.get_divider(), style='bold red', justify='center')
        print()

    @staticmethod
    def pause_and_return(seconds: int = 3) -> None:
        """Pause briefly and signal return to menu."""
        time.sleep(seconds)
        console.print('\n[red][bold][!][/bold] Returning to menu...[/red]', justify='center')
        time.sleep(1)


# =============================================================================
# DNS LOOKUP
# =============================================================================


@dataclass
class DNSResult:
    """Result container for DNS lookup."""
    method: str
    result: str
    success: bool


class DNSLookup:
    """
    Perform DNS lookups using multiple methods.
    
    Supports socket-based lookups and dnspython for comprehensive results.
    """

    def __init__(self, domain: str) -> None:
        """
        Initialize DNS lookup for a domain.
        
        Args:
            domain: The domain name to look up (e.g., "google.com")
        """
        self.domain = domain.strip().lower()

    def socket_lookup(self) -> DNSResult:
        """Perform basic DNS lookup using socket."""
        try:
            ip = socket.gethostbyname(self.domain)
            return DNSResult("socket", ip, True)
        except socket.gaierror as e:
            return DNSResult("socket", f"Could not resolve: {e}", False)

    def socket_getaddrinfo_lookup(self) -> DNSResult:
        """Perform DNS lookup using socket.getaddrinfo for more details."""
        try:
            addrs = socket.getaddrinfo(self.domain, None)
            ips = list({addr[4][0] for addr in addrs})
            return DNSResult("getaddrinfo", ", ".join(ips), True)
        except socket.gaierror as e:
            return DNSResult("getaddrinfo", f"Could not resolve: {e}", False)

    def dnspython_a_lookup(self) -> DNSResult:
        """Perform A record lookup using dnspython."""
        if dns is None:
            return DNSResult("dnspython (A)", "dnspython not installed", False)
        try:
            resolver = Resolver()
            answers = resolver.resolve(self.domain, "A")
            ips = [answer.address for answer in answers]
            return DNSResult("dnspython (A)", ", ".join(ips), True)
        except (NXDOMAIN, NoAnswer) as e:
            return DNSResult("dnspython (A)", f"Could not resolve: {e}", False)
        except Exception as e:
            return DNSResult("dnspython (A)", f"Error: {e}", False)

    def dnspython_mx_lookup(self) -> DNSResult:
        """Perform MX record lookup using dnspython."""
        if dns is None:
            return DNSResult("dnspython (MX)", "dnspython not installed", False)
        try:
            resolver = Resolver()
            answers = resolver.resolve(self.domain, "MX")
            records = [f"{answer.preference} {answer.exchange}" for answer in answers]
            return DNSResult("dnspython (MX)", ", ".join(records), True)
        except (NXDOMAIN, NoAnswer):
            return DNSResult("dnspython (MX)", "No MX records found", False)
        except Exception as e:
            return DNSResult("dnspython (MX)", f"Error: {e}", False)

    def display_results(self) -> None:
        """Display all DNS lookup results in a formatted table."""
        results = [
            self.socket_lookup(),
            self.socket_getaddrinfo_lookup(),
            self.dnspython_a_lookup(),
            self.dnspython_mx_lookup(),
        ]

        table = Table(title=f"DNS Lookup Results for [cyan]{self.domain}[/cyan]")
        table.add_column("Method", justify="center", style="cyan")
        table.add_column("Result", justify="left", style="green")
        table.add_column("Status", justify="center")

        for result in results:
            status = "[green]✓[/green]" if result.success else "[red]✗[/red]"
            result_style = "" if result.success else "dim"
            table.add_row(result.method, f"[{result_style}]{result.result}[/{result_style}]", status)

        console.print(table, justify='center')


# =============================================================================
# QR CODE GENERATOR
# =============================================================================


class QRCodeGenerator:
    """Generate QR codes from text or URLs."""

    @staticmethod
    def generate(
        data: str,
        fill_color: str = "black",
        back_color: str = "white",
        box_size: int = 10,
        border: int = 5
    ) -> Optional[Path]:
        """
        Generate a QR code image.
        
        Args:
            data: The text or URL to encode
            fill_color: Color of the QR code pattern
            back_color: Background color
            box_size: Size of each box in pixels
            border: Border size in boxes
            
        Returns:
            Path to the saved image, or None if failed
        """
        if qrcode is None:
            console.print("[red]Error: qrcode library not installed[/red]")
            return None

        try:
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=box_size,
                border=border
            )
            qr.add_data(data)
            qr.make(fit=True)
            
            img = qr.make_image(fill_color=fill_color, back_color=back_color)
            
            # Generate safe filename
            safe_name = "".join(c if c.isalnum() else "_" for c in data[:30])
            if not safe_name:
                safe_name = f"qr_{random.randint(1000, 9999)}"
            
            filename = Path(f"{safe_name}.png")
            img.save(filename)
            
            return filename
            
        except Exception as e:
            console.print(f"[red]Error generating QR code: {e}[/red]")
            return None

    @staticmethod
    def interactive_generate() -> None:
        """Interactive QR code generation with user prompts."""
        data = Prompt.ask("[bold cyan][>][/bold cyan] Enter text or URL for QR code")
        if not data.strip():
            console.print("[red]No data provided[/red]")
            return

        fill = Prompt.ask(
            "[bold cyan][>][/bold cyan] Fill color",
            default="black"
        )
        back = Prompt.ask(
            "[bold cyan][>][/bold cyan] Background color",
            default="white"
        )

        result = QRCodeGenerator.generate(data, fill_color=fill, back_color=back)
        if result:
            console.print(f"[green]✓ QR code saved as: {result}[/green]")


# =============================================================================
# NETWORK UTILITIES
# =============================================================================


class NetworkUtils:
    """Network-related utilities for pinging and port scanning."""

    @staticmethod
    def ping_host(host: str, port: int = 80, timeout: float = 2.0) -> bool:
        """
        Check if a host is reachable on a specific port.
        
        Args:
            host: Hostname or IP address
            port: Port number (default: 80)
            timeout: Connection timeout in seconds
            
        Returns:
            True if host is reachable, False otherwise
        """
        try:
            socket.setdefaulttimeout(timeout)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except socket.error:
            return False

    @staticmethod
    def check_port(host: str, port: int, timeout: float = 2.0) -> bool:
        """
        Check if a specific port is open on a host.
        
        Args:
            host: Hostname or IP address
            port: Port number to check
            timeout: Connection timeout in seconds
            
        Returns:
            True if port is open, False otherwise
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, int(port)))
            sock.close()
            return result == 0
        except (socket.error, ValueError):
            return False

    @staticmethod
    def scan_port_range(host: str, start_port: int, end_port: int) -> list[int]:
        """
        Scan a range of ports on a host.
        
        Args:
            host: Hostname or IP address
            start_port: Starting port number
            end_port: Ending port number
            
        Returns:
            List of open ports
        """
        open_ports = []
        for port in range(start_port, end_port + 1):
            if NetworkUtils.check_port(host, port, timeout=0.5):
                open_ports.append(port)
        return open_ports

    @staticmethod
    def interactive_ping() -> None:
        """Interactive host ping with user prompts."""
        host = Prompt.ask("[bold cyan][>][/bold cyan] Enter host to ping")
        if not host.strip():
            console.print("[red]No host provided[/red]")
            return

        console.print(f"[dim]Pinging {host}...[/dim]")
        if NetworkUtils.ping_host(host):
            console.print(f"[green]✓ {host} is UP![/green]")
        else:
            console.print(f"[red]✗ {host} is DOWN or unreachable[/red]")

    @staticmethod
    def interactive_port_check() -> None:
        """Interactive port check with user prompts."""
        host = Prompt.ask("[bold cyan][>][/bold cyan] Enter host")
        port_str = Prompt.ask("[bold cyan][>][/bold cyan] Enter port")

        try:
            port = int(port_str)
        except ValueError:
            console.print("[red]Invalid port number[/red]")
            return

        console.print(f"[dim]Checking {host}:{port}...[/dim]")
        if NetworkUtils.check_port(host, port):
            console.print(f"[green]✓ {host}:{port} is OPEN[/green]")
        else:
            console.print(f"[red]✗ {host}:{port} is CLOSED[/red]")


# =============================================================================
# PASSWORD GENERATOR
# =============================================================================


class PasswordStrength(Enum):
    """Password strength levels."""
    WEAK = auto()
    MEDIUM = auto()
    STRONG = auto()
    VERY_STRONG = auto()


class PasswordGenerator:
    """Secure password generation with customizable options."""

    # Character sets
    LOWERCASE = string.ascii_lowercase
    UPPERCASE = string.ascii_uppercase
    DIGITS = string.digits
    PUNCTUATION = string.punctuation
    AMBIGUOUS = "il1Lo0O"

    @staticmethod
    def generate(
        length: int = 16,
        include_uppercase: bool = True,
        include_digits: bool = True,
        include_symbols: bool = True,
        exclude_ambiguous: bool = False
    ) -> str:
        """
        Generate a secure random password.
        
        Args:
            length: Password length (minimum 4)
            include_uppercase: Include uppercase letters
            include_digits: Include numeric digits
            include_symbols: Include special characters
            exclude_ambiguous: Exclude visually similar characters (il1Lo0O)
            
        Returns:
            Generated password string
        """
        length = max(4, length)

        chars = PasswordGenerator.LOWERCASE
        if include_uppercase:
            chars += PasswordGenerator.UPPERCASE
        if include_digits:
            chars += PasswordGenerator.DIGITS
        if include_symbols:
            chars += PasswordGenerator.PUNCTUATION

        if exclude_ambiguous:
            for char in PasswordGenerator.AMBIGUOUS:
                chars = chars.replace(char, "")

        # Use secrets for cryptographic randomness if available
        try:
            import secrets
            password = "".join(secrets.choice(chars) for _ in range(length))
        except ImportError:
            password = "".join(random.choice(chars) for _ in range(length))

        return password

    @staticmethod
    def assess_strength(password: str) -> PasswordStrength:
        """
        Assess the strength of a password.
        
        Args:
            password: Password to assess
            
        Returns:
            PasswordStrength enum value
        """
        length = len(password)
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_symbol = any(c in string.punctuation for c in password)

        score = sum([has_lower, has_upper, has_digit, has_symbol])

        if length >= 16 and score >= 4:
            return PasswordStrength.VERY_STRONG
        elif length >= 12 and score >= 3:
            return PasswordStrength.STRONG
        elif length >= 8 and score >= 2:
            return PasswordStrength.MEDIUM
        else:
            return PasswordStrength.WEAK

    @staticmethod
    def interactive_generate() -> None:
        """Interactive password generation with user prompts."""
        length_str = Prompt.ask(
            "[bold cyan][>][/bold cyan] Password length",
            default="16"
        )

        try:
            length = int(length_str)
        except ValueError:
            console.print("[red]Invalid length, using 16[/red]")
            length = 16

        password = PasswordGenerator.generate(length=length)
        strength = PasswordGenerator.assess_strength(password)

        strength_colors = {
            PasswordStrength.WEAK: "red",
            PasswordStrength.MEDIUM: "yellow",
            PasswordStrength.STRONG: "green",
            PasswordStrength.VERY_STRONG: "bold green"
        }

        console.print(f"\n[bold]Generated Password:[/bold] [cyan]{password}[/cyan]")
        console.print(
            f"[bold]Strength:[/bold] [{strength_colors[strength]}]{strength.name}[/{strength_colors[strength]}]"
        )


# =============================================================================
# TEXT UTILITIES
# =============================================================================


class TextUtils:
    """Text manipulation and formatting utilities."""

    @staticmethod
    def to_ascii_art(text: str, font: str = "slant") -> str:
        """
        Convert text to ASCII art using pyfiglet.
        
        Args:
            text: Text to convert
            font: Font name (default: slant)
            
        Returns:
            ASCII art string
        """
        if pyfiglet is None:
            # Fallback: simple character expansion
            return "\n".join(f"  {char}  " for char in text.upper())
        
        try:
            return pyfiglet.figlet_format(text, font=font)
        except Exception:
            return pyfiglet.figlet_format(text)

    @staticmethod
    def reverse(text: str) -> str:
        """Reverse a string."""
        return text[::-1]

    @staticmethod
    def to_uppercase(text: str) -> str:
        """Convert to uppercase."""
        return text.upper()

    @staticmethod
    def to_lowercase(text: str) -> str:
        """Convert to lowercase."""
        return text.lower()

    @staticmethod
    def to_title_case(text: str) -> str:
        """Convert to title case."""
        return text.title()

    @staticmethod
    def to_slug(text: str) -> str:
        """Convert text to URL-friendly slug."""
        slug = text.lower().strip()
        slug = "".join(c if c.isalnum() or c == " " else "" for c in slug)
        slug = "-".join(slug.split())
        return slug

    @staticmethod
    def word_count(text: str) -> dict[str, int]:
        """
        Count words and characters in text.
        
        Returns:
            Dictionary with counts
        """
        words = text.split()
        return {
            "characters": len(text),
            "characters_no_spaces": len(text.replace(" ", "")),
            "words": len(words),
            "lines": text.count("\n") + 1
        }

    @staticmethod
    def interactive_ascii_art() -> None:
        """Interactive ASCII art generation."""
        text = Prompt.ask("[bold cyan][>][/bold cyan] Enter text for ASCII art")
        if not text.strip():
            console.print("[red]No text provided[/red]")
            return

        art = TextUtils.to_ascii_art(text)
        console.print(Panel(art, title="ASCII Art", border_style="cyan"))

    @staticmethod
    def interactive_reverse() -> None:
        """Interactive text reversal."""
        text = Prompt.ask("[bold cyan][>][/bold cyan] Enter text to reverse")
        console.print(f"\n[bold]Reversed:[/bold] [cyan]{TextUtils.reverse(text)}[/cyan]")


# =============================================================================
# HASH GENERATOR
# =============================================================================


class HashGenerator:
    """Generate cryptographic hashes from text or files."""

    ALGORITHMS = ["md5", "sha1", "sha256", "sha512"]

    @staticmethod
    def hash_text(text: str, algorithm: str = "sha256") -> str:
        """
        Generate hash of text.
        
        Args:
            text: Text to hash
            algorithm: Hash algorithm (md5, sha1, sha256, sha512)
            
        Returns:
            Hexadecimal hash string
        """
        algorithm = algorithm.lower()
        if algorithm not in HashGenerator.ALGORITHMS:
            algorithm = "sha256"

        hasher = hashlib.new(algorithm)
        hasher.update(text.encode("utf-8"))
        return hasher.hexdigest()

    @staticmethod
    def hash_file(filepath: Path, algorithm: str = "sha256") -> Optional[str]:
        """
        Generate hash of a file.
        
        Args:
            filepath: Path to file
            algorithm: Hash algorithm
            
        Returns:
            Hexadecimal hash string, or None if error
        """
        algorithm = algorithm.lower()
        if algorithm not in HashGenerator.ALGORITHMS:
            algorithm = "sha256"

        try:
            hasher = hashlib.new(algorithm)
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as e:
            console.print(f"[red]Error hashing file: {e}[/red]")
            return None

    @staticmethod
    def interactive_hash() -> None:
        """Interactive hash generation."""
        text = Prompt.ask("[bold cyan][>][/bold cyan] Enter text to hash")
        if not text.strip():
            console.print("[red]No text provided[/red]")
            return

        table = Table(title="Hash Results")
        table.add_column("Algorithm", style="cyan")
        table.add_column("Hash", style="green")

        for algo in HashGenerator.ALGORITHMS:
            hash_val = HashGenerator.hash_text(text, algo)
            table.add_row(algo.upper(), hash_val)

        console.print(table)


# =============================================================================
# BASE64 ENCODER/DECODER
# =============================================================================


class Base64Utils:
    """Base64 encoding and decoding utilities."""

    @staticmethod
    def encode(text: str) -> str:
        """Encode text to Base64."""
        return base64.b64encode(text.encode("utf-8")).decode("utf-8")

    @staticmethod
    def decode(encoded: str) -> Optional[str]:
        """
        Decode Base64 to text.
        
        Returns:
            Decoded string, or None if invalid
        """
        try:
            return base64.b64decode(encoded.encode("utf-8")).decode("utf-8")
        except Exception:
            return None

    @staticmethod
    def interactive() -> None:
        """Interactive Base64 encoding/decoding."""
        choice = Prompt.ask(
            "[bold cyan][>][/bold cyan] [E]ncode or [D]ecode?",
            choices=["e", "d", "E", "D"],
            default="e"
        )

        text = Prompt.ask("[bold cyan][>][/bold cyan] Enter text")
        if not text:
            console.print("[red]No text provided[/red]")
            return

        if choice.lower() == "e":
            result = Base64Utils.encode(text)
            console.print(f"\n[bold]Encoded:[/bold] [cyan]{result}[/cyan]")
        else:
            result = Base64Utils.decode(text)
            if result:
                console.print(f"\n[bold]Decoded:[/bold] [cyan]{result}[/cyan]")
            else:
                console.print("[red]Invalid Base64 string[/red]")


# =============================================================================
# JSON VALIDATOR
# =============================================================================


class JSONValidator:
    """JSON validation and formatting utilities."""

    @staticmethod
    def validate(json_string: str) -> tuple[bool, Optional[dict], Optional[str]]:
        """
        Validate and parse JSON string.
        
        Returns:
            Tuple of (is_valid, parsed_data, error_message)
        """
        try:
            data = json.loads(json_string)
            return True, data, None
        except json.JSONDecodeError as e:
            return False, None, str(e)

    @staticmethod
    def prettify(json_string: str, indent: int = 2) -> Optional[str]:
        """
        Format JSON string with indentation.
        
        Returns:
            Formatted JSON string, or None if invalid
        """
        is_valid, data, _ = JSONValidator.validate(json_string)
        if is_valid and data is not None:
            return json.dumps(data, indent=indent, sort_keys=True)
        return None

    @staticmethod
    def interactive() -> None:
        """Interactive JSON validation."""
        console.print("[dim]Enter JSON (press Enter twice when done):[/dim]")
        lines = []
        while True:
            line = input()
            if line == "" and lines and lines[-1] == "":
                break
            lines.append(line)

        json_string = "\n".join(lines[:-1] if lines and lines[-1] == "" else lines)
        
        is_valid, data, error = JSONValidator.validate(json_string)
        
        if is_valid:
            console.print("[green]✓ Valid JSON![/green]")
            pretty = JSONValidator.prettify(json_string)
            if pretty:
                console.print(Panel(pretty, title="Formatted JSON", border_style="green"))
        else:
            console.print(f"[red]✗ Invalid JSON: {error}[/red]")


# =============================================================================
# URL SHORTENER
# =============================================================================


class URLShortener:
    """URL shortening utilities."""

    @staticmethod
    def shorten_with_tinyurl(url: str) -> Optional[str]:
        """
        Shorten URL using TinyURL (free, no API key required).
        
        Args:
            url: URL to shorten
            
        Returns:
            Shortened URL, or None if failed
        """
        if requests is None:
            console.print("[red]Error: requests library not installed[/red]")
            return None

        try:
            response = requests.get(
                f"https://tinyurl.com/api-create.php?url={url}",
                timeout=10
            )
            if response.status_code == 200:
                return response.text
            return None
        except Exception as e:
            console.print(f"[red]Error shortening URL: {e}[/red]")
            return None

    @staticmethod
    def interactive() -> None:
        """Interactive URL shortening."""
        url = Prompt.ask("[bold cyan][>][/bold cyan] Enter URL to shorten")
        if not url.strip():
            console.print("[red]No URL provided[/red]")
            return

        # Add protocol if missing
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        console.print("[dim]Shortening URL...[/dim]")
        short_url = URLShortener.shorten_with_tinyurl(url)

        if short_url:
            console.print(f"[green]✓ Shortened URL:[/green] [cyan]{short_url}[/cyan]")
        else:
            console.print("[red]Failed to shorten URL[/red]")


# =============================================================================
# FILE COMPRESSOR
# =============================================================================


class FileCompressor:
    """File and directory compression utilities."""

    FORMATS = ["zip", "tar", "gztar", "bztar"]

    @staticmethod
    def compress(
        source_path: str,
        output_name: Optional[str] = None,
        format: str = "zip"
    ) -> Optional[Path]:
        """
        Compress a file or directory.
        
        Args:
            source_path: Path to file or directory to compress
            output_name: Name for output archive (without extension)
            format: Archive format (zip, tar, gztar, bztar)
            
        Returns:
            Path to created archive, or None if failed
        """
        source = Path(source_path)
        if not source.exists():
            console.print(f"[red]Error: Path does not exist: {source_path}[/red]")
            return None

        if format not in FileCompressor.FORMATS:
            format = "zip"

        output_name = output_name or source.stem

        try:
            if source.is_file():
                # For single files, create a temporary directory
                import tempfile
                with tempfile.TemporaryDirectory() as tmp_dir:
                    tmp_file = Path(tmp_dir) / source.name
                    shutil.copy2(source, tmp_file)
                    archive_path = shutil.make_archive(output_name, format, tmp_dir)
            else:
                archive_path = shutil.make_archive(output_name, format, source)

            return Path(archive_path)
        except Exception as e:
            console.print(f"[red]Error compressing: {e}[/red]")
            return None

    @staticmethod
    def interactive() -> None:
        """Interactive file compression."""
        path = Prompt.ask("[bold cyan][>][/bold cyan] Enter path to compress")
        if not path.strip():
            console.print("[red]No path provided[/red]")
            return

        format_choice = Prompt.ask(
            "[bold cyan][>][/bold cyan] Format (zip, tar, gztar, bztar)",
            default="zip"
        )

        console.print("[dim]Compressing...[/dim]")
        result = FileCompressor.compress(path, format=format_choice)

        if result:
            console.print(f"[green]✓ Created: {result}[/green]")


# =============================================================================
# YOUTUBE DOWNLOADER
# =============================================================================


class YouTubeDownloader:
    """YouTube video downloading utilities."""

    @staticmethod
    def download(
        url: str,
        output_path: str = "downloads",
        audio_only: bool = False
    ) -> Optional[Path]:
        """
        Download a YouTube video.
        
        Args:
            url: YouTube video URL
            output_path: Directory to save video
            audio_only: Download audio only
            
        Returns:
            Path to downloaded file, or None if failed
        """
        if YouTube is None:
            console.print("[red]Error: pytube library not installed[/red]")
            return None

        try:
            yt = YouTube(url)
            console.print(f"[dim]Downloading: {yt.title}[/dim]")

            # Create output directory
            output_dir = Path(output_path)
            output_dir.mkdir(parents=True, exist_ok=True)

            if audio_only:
                stream = yt.streams.filter(only_audio=True).first()
            else:
                stream = yt.streams.get_highest_resolution()

            if stream is None:
                console.print("[red]No suitable stream found[/red]")
                return None

            downloaded_file = stream.download(output_path=str(output_dir))
            return Path(downloaded_file)

        except PytubeError as e:
            console.print(f"[red]YouTube error: {e}[/red]")
            return None
        except Exception as e:
            console.print(f"[red]Error downloading: {e}[/red]")
            return None

    @staticmethod
    def interactive() -> None:
        """Interactive YouTube download."""
        url = Prompt.ask("[bold cyan][>][/bold cyan] Enter YouTube URL")
        if not url.strip():
            console.print("[red]No URL provided[/red]")
            return

        audio_only = Prompt.ask(
            "[bold cyan][>][/bold cyan] Audio only?",
            choices=["y", "n"],
            default="n"
        ).lower() == "y"

        result = YouTubeDownloader.download(url, audio_only=audio_only)

        if result:
            console.print(f"[green]✓ Downloaded: {result}[/green]")


# =============================================================================
# MENU SYSTEM
# =============================================================================


@dataclass
class MenuItem:
    """Represents a menu option."""
    name: str
    handler: Callable[[], None]
    description: str = ""


class Menu:
    """
    Interactive terminal menu system.
    
    Provides a clean, navigable interface for all utilities.
    """

    def __init__(self) -> None:
        """Initialize the menu with all available options."""
        self.items: list[MenuItem] = [
            MenuItem("DNS Lookup", self._dns_lookup, "Look up DNS records for a domain"),
            MenuItem("QR Code Generator", QRCodeGenerator.interactive_generate, "Generate QR codes from text/URLs"),
            MenuItem("IP Pinger", NetworkUtils.interactive_ping, "Check if a host is reachable"),
            MenuItem("Port Checker", NetworkUtils.interactive_port_check, "Check if a port is open"),
            MenuItem("Password Generator", PasswordGenerator.interactive_generate, "Generate secure passwords"),
            MenuItem("ASCII Art", TextUtils.interactive_ascii_art, "Convert text to ASCII art"),
            MenuItem("Reverse Text", TextUtils.interactive_reverse, "Reverse any text"),
            MenuItem("Hash Generator", HashGenerator.interactive_hash, "Generate MD5/SHA hashes"),
            MenuItem("Base64 Encode/Decode", Base64Utils.interactive, "Encode or decode Base64"),
            MenuItem("JSON Validator", JSONValidator.interactive, "Validate and format JSON"),
            MenuItem("URL Shortener", URLShortener.interactive, "Shorten long URLs"),
            MenuItem("File Compressor", FileCompressor.interactive, "Compress files/directories"),
            MenuItem("YouTube Downloader", YouTubeDownloader.interactive, "Download YouTube videos"),
            MenuItem("Show License", self._show_license, "Display software license"),
            MenuItem("Exit", self._exit_app, "Exit the application"),
        ]

    def _dns_lookup(self) -> None:
        """Handle DNS lookup menu option."""
        domain = Prompt.ask("[bold cyan][>][/bold cyan] Enter domain (e.g., google.com)")
        if domain.strip():
            lookup = DNSLookup(domain)
            lookup.display_results()

    def _show_license(self) -> None:
        """Display the license information."""
        license_text = """
MIT License

Copyright (c) 2023-2026 Zayan & Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
        """
        console.print(Panel(license_text.strip(), title="MIT License", border_style="blue"))

    def _exit_app(self) -> None:
        """Exit the application with countdown."""
        console.print("\n[yellow]Thanks for using Krypton![/yellow]", justify='center')
        for i in range(3, 0, -1):
            console.print(f"[dim]Exiting in {i}...[/dim]", justify='center')
            time.sleep(1)
        ConsoleUtils.clear_screen()
        sys.exit(0)

    def display(self) -> None:
        """Display the menu options in a formatted table."""
        table = Table(
            title="[bold]Available Utilities[/bold]",
            show_header=True,
            header_style="bold magenta",
            border_style="blue"
        )
        table.add_column("#", justify="center", style="cyan", width=4)
        table.add_column("Utility", style="white")
        table.add_column("Description", style="dim")

        for idx, item in enumerate(self.items, 1):
            table.add_row(str(idx), item.name, item.description)

        console.print(table, justify='center')

    def run(self) -> None:
        """Run the main menu loop."""
        while True:
            try:
                ConsoleUtils.print_header()
                self.display()
                print()
                console.print(ConsoleUtils.get_divider(), style='bold red', justify='center')
                print()

                # Get user input
                console.print(
                    "[blink][bold]Select an option (1-{}):[/bold][/blink]".format(len(self.items)),
                    justify='center'
                )

                try:
                    choice = int(input("  " * (shutil.get_terminal_size().columns // 4)))
                except ValueError:
                    console.print("[red]Please enter a valid number[/red]", justify='center')
                    time.sleep(1.5)
                    continue

                if 1 <= choice <= len(self.items):
                    print()
                    self.items[choice - 1].handler()
                    ConsoleUtils.pause_and_return()
                else:
                    console.print("[red]Invalid option[/red]", justify='center')
                    time.sleep(1.5)

            except KeyboardInterrupt:
                console.print("\n[yellow]Interrupted. Exiting...[/yellow]")
                break
            except Exception as e:
                from rich.markup import escape
                console.print(f"[red]Error: {escape(str(e))}[/red]")
                time.sleep(2)


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================


def main() -> None:
    """Main entry point for Krypton."""
    # Initial header display
    ConsoleUtils.print_header()
    time.sleep(0.5)

    # Run the menu
    menu = Menu()
    menu.run()


if __name__ == "__main__":
    main()