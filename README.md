<h1 align="center">Krypton</h1>

<p align="center">
  <b>A General-Purpose Command-Line Utility Toolkit</b>
</p>

<p align="center">
  <a href="https://github.com/KiIlerDrift">
    <img src="https://flat.badgen.net/badge/Made%20by/KillerDrift/blue" alt="Made by">
  </a>
  <a href="LICENSE">
    <img src="https://flat.badgen.net/badge/License/MIT/blue" alt="License">
  </a>
  <a href="https://github.com/KiIlerDrift/Krypt0n/releases">
    <img src="https://flat.badgen.net/badge/Version/2.0.0/blue" alt="Version">
  </a>
  <img src="https://flat.badgen.net/badge/Python/3.9+/green" alt="Python">
</p>

<p align="center">
  <a href="https://github.com/KiIlerDrift/Krypt0n/forks">
    <img src="https://flat.badgen.net/github/forks/KiIlerDrift/Krypt0n" alt="Forks">
  </a>
  <a href="https://github.com/KiIlerDrift/Krypt0n/stars">
    <img src="https://flat.badgen.net/github/stars/KiIlerDrift/Krypt0n" alt="Stars">
  </a>
  <a href="https://github.com/KiIlerDrift/Krypt0n/watchers">
    <img src="https://flat.badgen.net/github/watchers/KiIlerDrift/Krypt0n" alt="Watchers">
  </a>
</p>

---

A collection of safe, ethical command-line utilities for everyday tasks. Krypton provides a beautiful terminal interface for common operations like DNS lookups, password generation, file compression, and more.

## ✨ Features

| Utility | Description |
|---------|-------------|
| 🔍 **DNS Lookup** | Look up DNS records using multiple methods (socket, dnspython) |
| 📱 **QR Code Generator** | Generate customizable QR codes from text or URLs |
| 🌐 **IP Pinger** | Check if hosts are reachable |
| 🔌 **Port Checker** | Verify if specific ports are open |
| 🔐 **Password Generator** | Generate secure passwords with strength assessment |
| 🎨 **ASCII Art** | Convert text to ASCII art using pyfiglet |
| 🔄 **Text Reverser** | Reverse any text string |
| #️⃣ **Hash Generator** | Generate MD5, SHA-1, SHA-256, SHA-512 hashes |
| 📝 **Base64 Encode/Decode** | Encode and decode Base64 strings |
| 📋 **JSON Validator** | Validate and pretty-print JSON |
| 🔗 **URL Shortener** | Shorten long URLs using TinyURL |
| 📦 **File Compressor** | Compress files/directories (zip, tar, gztar) |
| 📺 **YouTube Downloader** | Download YouTube videos and audio |

## 🚀 Quick Start

### Prerequisites

- Python 3.9 or higher
- pip (Python package manager)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/KiIlerDrift/Krypt0n.git
   cd Krypt0n
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run Krypton**
   ```bash
   python krypton.py
   ```

## 📖 Usage Examples

### DNS Lookup
```
Select option 1 → Enter domain (e.g., google.com)
```
Displays A records, MX records, and IP addresses using multiple lookup methods.

### Password Generator
```
Select option 5 → Enter desired length (default: 16)
```
Generates a cryptographically secure password with strength assessment.

### QR Code Generator
```
Select option 2 → Enter text or URL → Choose colors
```
Creates a PNG image with your custom QR code.

### YouTube Downloader
```
Select option 13 → Paste YouTube URL → Choose video or audio only
```
Downloads to the `downloads` folder.

## 📦 Dependencies

| Package | Purpose |
|---------|---------|
| `rich` | Beautiful terminal output and formatting |
| `requests` | HTTP requests for URL shortening |
| `pytube` | YouTube video downloading |
| `qrcode[pil]` | QR code generation |
| `dnspython` | Advanced DNS lookups |
| `pyfiglet` | ASCII art text generation |

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the project
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is provided for educational and legitimate utility purposes only. The developers are not responsible for any misuse of the software. Please use responsibly and in accordance with applicable laws and terms of service.

---

<p align="center">
  Made with ❤️ by <a href="https://github.com/KiIlerDrift">KillerDrift</a> & Contributors
</p>
