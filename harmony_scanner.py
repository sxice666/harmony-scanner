# -*- coding: utf-8 -*-
"""
HARMONY SCANNER v1.1 - Interactive OSINT Lab Tool
Author: sxice666
Usage: 
    python harmony_scanner.py
    >>> scan
    >>> help
    >>> exit
"""

import socket
import ssl
import json
import sys
import base64
from datetime import datetime
from urllib.parse import urlparse

# === CONFIGURATION ===
DEFAULT_PORTS = [80, 443, 8080, 8443]
TIMEOUT_CONNECT = 3.0   # Seconds for TCP connect check
TIMEOUT_SSL = 5.0       # Seconds for SSL handshake/cert fetch


def hr(title=""):
    """Prints a horizontal rule with optional title."""
    line = "=" * 60
    if title:
        print(f"\n{line}\n {title.upper()}\n{line}")
    else:
        print(line)


def resolve_dns(domain):
    """Resolves domain to list of unique IPs."""
    try:
        _, aliases, ips = socket.gethostbyname_ex(domain)
        return list(set(ips))
    except Exception as e:
        return []


def check_port(ip, port, timeout=TIMEOUT_CONNECT):
    """Checks if a specific IP:Port is open using TCP Connect."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((ip, port))
        return result == 0
    except Exception:
        return False
    finally:
        sock.close()


def parse_der_with_cryptography(der_bytes):
    """
    Attempts to parse raw DER bytes using the 'cryptography' library.
    Returns a dict with cert info or None if library missing/error.
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        
        cert_obj = x509.load_der_x509_certificate(der_bytes)
        
        # Extract Subject CN
        subject_attrs = cert_obj.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        cn = subject_attrs[0].value if subject_attrs else "N/A"
        
        # Extract Issuer CN
        issuer_attrs = cert_obj.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        issuer_cn = issuer_attrs[0].value if issuer_attrs else "N/A"
        
        # Extract SANs
        sans = []
        try:
            san_ext = cert_obj.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            dns_names = san_ext.value.get_values_for_type(x509.DNSName)
            sans.extend(dns_names)
        except x509.ExtensionNotFound:
            pass
            
        # Validity dates
        not_before = cert_obj.not_valid_before_utc.isoformat() if hasattr(cert_obj, 'not_valid_before_utc') else str(cert_obj.not_valid_before)
        not_after = cert_obj.not_valid_after_utc.isoformat() if hasattr(cert_obj, 'not_valid_after_utc') else str(cert_obj.not_valid_after)

        return {
            "source": "cryptography_lib",
            "cn": cn,
            "issuer": issuer_cn,
            "valid_from": not_before,
            "valid_to": not_after,
            "sans": sans,
            "fingerprint_sha256": cert_obj.fingerprint(hashes.SHA256()).hex(":")
        }
        
    except ImportError:
        return {"error": "Library 'cryptography' not installed. Run: pip install cryptography"}
    except Exception as e:
        return {"error": f"Parsing error: {str(e)}"}


def fetch_ssl_cert(ip, domain, port=443, timeout=TIMEOUT_SSL):
    """Connects via TLS and extracts certificate details with fallback to DER parsing."""
    
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    # Try to set minimum version to avoid old protocol issues
    try:
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    except AttributeError:
        pass

    cert_data = {}
    der_bytes = None
    
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        ssock = context.wrap_socket(sock, server_hostname=domain)
        
        # 1. Try standard Python ssl getpeercert
        cert_dict = ssock.getpeercert(binary_form=False)
        
        if cert_dict:
            # Standard success path
            subject_dict = dict(x[0] for x in cert_dict['subject'])
            common_name = subject_dict.get('commonName', 'N/A')
            
            issuer_dict = dict(x[0] for x in cert_dict['issuer'])
            issuer_cn = issuer_dict.get('commonName', 'N/A')
            
            sans = []
            if 'subjectAltName' in cert_dict:
                for typ, val in cert_dict['subjectAltName']:
                    if typ == 'DNS':
                        sans.append(val)
            
            cert_data = {
                "source": "python_ssl_module",
                "cn": common_name,
                "issuer": issuer_cn,
                "valid_from": cert_dict.get('notBefore'),
                "valid_to": cert_dict.get('notAfter'),
                "sans": sans,
                "protocol": ssock.version(),
                "cipher": ssock.cipher()[0] if ssock.cipher() else "Unknown"
            }
        else:
            # 2. Fallback: Get binary form (DER) manually
            der_bytes = ssock.getpeercert(binary_form=True)
            
            if der_bytes:
                # We have the raw bytes, let's try to parse them nicely
                parsed_info = parse_der_with_cryptography(der_bytes)
                
                if "error" in parsed_info:
                     cert_data = {
                         "source": "raw_der_saved",
                         "note": "Could not parse automatically, but saved DER file.",
                         "error_detail": parsed_info["error"],
                         "size_bytes": len(der_bytes)
                     }
                else:
                    cert_data = parsed_info
                    # Add protocol info even if we used manual parsing
                    cert_data["protocol"] = ssock.version()
            else:
                 cert_data = {"error": "Handshake succeeded but NO certificate was returned by server."}
                 
        ssock.close()
            
    except ssl.SSLError as e:
        cert_data = {"error": f"SSL Handshake Failed: {e}"}
    except socket.timeout:
        cert_data = {"error": "Timed out waiting for SSL response"}
    except ConnectionResetError:
        cert_data = {"error": "Connection reset by peer (likely blocked/WAF intervention)"}
    except Exception as e:
        cert_data = {"error": f"Unexpected error: {type(e).__name__}: {e}"}
        
    # Attach raw DER bytes to data so main loop can save it if needed
    cert_data["_raw_der"] = der_bytes 
    
    return cert_data


def perform_scan(domain):
    """Main scanning logic for a single domain."""
    clean_domain = urlparse(domain).netloc or domain
    
    if not clean_domain:
        print("[-] Error: Invalid domain format.")
        return

    hr(f"SCANNING TARGET: {clean_domain}")
    
    report = {
        "target": clean_domain,
        "timestamp": datetime.now().isoformat(),
        "resolved_ips": [],
        "services": []
    }

    # Step 1: DNS Resolution
    print("[*] Resolving DNS...")
    ips = resolve_dns(clean_domain)
    
    if not ips:
        print(f"[-] Failed to resolve any IP addresses for '{clean_domain}'.")
        return
        
    print(f"[+] Found {len(ips)} IP address(es): {', '.join(ips)}")
    report["resolved_ips"] = ips

    # Step 2: Port Scanning & Service Enumeration
    print(f"[*] Scanning ports {DEFAULT_PORTS} on {len(ips)} host(s)...")
    
    total_open_services = 0
    
    for ip in ips:
        for port in DEFAULT_PORTS:
            status = check_port(ip, port)
            
            if status:
                total_open_services += 1
                service_entry = {
                    "ip": ip,
                    "port": port,
                    "status": "OPEN",
                    "details": {}
                }
                
                print(f"    [+] OPEN: {ip}:{port}", end=" ")
                
                # If it's an HTTPS port, try to grab the cert
                if port in [443, 8443]:
                    print("(Fetching SSL...)")
                    ssl_info = fetch_ssl_cert(ip, clean_domain, port)
                    
                    # Remove internal helper key before adding to report
                    raw_der = ssl_info.pop("_raw_der", None)
                    service_entry["details"]["ssl"] = ssl_info
                    
                    # Output formatting
                    if "error" in ssl_info:
                        print(f"        [-] ERROR: {ssl_info['error']}")
                    else:
                        src_tag = ssl_info.get("source", "?")
                        print(f"        [{src_tag}] CN: {ssl_info.get('cn', 'N/A')}")
                        print(f"        [{src_tag}] Issuer: {ssl_info.get('issuer', 'N/A')}")
                        
                        sans_list = ssl_info.get("sans", [])
                        if sans_list:
                            display_sans = ", ".join(sans_list[:5])
                            suffix = "..." if len(sans_list) > 5 else ""
                            print(f"        [{src_tag}] SANs: {display_sans}{suffix}")
                        else:
                             print(f"        [{src_tag}] SANs: None found")
                             
                        if ssl_info.get("protocol"):
                             print(f"        [{src_tag}] Protocol: {ssl_info['protocol']}")

                elif port in [80, 8080]:
                    print("(HTTP detected)")
                    service_entry["details"]["service_guess"] = "HTTP/Web Server"
                    
                report["services"].append(service_entry)

    hr("SCAN SUMMARY")
    print(f"Total Unique IPs: {len(ips)}")
    print(f"Total Open Services Found: {total_open_services}")
    
    if total_open_services == 0:
        print("[!] No standard web ports were found open.")

    # Save Report to File
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_domain = clean_domain.replace('.', '_').replace('/', '_')
    filename = f"harmony_report_{safe_domain}_{timestamp_str}.json"
    
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=4, ensure_ascii=False)
        print(f"\n[*] Detailed JSON report saved to: {filename}")
    except Exception as e:
        print(f"\n[-] Failed to save report file: {e}")

    return report


def show_help():
    hr("HELP & COMMANDS")
    print("""
Available Commands:

  scan <domain>      Start full infrastructure scan.
                     Examples:
                       scan google.com
                       scan github.com
                       scan school.mos.ru

  help               Show this help message.

  exit               Quit the Harmony Scanner.

What does 'scan' do?
  1. Resolves Domain -> IP Addresses (DNS).
  2. Checks connectivity to standard ports: 80, 443, 8080, 8443.
  3. For HTTPS ports (443/8443), downloads and parses the SSL Certificate.
     - Uses Python's built-in ssl module first.
     - Falls back to saving raw DER and parsing with 'cryptography' lib if available.
     - Extracts Common Name (CN), Issuer, and Subject Alternative Names (SANs).
  4. Saves everything into a JSON report file in the current directory.

Tip: For best results with complex certificates, run:
     pip install cryptography
""")


def main_loop():
    hr("HARMONY SCANNER v1.1 - INTERACTIVE MODE")
    print("Type 'help' for commands, 'scan <domain>' to start, 'exit' to quit.")
    
    while True:
        try:
            user_input = input("\n>>> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[*] Interrupted by user. Exiting...")
            break

        if not user_input:
            continue

        parts = user_input.split(maxsplit=1)
        command = parts[0].lower()
        argument = parts[1] if len(parts) > 1 else None

        if command == "exit" or command == "quit":
            print("[*] Goodbye!")
            break

        elif command == "help":
            show_help()

        elif command == "scan":
            if not argument:
                print("[-] Error: Please specify a domain or IP. Usage: scan <domain>")
            else:
                perform_scan(argument)

        else:
            print(f"[-] Unknown command: '{command}'. Type 'help' for list of commands.")


if __name__ == "__main__":
    main_loop()