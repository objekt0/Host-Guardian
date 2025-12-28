import os
import sys
import time
import socket
import re
import platform
import subprocess
import logging
import threading
from datetime import datetime
from scapy.all import sniff, ARP, conf, Ether, srp, getmacbyip

# ═══════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════

CONFIG = {
    "MODE": "enforce",          # 'enforce' (Lock & Block) or 'monitor' (Log only)
    "REFRESH_INTERVAL": 30,     # Seconds to re-apply lock
    "SAFE_MODE": True,          # Auto-unlock if connection is lost
    "LOG_FILE": "host_guardian.log",
    "VERSION": "2.1-Refactored"
}

# ═══════════════════════════════════════════════════════════════════════════
# UI & STYLING
# ═══════════════════════════════════════════════════════════════════════════

class UI:
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'
    DIM = '\033[2m'

    @staticmethod
    def banner():
        return f"""{UI.CYAN}{UI.BOLD}
    ╔═════════════════════════════════════════════════════════════════════════╗
    ║                🛡️  HOST GUARDIAN - ARP PROTECTION SYSTEM                ║
    ╚═════════════════════════════════════════════════════════════════════════╝{UI.END}"""

    @staticmethod
    def log_status(icon, message, color=CYAN):
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"  {UI.DIM}[{timestamp}]{UI.END} {color}{icon} {message}{UI.END}")

# ═══════════════════════════════════════════════════════════════════════════
# NETWORK UTILITIES
# ═══════════════════════════════════════════════════════════════════════════

class NetworkManager:
    def __init__(self):
        self.os = platform.system()
        self.interface = self._detect_interface()
        self.gateway_ip = self._get_gateway_ip()
        self.gateway_mac = None

    def _detect_interface(self):
        """Detects the active network interface by connecting to a public IP."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()

            if self.os == "Windows":
                from scapy.arch.windows import get_windows_if_list
                for iface in get_windows_if_list():
                    if "ips" in iface and local_ip in iface["ips"]:
                        return iface["name"]
            return conf.iface
        except Exception:
            return "Wi-Fi"

    def _get_gateway_ip(self):
        try:
            return conf.route.route("0.0.0.0")[2]
        except Exception:
            return None

    def get_mac(self, ip):
        """Resolves MAC address via system ARP table or SRP packet."""
        # Try system ARP table first
        try:
            if self.os == "Windows":
                cmd = subprocess.check_output(f"arp -a {ip}", shell=True).decode('cp1252', errors='ignore')
                match = re.search(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", cmd)
                if match: return match.group().replace("-", ":").upper()
            else:
                mac = getmacbyip(ip)
                if mac: return mac
        except: pass

        # Fallback: Scapy SRP
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, verbose=0)
        return ans[0][1].hwsrc if ans else None

    def toggle_arp_lock(self, ip, mac, lock=True):
        """Locks or unlocks the ARP entry in the system neighbor table."""
        action = "add" if lock else "delete"
        try:
            if self.os == "Windows":
                mac_win = mac.replace(":", "-")
                # Ensure clean state by attempting delete first
                subprocess.run(f'netsh interface ip delete neighbors "{self.interface}" {ip}', 
                               shell=True, capture_output=True)
                if lock:
                    subprocess.run(f'netsh interface ip add neighbors "{self.interface}" {ip} {mac_win}', 
                                   shell=True, check=True, capture_output=True)
            else:
                subprocess.run(f"ip neigh {'replace' if lock else 'del'} {ip} lladdr {mac} nud permanent dev {self.interface}", 
                               shell=True, check=True, capture_output=True)
            return True
        except Exception:
            return False

# ═══════════════════════════════════════════════════════════════════════════
# CORE PROTECTION ENGINE
# ═══════════════════════════════════════════════════════════════════════════

class HostGuardian:
    def __init__(self):
        self.net = NetworkManager()
        self.running = True
        self.attack_count = 0
        self.lock_active = False

        logging.basicConfig(filename=CONFIG["LOG_FILE"], level=logging.INFO, 
                            format='%(asctime)s - %(levelname)s - %(message)s')

    def check_health(self):
        """Verifies internet connectivity via Gateway ping."""
        param = '-n' if self.net.os == 'Windows' else '-c'
        res = subprocess.call(['ping', param, '1', self.net.gateway_ip], 
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return res == 0

    def watchdog(self):
        """Background thread to maintain ARP lock and check connectivity."""
        while self.running:
            is_alive = self.check_health()
            
            if not is_alive and CONFIG["SAFE_MODE"]:
                if self.lock_active:
                    UI.log_status("⚠", "Connection Lost. Releasing lock for safety...", UI.YELLOW)
                    self.net.toggle_arp_lock(self.net.gateway_ip, self.net.gateway_mac, False)
                    self.lock_active = False
            elif is_alive and CONFIG["MODE"] == "enforce":
                self.net.toggle_arp_lock(self.net.gateway_ip, self.net.gateway_mac, True)
                self.lock_active = True
                
            time.sleep(CONFIG["REFRESH_INTERVAL"])

    def packet_callback(self, pkt):
        if not pkt.haslayer(ARP) or pkt[ARP].op != 2: # Looking for ARP replies
            return

        if pkt[ARP].psrc == self.net.gateway_ip:
            if pkt[ARP].hwsrc.lower() != self.net.gateway_mac.lower():
                self.attack_count += 1
                UI.log_status("🔥", f"SPOOFING DETECTED! Attacker: {pkt[ARP].hwsrc}", UI.RED)
                logging.warning(f"ARP Spoof Attempt: {pkt[ARP].hwsrc}")

    def start(self):
        print(UI.banner())
        UI.log_status("🔍", f"Scanning: {self.net.gateway_ip} on {self.net.interface}")
        
        self.net.gateway_mac = self.net.get_mac(self.net.gateway_ip)
        if not self.net.gateway_mac:
            UI.log_status("✗", "Could not resolve Gateway MAC. Exiting.", UI.RED)
            return

        UI.log_status("✓", f"Gateway Verified: {self.net.gateway_mac}", UI.GREEN)
        
        # Start Watchdog
        threading.Thread(target=self.watchdog, daemon=True).start()
        
        UI.log_status("🛡️", f"Protection Active ({CONFIG['MODE']}) - Press Ctrl+C to stop", UI.CYAN)
        
        try:
            sniff(filter="arp", prn=self.packet_callback, store=0, iface=self.net.interface)
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        self.running = False
        print(f"\n{UI.DIM}────────────────────────────────────────────────────────────{UI.END}")
        UI.log_status("⏹", "Shutting down... Releasing system locks.")
        self.net.toggle_arp_lock(self.net.gateway_ip, self.net.gateway_mac, False)
        UI.log_status("✓", f"Clean exit. Total attacks blocked: {self.attack_count}", UI.GREEN)
        sys.exit(0)

# ═══════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    # Admin Check
    is_admin = False
    try:
        is_admin = os.getuid() == 0
    except AttributeError:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0

    if not is_admin:
        print(f"{UI.RED}✗ ERROR: This script requires Administrator/Root privileges.{UI.END}")
        sys.exit(1)

    guardian = HostGuardian()
    guardian.start()
