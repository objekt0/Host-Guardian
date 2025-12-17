#!/usr/bin/env python3
"""
🛡️ Host Guardian - v3.0 (Self-Healing & Hardened)
Features:
- Auto Discovery
- Static ARP Locking (Linux/Windows)
- Safe-Rollback (Watchdog)
- Periodic Refresh (Hardening)
"""

from scapy.all import sniff, ARP, conf, Ether, srp, getmacbyip, get_if_list
import os
import socket
import sys
import platform
import subprocess
import time
import logging
import threading
import re
from datetime import datetime

def get_default_interface():
    """
    تحديد كرت الشبكة المتصل بالإنترنت تلقائياً
    """
    target = "8.8.8.8"  # سيرفر جوجل (للتجربة فقط)
    
    try:
        # 1. معرفة الآي بي المحلي المستخدم للإنترنت
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((target, 80))
        local_ip = s.getsockname()[0]
        s.close()
        
        print(f"[AUTO] Local IP detected: {local_ip}")

        # 2. البحث عن اسم الواجهة التي تحمل هذا الآي بي
        if platform.system() == "Windows":
            from scapy.arch.windows import get_windows_if_list
            
            # Scapy يجلب قائمة بكل الكروت في الويندوز
            interfaces = get_windows_if_list()
            for iface in interfaces:
                # نبحث داخل الكرت هل يحتوي على الآي بي الخاص بنا؟
                if "ips" in iface and local_ip in iface["ips"]:
                    # في ويندوز نحتاج "Connection Name" مثل Wi-Fi
                    return iface["name"]
                    
        else:
            # في لينكس الوضع أسهل، Scapy يحددها تلقائياً
            return conf.iface

    except Exception as e:
        print(f"[ERROR] Auto-select failed: {e}")
        return None

# ════════════ CONFIGURATION ════════════
CONFIG = {
    "mode": "enforce",          # 'enforce' (Lock & Block) or 'monitor' (Log only)
    "refresh_interval": 30,     # Seconds to re-apply lock (Hardening)
    "safe_mode": True,          # Auto-unlock if connection is lost (Safe-Rollback)
    "log_file": "host_guardian.log",
    "interface": get_default_interface() or "Wi-Fi"           # Auto Detect or Fallback
}
# ═══════════════════════════════════════

# إعداد اللوجينج
logging.basicConfig(
    filename=CONFIG["log_file"],
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(message)s'
)

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    WHITE = '\033[97m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_BLUE = '\033[44m'

class HostGuardian:
    VERSION = "3.0"
    
    def __init__(self):
        self.os_type = platform.system()
        self.gateway_ip = None
        self.gateway_mac = None
        self.interface = CONFIG["interface"]
        self.running = True
        self.lock_active = False
        self.attack_count = 0
        self.start_time = None

    def clear_screen(self):
        """مسح الشاشة"""
        os.system('cls' if self.os_type == 'Windows' else 'clear')

    def print_banner(self):
        """طباعة بانر البرنامج"""
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
    ╔///////////////////////////////////////////////////////////////////////////////////////////////╗
    ║                                                                                               ║
    ║                        {Colors.WHITE}██╗  ██╗ ██████╗ ███████╗████████╗{Colors.CYAN}          ║
    ║                        {Colors.WHITE}██║  ██║██╔═══██╗██╔════╝╚══██╔══╝{Colors.CYAN}          ║
    ║                        {Colors.WHITE}███████║██║   ██║███████╗   ██║   {Colors.CYAN}          ║
    ║                        {Colors.WHITE}██╔══██║██║   ██║╚════██║   ██║   {Colors.CYAN}          ║
    ║                        {Colors.WHITE}██║  ██║╚██████╔╝███████║   ██║   {Colors.CYAN}          ║
    ║                        {Colors.WHITE}╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   {Colors.CYAN}          ║
    ║                                                                                               ║
    ║      {Colors.GREEN}██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ ██╗ █████╗ ███╗   ██╗{Colors.CYAN} ║
    ║     {Colors.GREEN}██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗██║██╔══██╗████╗  ██║{Colors.CYAN}║
    ║     {Colors.GREEN}██║  ███╗██║   ██║███████║██████╔╝██║  ██║██║███████║██╔██╗ ██║{Colors.CYAN}║
    ║     {Colors.GREEN}██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║██║██╔══██║██║╚██╗██║{Colors.CYAN}║
    ║     {Colors.GREEN}╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝██║██║  ██║██║ ╚████║{Colors.CYAN}║
    ║      {Colors.GREEN}╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝{Colors.CYAN} ║
    ║                                                                                               ║
    ╠///////////////////////////////////////////////////////////////////////////////////////////////╣
    ║  {Colors.YELLOW}🛡️  ARP Spoofing Protection System  v{self.VERSION}{Colors.CYAN}              ║
    ║  {Colors.DIM}    Self-Healing • Static Lock • Watchdog{Colors.CYAN}                           ║
    ╚///////////////////////////////////////////////////////////////////////////////////////////////╝
{Colors.ENDC}""" 
        print(banner)

    def print_section(self, title, icon="▶"): 
        """طباعة عنوان قسم"""
        print(f"\n{Colors.CYAN}{'─'*60}{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.BLUE}  {icon} {title}{Colors.ENDC}")
        print(f"{Colors.CYAN}{'─'*60}{Colors.ENDC}")

    def print_status(self, label, value, status="info"):
        """طباعة حالة بتنسيق جميل"""
        colors = {
            "info": Colors.CYAN,
            "success": Colors.GREEN,
            "warning": Colors.YELLOW,
            "error": Colors.FAIL
        }
        color = colors.get(status, Colors.CYAN)
        print(f"  {Colors.DIM}├─{Colors.ENDC} {Colors.WHITE}{label}:{Colors.ENDC} {color}{value}{Colors.ENDC}")

    def print_box(self, message, box_type="info"):
        """طباعة رسالة في صندوق"""
        colors = {
            "info": (Colors.BLUE, "ℹ"),
            "success": (Colors.GREEN, "✓"),
            "warning": (Colors.YELLOW, "⚠"),
            "error": (Colors.FAIL, "✗"),
            "shield": (Colors.CYAN, "🛡️")
        }
        color, icon = colors.get(box_type, (Colors.BLUE, "•"))
        width = len(message) + 6
        print(f"\n  {color}╭{'─'*width}╮{Colors.ENDC}")
        print(f"  {color}│  {icon}  {message}  │{Colors.ENDC}")
        print(f"  {color}╰{'─'*width}╯{Colors.ENDC}\n")

    def log(self, type, message):
        """دالة مساعدة للطباعة والتسجيل معاً"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        if type == "INFO":
            print(f"  {Colors.DIM}[{timestamp}]{Colors.ENDC} {Colors.GREEN}✓ {message}{Colors.ENDC}")
        elif type == "WARN":
            print(f"  {Colors.DIM}[{timestamp}]{Colors.ENDC} {Colors.YELLOW}⚠ {message}{Colors.ENDC}")
        elif type == "ERR":
            print(f"  {Colors.DIM}[{timestamp}]{Colors.ENDC} {Colors.FAIL}✗ {message}{Colors.ENDC}")
        logging.info(message)

    def auto_discovery(self):
        self.print_section("Network Auto-Discovery", "🔍")
        try:
            # 1. تحديد كرت الشبكة
            if not self.interface:
                self.interface = conf.iface
            
            # 2. تحديد IP الراوتر
            self.gateway_ip = conf.route.route("0.0.0.0")[2]
            
            self.print_status("Gateway IP", self.gateway_ip, "info")
            self.print_status("Interface", self.interface, "info")
            self.print_status("OS Type", self.os_type, "info")

            # 3. الحل الجذري (Windows Native ARP)
            print(f"\n  {Colors.YELLOW}⏳ Updating ARP table...{Colors.ENDC}")
            param = '-n' if self.os_type == 'Windows' else '-c'
            subprocess.run(['ping', param, '1', self.gateway_ip], stdout=subprocess.DEVNULL)

            print(f"  {Colors.YELLOW}⏳ Reading System ARP Table...{Colors.ENDC}")
            if self.os_type == "Windows":
                arp_cmd = subprocess.check_output(f"arp -a {self.gateway_ip}", shell=True).decode('cp1252', errors='ignore')
                search = re.search(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", arp_cmd)
                if search:
                    self.gateway_mac = search.group().replace("-", ":").upper()
            else:
                self.gateway_mac = getmacbyip(self.gateway_ip)

            # التحقق النهائي
            if self.gateway_mac:
                self.print_status("Gateway MAC", self.gateway_mac, "success")
                self.print_box("Network Discovery Complete!", "success")
                logging.info(f"Discovery: IP={self.gateway_ip}, MAC={self.gateway_mac}")
            else:
                print(f"  {Colors.YELLOW}⏳ Fallback to raw SRP...{Colors.ENDC}")
                ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=self.gateway_ip), timeout=2, verbose=0)
                if ans:
                    self.gateway_mac = ans[0][1].hwsrc
                    self.print_status("Gateway MAC", self.gateway_mac, "success")
                else:
                    self.print_box("Could not find Gateway MAC!", "error")
                    sys.exit(1)

        except Exception as e:
            self.print_box(f"Discovery Error: {e}", "error")
            sys.exit(1)

    def check_connection(self):
        """فحص سريع للاتصال (Ping)"""
        param = '-n' if self.os_type == 'Windows' else '-c'
        res = subprocess.call(
            ['ping', param, '1', self.gateway_ip], 
            stdout=subprocess.DEVNULL, 
            stderr=subprocess.DEVNULL
        )
        return res == 0

    def manage_lock(self, action="lock"):
        """تطبيق أو إزالة القفل (Enforcement Logic)"""
        if CONFIG["mode"] != "enforce" and action == "lock":
            return

        ip = self.gateway_ip
        mac = self.gateway_mac
        iface = self.interface

        try:
            if self.os_type == "Windows":
                mac_win = mac.replace(":", "-")
                del_cmd = f'netsh interface ip delete neighbors "{iface}" {ip}'
                add_cmd = f'netsh interface ip add neighbors "{iface}" {ip} {mac_win}'
                
                subprocess.run(del_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                
                if action == "lock":
                    subprocess.run(add_cmd, shell=True, check=True, stdout=subprocess.DEVNULL)

            elif self.os_type == "Linux":
                del_cmd = f"ip neigh del {ip} dev {iface}"
                add_cmd = f"ip neigh replace {ip} lladdr {mac} nud permanent dev {iface}"
                
                subprocess.run(del_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if action == "lock":
                    subprocess.run(add_cmd, shell=True, check=True, stdout=subprocess.DEVNULL)

            if action == "lock":
                self.lock_active = True
            else:
                self.lock_active = False

        except Exception as e:
            logging.error(f"Lock Operation Failed: {e}")

    def watchdog_loop(self):
        """العملية الخلفية: Refresh + Safe Rollback"""
        while self.running:
            is_connected = self.check_connection()

            if not is_connected:
                if CONFIG["safe_mode"] and self.lock_active:
                    self.log("WARN", "Connection Lost! Safe-Rollback triggered...")
                    self.manage_lock("unlock")
                    time.sleep(5) 
                else:
                    self.log("WARN", "Connection unstable...")
            else:
                if CONFIG["mode"] == "enforce":
                    self.manage_lock("lock")
            
            time.sleep(CONFIG["refresh_interval"])

    def process_packet(self, packet):
        """Detection Logic Only"""
        if not packet.haslayer(ARP): return
        
        op = packet[ARP].op
        sender_ip = packet[ARP].psrc
        sender_mac = packet[ARP].hwsrc

        if sender_ip == self.gateway_ip and op == 2:
            if sender_mac.lower() != self.gateway_mac.lower():
                self.attack_count += 1
                print(f"\n{Colors.BG_RED}{Colors.WHITE}{Colors.BOLD}")
                print(f"  ╔══════════════════════════════════════════════════════════╗")
                print(f"  ║ 🚨 ARP SPOOFING ATTACK DETECTED! #{self.attack_count:<20}║")
                print(f"  ╠══════════════════════════════════════════════════════════╣")
                print(f"  ║  Attacker MAC : {sender_mac:<40}                         ║")
                print(f"  ║  Claiming IP  : {sender_ip:<40}                          ║")
                print(f"  ║  Real MAC     : {self.gateway_mac:<40}                   ║")
                print(f"  ╚══════════════════════════════════════════════════════════╝")
                print(f"{Colors.ENDC}")
                logging.warning(f"SPOOFING DETECTED! Attacker: {sender_mac}")

    def print_active_status(self):
        """طباعة حالة البرنامج النشطة"""
        mode_color = Colors.GREEN if CONFIG["mode"] == "enforce" else Colors.YELLOW
        mode_icon = "🔒" if CONFIG["mode"] == "enforce" else "👁️"
        safe_status = "ON" if CONFIG["safe_mode"] else "OFF"
        
        print(f"\n{Colors.CYAN}{'═'*60}{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.WHITE}  📊 PROTECTION STATUS{Colors.ENDC}")
        print(f"{Colors.CYAN}{'═'*60}{Colors.ENDC}")
        print(f"  {Colors.DIM}│{Colors.ENDC}")
        print(f"  {Colors.DIM}├─{Colors.ENDC} Mode        : {mode_color}{mode_icon} {CONFIG['mode'].upper()}{Colors.ENDC}")
        print(f"  {Colors.DIM}├─{Colors.ENDC} Safe Mode   : {Colors.CYAN}{safe_status}{Colors.ENDC}")
        print(f"  {Colors.DIM}├─{Colors.ENDC} Refresh     : {Colors.CYAN}{CONFIG['refresh_interval']}s{Colors.ENDC}")
        print(f"  {Colors.DIM}├─{Colors.ENDC} Target      : {Colors.GREEN}{self.gateway_ip}{Colors.ENDC}")
        print(f"  {Colors.DIM}└─{Colors.ENDC} Locked MAC  : {Colors.GREEN}{self.gateway_mac}{Colors.ENDC}")
        print(f"{Colors.CYAN}{'═'*60}{Colors.ENDC}")
        
        print(f"\n  {Colors.GREEN}🛡️  Protection Active - Monitoring ARP Traffic...{Colors.ENDC}")
        print(f"  {Colors.DIM}   Press Ctrl+C to stop{Colors.ENDC}\n")

    def start(self):
        self.start_time = datetime.now()
        
        # مسح الشاشة وطباعة البانر
        self.clear_screen()
        self.print_banner()
        
        # تهيئة
        self.auto_discovery()
        
        # تشغيل الـ Watchdog في Thread منفصل
        wd_thread = threading.Thread(target=self.watchdog_loop, daemon=True)
        wd_thread.start()
        
        # طباعة حالة الحماية
        self.print_active_status()
        
        try:
            # التعديل الضروري: تحديد الكرت الذي اكتشفناه سابقاً
            sniff(filter="arp", prn=self.process_packet, store=0, iface=self.interface)
        except KeyboardInterrupt:
            print(f"\n{Colors.CYAN}{'═'*60}{Colors.ENDC}")
            print(f"{Colors.BOLD}{Colors.YELLOW}  ⏹️  Shutting Down...{Colors.ENDC}")
            print(f"{Colors.CYAN}{'═'*60}{Colors.ENDC}")
            
            runtime = datetime.now() - self.start_time
            print(f"  {Colors.DIM}├─{Colors.ENDC} Runtime       : {Colors.CYAN}{runtime}{Colors.ENDC}")
            print(f"  {Colors.DIM}├─{Colors.ENDC} Attacks Found : {Colors.YELLOW}{self.attack_count}{Colors.ENDC}")
            print(f"  {Colors.DIM}└─{Colors.ENDC} Status        : {Colors.GREEN}ARP Lock Released{Colors.ENDC}")
            
            self.running = False
            self.manage_lock("unlock")
            
            print(f"\n  {Colors.GREEN}✓ Goodbye! Stay protected! 🛡️{Colors.ENDC}\n")
            sys.exit(0)

if __name__ == "__main__":
    # التحقق من الصلاحيات
    try:
        is_admin = os.getuid() == 0
    except AttributeError:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    
    if not is_admin:
        print(f"\n{Colors.FAIL}{'═'*50}{Colors.ENDC}")
        print(f"{Colors.FAIL}  ✗ ERROR: Administrator privileges required!{Colors.ENDC}")
        print(f"{Colors.FAIL}{'═'*50}{Colors.ENDC}")
        print(f"\n  {Colors.YELLOW}Please run this script as Administrator.{Colors.ENDC}\n")
        sys.exit(1)

    guardian = HostGuardian()
    guardian.start()