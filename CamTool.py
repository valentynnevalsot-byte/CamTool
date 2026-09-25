#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CamTool v1.2 — LAN Camera Security Audit Toolkit
=================================================
Legit audit only. Use on networks you own / are authorized to test.
"""

import os, sys, socket, subprocess, threading, ipaddress, shutil, time
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib.request, urllib.error, base64

# ---------- Vzhled ----------
if shutil.which("tput"):
    try:
        subprocess.run(["tput","initc"], capture_output=True)  # noop
    except Exception:
        pass

GREEN="\033[92m"; RED="\033[91m"; YEL="\033[93m"; CYAN="\033[96m"
MAG="\033[95m";  BOLD="\033[1m"; DIM="\033[2m"; END="\033[0m"

BANNER = r"""
                             .:-=*#%%%#%%#=.
                     .::-+*#%%%#*+=:..  .-#@%-.
              .:-=+*#%%%#*+=::.            .+@@+:...
       ..-=+*#%%%#*+=-:..                     =@@*:...
..:=+*#%%%#*+=-:...                            .=@@*-.
:-+*%@@@#+=:::..                                  -@@-
:+#%@@%%###%%%%#+:                              ..=@@.
#@*-:.      .-*%%+:                      .:=*#%%@@*=.
+@:  .. .:-=+*--#@%=...          .:-+*%%%#*=-: -#:
-#.  :. :%%#**+=-:::+%@@%+=.. .:=+#%%%#*=:.   .@#:.
:@+  :  #@.=*==++**+=:-*@@=. .:-=*#%%%#+-:.   .@*
.+@- .. =@-=@++*@@%%@#=-:=%@#+*#%%#*+-.      *@-
  #@:  :  @%.@#+%@=..*@*++:.+**=:.         .=@@=
   #@#%#**: +@:+@+*@@=.%@*++=.@% .    :=*%%%#+.
    --:::::.:@#.@*+*@#.+@#+++:+@- =  @@#*=-:.....
       ...:::#@:+@+*@@%%@@*++=.@% -: +@*:::...
      .  ...=@*.@#+**+===----=@% -- :+#@@+:::.:::.....
          ..::+@*=+=++**#######= .=:.. -@@*=:::::=%@%%%%%%+.
               .+***++=--::.....:-:. :-. -@*--::::-@@.  .  =@+.
                   ...:::::::......-@-    *@+-:::-+%@+    .@*..
                    .      ....::-#@%#: .@@+=+*%%%*=:... .@+.
                              ....::-*@@= .%@%%#+=::...  :#+.
                                ...:@@*#=::.  ....:..   .@*
                                 ..:@@       :-+#+.:    @*..
                                   .@@.   :=+#%%%#*@%.  :%=
                                    +@#+==----+%@#+=:.  .+*+=====:
                    .::.      .:::. :+########=:..
"""

B  = f"{MAG}{BANNER}{END}"
DIV= f"{CYAN}{'─'*64}{END}"
BOX= f"{CYAN}╔══════════════════════════════════════════════════════════════╗\n║{END}{{:^60}}{CYAN}║\n╚══════════════════════════════════════════════════════════════╝{END}"

def box(title):
    print(f"{CYAN}╔{'═'*62}╗\n║{END} {MAG}{BOLD}{title:<60}{END}{CYAN}║\n╚{'═'*62}╝{END}")

def info(msg):   print(f"  {CYAN}[•]{END} {msg}")
def ok(msg):     print(f"  {GREEN}[✔]{END} {msg}")
def warn(msg):   print(f"  {YEL}[!]{END} {msg}")
def fail(msg):   print(f"  {RED}[✘]{END} {msg}")
def crit(msg):   print(f"  {RED}{BOLD}[!!!]{END} {msg}")

FOUND=[]          # (ip, port, service)
LOCK=threading.Lock()

PORTS=[80,443,554,8000,8006,8080,8554,8899,37777,34567]
SERV={80:"HTTP",443:"HTTPS",554:"RTSP",8899:"ONVIF",8000:"HTTP-alt",
      8080:"HTTP-proxy",8554:"RTSP-alt",37777:"Dahua",8006:"Hikvision",34567:"Hikvision-alt"}

# ---------- Helpery ----------

def check_root():
    if hasattr(os,"geteuid") and os.geteuid()!=0:
        fail("Spust s sudo:  sudo python3 camtool.py"); sys.exit(1)

def get_cidr():
    try:
        out=subprocess.check_output(["ip","route"], text=True, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            tok=line.split()
            if tok and "/" in tok[0]:
                try:
                    n=ipaddress.ip_network(tok[0], strict=False)
                    if not str(n).startswith("127."):
                        return str(n)
                except ValueError: pass
    except Exception: pass
    try:
        s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("8.8.8.8",80))
        myip=s.getsockname()[0]; s.close()
        return str(ipaddress.ip_network(myip+"/24", strict=False))
    except Exception: return None

def tcp_probe(ip, port, timeout=1.0):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((ip,port))==0
    except OSError: return False

def banner_grab(ip, port, timeout=2.0):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout); s.connect((ip,port))
            s.sendall(f"GET / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
            data=s.recv(2048).decode(errors="ignore")
            for line in data.splitlines():
                if line.lower().startswith("server:"):
                    return line.split(":",1)[1].strip()
            return data[:80].replace("\n"," ").strip()
    except OSError: return ""

DEFAULT_CREDS=[("admin","admin"),("admin","12345"),("admin","123456"),("admin",""),
               ("admin","password"),("admin","admin123"),("root","root"),("root","pass"),
               ("666666","666666"),("888888","888888"),("service","service")]

def test_default_creds(ip):
    warn(f"Testuji default hesla na {ip} ...")
    for user,pw in DEFAULT_CREDS:
        try:
            req=urllib.request.Request(f"http://{ip}/")
            req.add_header("Authorization","Basic "+base64.b64encode(f"{user}:{pw}".encode()).decode())
            urllib.request.urlopen(req, timeout=3)
            crit(f"SLABÉ PŘIHLÁŠKY: {user}:{pw} na {ip}")
            return True
        except urllib.error.HTTPError as e:
            if e.code!=401:
                crit(f"SLABÉ PŘIHLÁŠKY: {user}:{pw} na {ip} (HTTP {e.code})")
                return True
        except Exception: continue
    ok(f"Default hesla nefungují na {ip}")
    return False

def test_open_rtsp(ip):
    warn(f"RTSP test na {ip}:554 ...")
    for path in ["/","/stream1","/live/ch0","/cam/realmonitor?channel=1&subtype=0"]:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3); s.connect((ip,554))
                s.sendall(f"DESCRIBE rtsp://{ip}{path} RTSP/1.0\r\nCSeq: 1\r\n\r\n".encode())
                resp=s.recv(512).decode(errors="ignore")
                first=resp.splitlines()[0] if resp else ""
                code=first.split(" ")[1] if " " in first else ""
                if code=="200":
                    crit(f"OTEVŘENÝ RTSP (bez hesla): rtsp://{ip}{path}")
                    return True
                if code=="401":
                    ok(f"RTSP vyžaduje heslo (OK)")
                    return False
        except OSError: continue
    info("Žádná RTSP odpověď")
    return False

def vendor_from_banner(b):
    bl=b.lower()
    if "hikvision" in bl: return "Hikvision"
    if "dahua"   in bl: return "Dahua"
    if "axis"    in bl: return "Axis"
    if "ubiquiti" in bl: return "Ubiquiti"
    if "bosch"   in bl: return "Bosch"
    if "milesight" in bl: return "Milesight"
    if "goke"    in bl: return "Goke"
    if "hipcam"  in bl: return "Hipcam/Anyka"
    return "Unknown"

def scan_host(ip):
    try: ipaddress.ip_address(ip)
    except ValueError: return
    open_ports=[p for p in PORTS if tcp_probe(ip,p)]
    if open_ports:
        with LOCK:
            for p in open_ports:
                FOUND.append((ip,p,SERV.get(p,"?")))
        return
    # progress only for empty hosts
    print(f"\r{DIM}    scanning {ip:<16}{END}", end="", flush=True)

# ---------- Menu akce ----------

def action_word_cam():
    box("WORD CAM — Discovery")
    cidr=get_cidr()
    if not cidr:
        warn("Nepodařilo se zjistit subnet.")
        cidr=input("  subnet (např. 192.168.1.0/24) > ").strip()
    try: net=ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        fail("Špatný formát subnetu."); return
    info(f"Síť: {MAG}{cidr}{END}")
    info(f"Porty: {PORTS}")
    print(f"  {CYAN}{'─'*60}{END}")
    FOUND.clear()
    hosts=[str(h) for h in net.hosts()]
    t0=time.time()
    with ThreadPoolExecutor(max_workers=100) as ex:
        futs=[ex.submit(scan_host,ip) for ip in hosts]
        for f in as_completed(futs): f.result()
    dt=time.time()-t0
    print(f"\r{' '*40}\r", end="")  # smazat progress řádek
    ips=sorted(set(x[0] for x in FOUND))
    print(f"\n{CYAN}  {'─'*60}{END}")
    if not ips:
        warn(f"Žádní kameroví hostitelé (sken trval {dt:.1f}s)."); return
    ok(f"Nalezeno {len(ips)} hostitelů za {dt:.1f}s")
    print(f"  {'IP':<17}{'PORT':<7}{'SLUŽBA':<16}{'VÝROBCE'}")
    print(f"  {CYAN}{'─'*60}{END}")
    for ip,p,svc in sorted(FOUND, key=lambda x:(x[0],x[1])):
        b=banner_grab(ip,p)
        v=vendor_from_banner(b) if b else "?"
        print(f"  {GREEN}{ip:<17}{END}{p:<7}{svc:<16}{MAG}{v}{END}")

def action_cam_ip():
    box("CAMERA IP — Detail Audit")
    if not FOUND:
        warn("Nejprve spusť volbu 1 (Word Cam)."); return
    for ip in sorted(set(x[0] for x in FOUND)):
        print(f"\n  {MAG}{BOLD}▶ {ip}{END}")
        print(f"  {CYAN}{'─'*58}{END}")
        for ip2,p,svc in [x for x in FOUND if x[0]==ip]:
            b=banner_grab(ip2,p)
            if b: info(f"Port {p} ({svc}): {YEL}{b}{END}")
        weak=test_default_creds(ip)
        if tcp_probe(ip,554):
            test_open_rtsp(ip)
        print()

def action_phone_cam():
    box("PHONE CAM — Local devices")
    if not os.path.isdir("/dev"):
        fail("Není /dev — jen na Linuxu."); return
    devs=[d for d in os.listdir("/dev") if d.startswith("video")]
    if not devs:
        warn("Žádná /dev/video* zařízení."); return
    for d in sorted(devs):
        ok(f"/dev/{d}")
        subprocess.run(["v4l2-ctl","-d",f"/dev/{d}","--info"])

def action_update_system():
    box("UPDATE SYSTEM")
    subprocess.run("apt update && apt upgrade -y", shell=True)

def action_info_tool():
    box("INFO TOOL")
    subprocess.run("uname -a; echo; ip -br addr; echo; ip route | head -5", shell=True)

MENU=f"""
{DIV}
 {BOLD}CAMTOOL v1.2{END}  {DIM}— LAN Camera Security Audit{END}
{DIV}
  {MAG}1{END}. Word Cam      {DIM}scan LAN pro kamery{END}
  {MAG}2{END}. Camera IP     {DIM}banner + default-creds + RTSP audit{END}
  {MAG}3{END}. Phone Cam     {DIM}lokální kamery (/dev/video*){END}
  {MAG}4{END}. Update system
  {MAG}5{END}. Info tool
  {MAG}6{END}. Exit
{DIV}
"""

def main():
    check_root()
    print(B)
    print(f"{CYAN}{BOLD}      CAMTOOL v1.2{END} {DIM}— LAN Camera Security Audit{END}")
    print(f"{DIM}  Používej jen na sítích, které vlastníš / máš autorizaci testovat.{END}\n")
    while True:
        print(MENU)
        try:
            c=input(f"  {GREEN}{BOLD}camtool{END} {DIM}▶{END} ").strip()
        except (KeyboardInterrupt, EOFError):
            print(f"\n  {GREEN}[*] Bye.{END}"); sys.exit(0)
        print()
        try:
            if   c=="1": action_word_cam()
            elif c=="2": action_cam_ip()
            elif c=="3": action_phone_cam()
            elif c=="4": action_update_system()
            elif c=="5": action_info_tool()
            elif c=="6": print(f"  {GREEN}[*] Bye.{END}"); sys.exit(0)
            else: fail("Neplatná volba.")
        except KeyboardInterrupt:
            print(f"\n  {YEL}[*] Přerušeno.{END}")
        except Exception as e:
            fail(f"Chyba: {e}")

if __name__=="__main__":
    main()
