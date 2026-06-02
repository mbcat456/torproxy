import asyncio, ctypes, json, os, signal, subprocess, sys, tempfile, threading, time

E = "\033"; R = E+"[0m"; B = E+"[1m"; D = E+"[2m"
CLR = E+"[2J"+E+"[3J"+E+"[H"
HIDE = E+"[?25l"; SHOW = E+"[?25h"
def G(r,g,b,s=""): return f"{E}[{s}38;2;{r};{g};{b}m"
def GO(r,c): return f"{E}[{r};{c}H"
gn = lambda t: G(100,255,100)+t+R; yl = lambda t: G(255,205,55)+t+R
rd = lambda t: G(255,85,85)+t+R;   cy = lambda t: G(65,205,255)+t+R
wh = lambda t: G(225,225,225)+t+R; gy = lambda t: G(115,115,115)+t+R
dg = lambda t: G(65,65,65)+t+R

import re
_ANSI = re.compile(r"\033\[[0-9;]*[a-zA-Z]")
def _vlen(s): return len(_ANSI.sub("", s))
def _center(s, w): return " " * max(0, (w - _vlen(s)) // 2) + s

if sys.platform == "win32":
    k32 = ctypes.windll.kernel32
    h = k32.GetStdHandle(-11); m = ctypes.c_ulong()
    if k32.GetConsoleMode(h,ctypes.byref(m)): k32.SetConsoleMode(h,(m.value|0x0004)&~0x0040)

def _cpu_name():
    if sys.platform == "win32":
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                r"HARDWARE\DESCRIPTION\System\CentralProcessor\0") as k:
                return winreg.QueryValueEx(k,"ProcessorNameString")[0].strip()
        except: pass
    else:
        try:
            with open("/proc/cpuinfo") as f:
                for line in f:
                    if line.startswith("model name"):
                        return line.split(":", 1)[1].strip()
        except: pass
    return "Unknown CPU"

def _ram():
    try:
        if sys.platform == "win32":
            class M(ctypes.Structure):
                _fields_=[("l",ctypes.c_uint32),("ld",ctypes.c_uint32),
                          ("t",ctypes.c_uint64),("a",ctypes.c_uint64),
                          ("_1",ctypes.c_uint64),("_2",ctypes.c_uint64),
                          ("_3",ctypes.c_uint64),("_4",ctypes.c_uint64),
                          ("_5",ctypes.c_uint64)]
            m=M(); m.l=ctypes.sizeof(M)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m))
            return m.t, m.a, m.ld
        else:
            total = avail = 0
            with open("/proc/meminfo") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        total = int(line.split()[1]) * 1024
                    elif line.startswith("MemAvailable:"):
                        avail = int(line.split()[1]) * 1024
                    if total and avail:
                        break
            if total:
                pct = int((1 - avail / total) * 100)
                return total, avail, pct
    except: pass
    return 0, 0, 0

def _pmem():
    try:
        import psutil
        return psutil.Process().memory_info().rss
    except: pass
    if sys.platform == "win32":
        try:
            import ctypes.wintypes
            class P(ctypes.Structure):
                _fields_=[("cb",ctypes.wintypes.DWORD),
                          ("PageFaultCount",ctypes.wintypes.DWORD),
                          ("PeakWorkingSetSize",ctypes.c_size_t),
                          ("WorkingSetSize",ctypes.c_size_t),
                          ("QuotaPeakPagedPoolUsage",ctypes.c_size_t),
                          ("QuotaPagedPoolUsage",ctypes.c_size_t),
                          ("QuotaPeakNonPagedPoolUsage",ctypes.c_size_t),
                          ("QuotaNonPagedPoolUsage",ctypes.c_size_t),
                          ("PagefileUsage",ctypes.c_size_t),
                          ("PeakPagefileUsage",ctypes.c_size_t)]
            p=P(); p.cb=ctypes.sizeof(P)
            try:
                ctypes.windll.kernel32.K32GetProcessMemoryInfo(
                    ctypes.windll.kernel32.GetCurrentProcess(), ctypes.byref(p), p.cb)
            except:
                ctypes.windll.psapi.GetProcessMemoryInfo(
                    ctypes.windll.kernel32.GetCurrentProcess(), ctypes.byref(p), p.cb)
            return p.WorkingSetSize
        except: pass
    else:
        try:
            with open("/proc/self/status") as f:
                for line in f:
                    if line.startswith("VmRSS:"):
                        return int(line.split()[1]) * 1024
        except: pass
    return -1

_cpu_prev = None

def _cpu_pct():
    global _cpu_prev
    try:
        import psutil
        return psutil.cpu_percent(interval=0)
    except: pass

    if sys.platform == "win32":
        try:
            class FT(ctypes.Structure):
                _fields_=[("dwLowDateTime",ctypes.c_uint32),
                          ("dwHighDateTime",ctypes.c_uint32)]
            class ST(ctypes.Structure):
                _fields_=[("lidle",FT),("lkernel",FT),("luser",FT)]
            s=ST(); ctypes.windll.kernel32.GetSystemTimes(
                ctypes.byref(s.lidle),ctypes.byref(s.lkernel),ctypes.byref(s.luser))
            idle = (s.lidle.dwHighDateTime << 32) | s.lidle.dwLowDateTime
            kernel = (s.lkernel.dwHighDateTime << 32) | s.lkernel.dwLowDateTime
            user = (s.luser.dwHighDateTime << 32) | s.luser.dwLowDateTime
            total = kernel + user + idle
            cur = (idle, total)
            if _cpu_prev is None:
                _cpu_prev = cur; return -1
            idle_d = cur[0] - _cpu_prev[0]
            total_d = cur[1] - _cpu_prev[1]
            _cpu_prev = cur
            if total_d > 0: return (1.0 - idle_d / total_d) * 100.0
            return -1
        except: return -1
    else:
        try:
            with open("/proc/stat") as f:
                fields = f.readline().split()
            if fields[0] != "cpu": return -1
            vals = [int(x) for x in fields[1:]]
            total = sum(vals)
            idle = vals[3] + (vals[4] if len(vals) > 4 else 0)
            cur = (idle, total)
            if _cpu_prev is None:
                _cpu_prev = cur; return -1
            idle_d = cur[0] - _cpu_prev[0]
            total_d = cur[1] - _cpu_prev[1]
            _cpu_prev = cur
            if total_d > 0: return (1.0 - idle_d / total_d) * 100.0
            return -1
        except: return -1

CPU = _cpu_name()
CORES = os.cpu_count() or 1

def _fsz(b):
    if b>=1<<30: return f"{b/(1<<30):.1f} GB"
    if b>=1<<20: return f"{b/(1<<20):.0f} MB"
    return f"{b>>10} KB"

def _dur(s):
    if s<60: return f"{int(s)}s"
    if s<3600: return f"{int(s//60)}m {int(s%60)}s"
    return f"{int(s//3600)}h {int((s%3600)//60)}m"

def _bw(bps):
    if bps >= 1e9: return f"{bps/1e9:.1f} Gbps"
    if bps >= 1e6: return f"{bps/1e6:.1f} Mbps"
    if bps >= 1e3: return f"{bps/1e3:.0f} Kbps"
    return f"{bps:.0f} bps"

SF = os.path.join(tempfile.gettempdir(),"torproxy_state.json")
def _rs():
    try:
        with open(SF) as f: return json.load(f)
    except: return None
def _ds():
    try: os.remove(SF)
    except: pass

_kq = None

if sys.platform == "win32":
    import msvcrt

    def _start_keys():
        global _kq
        loop = asyncio.get_running_loop(); _kq = asyncio.Queue()
        def _r():
            while True:
                try: ch = msvcrt.getwch()
                except: break
                try:
                    if ch=="\x1b":
                        loop.call_soon_threadsafe(_kq.put_nowait,"esc")
                    elif ch in "\r\n":
                        loop.call_soon_threadsafe(_kq.put_nowait,"enter")
                    elif ch=="\x08":
                        loop.call_soon_threadsafe(_kq.put_nowait,"bs")
                    elif ch in ("\xe0","\x00"):
                        c2=msvcrt.getwch()
                        m={"H":"up","P":"down","K":"left","M":"right"}
                        loop.call_soon_threadsafe(_kq.put_nowait,m.get(c2,c2))
                    elif ch.isprintable():
                        loop.call_soon_threadsafe(_kq.put_nowait,ch)
                except: pass
        threading.Thread(target=_r,daemon=True).start()
else:
    import termios, tty, select as _select

    def _start_keys():
        global _kq
        loop = asyncio.get_running_loop(); _kq = asyncio.Queue()
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        tty.setraw(fd)
        def _r():
            try:
                while True:
                    try:
                        r, _, _ = _select.select([sys.stdin], [], [], 0.1)
                        if not r: continue
                        ch = sys.stdin.read(1)
                    except: break
                    try:
                        if ch == "\x1b":
                            r2, _, _ = _select.select([sys.stdin], [], [], 0.0)
                            if r2:
                                nxt = sys.stdin.read(1)
                                if nxt == "[":
                                    csi = ""
                                    while True:
                                        r3, _, _ = _select.select([sys.stdin], [], [], 0.0)
                                        if r3:
                                            c = sys.stdin.read(1)
                                            csi += c
                                            if c.isalpha() or c == "~":
                                                break
                                        else:
                                            break
                                    m = {"A":"up","B":"down","C":"right","D":"left",
                                         "H":"home","F":"end"}
                                    loop.call_soon_threadsafe(_kq.put_nowait,m.get(csi, "esc"))
                                else:
                                    loop.call_soon_threadsafe(_kq.put_nowait,"esc")
                            else:
                                loop.call_soon_threadsafe(_kq.put_nowait,"esc")
                        elif ch in "\r\n":
                            loop.call_soon_threadsafe(_kq.put_nowait,"enter")
                        elif ch == "\x7f" or ch == "\x08":
                            loop.call_soon_threadsafe(_kq.put_nowait,"bs")
                        elif ch.isprintable():
                            loop.call_soon_threadsafe(_kq.put_nowait,ch)
                    except: pass
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old)
        threading.Thread(target=_r,daemon=True).start()

async def _key(to=None):
    if not _kq: _start_keys()
    t = asyncio.ensure_future(_kq.get())
    if to:
        s = asyncio.ensure_future(asyncio.sleep(to))
        d,p = await asyncio.wait([t,s],return_when=asyncio.FIRST_COMPLETED)
        for x in p: x.cancel()
        return t.result() if t in d else None
    return await t

async def run():
    sys.stdout.write(HIDE)
    child = None; started = 0.0; child_pid = 0; target = 0
    launch_msg = ""
    cached_ram = (0,0,0); cached_pmem = -1; cached_cpu = -1.0
    last_ram = 0.0; last_fast = 0.0
    last_bytes_up = 0; last_bytes_down = 0; last_bytes_time = 0.0
    bw_up = "0 Kbps"; bw_down = "0 Kbps"

    si = asyncio.Event()

    def _on_sigint(*_):
        si._loop.call_soon_threadsafe(si.set)

    signal.signal(signal.SIGINT, _on_sigint)
    si._loop = asyncio.get_running_loop()

    try:
        while True:
            ts = os.get_terminal_size(); W,H = ts.columns, ts.lines
            s = _rs()
            ut = time.monotonic() - started if started else 0
            now = time.monotonic()
            if now - last_ram > 10:
                cached_ram = _ram(); last_ram = now
            if now - last_fast > 1.0:
                cached_pmem = _pmem(); cached_cpu = _cpu_pct(); last_fast = now
            ram_t, ram_a, ram_p = cached_ram
            ram_used = ram_t - ram_a if ram_t else 0
            pm = cached_pmem

            out = [CLR]

            cpu_raw = CPU.replace(" Processor","").replace("processor","")[:30]
            cpu_line = dg(cpu_raw)
            cpu_str = f"{cached_cpu:.0f}%" if cached_cpu >= 0 else "--%"
            ram_line = gy(_fsz(ram_used)) + dg("/") + gy(_fsz(ram_t)) + dg(" · ") + gy(f"{cpu_str} cpu usage")
            title_line = B + "TorProxy" + R + " " + dg("v1.6")

            L = min(_vlen(cpu_line) + 3, 35)
            rw = _vlen(ram_line) + 2
            rx = W - rw
            mid_area = rx - L - 1
            title_x = L + 1 + (mid_area - _vlen(title_line)) // 2

            out.append(GO(1, 1) + cpu_line)
            out.append(GO(1, L) + dg(" │ "))
            out.append(GO(1, title_x) + title_line)
            out.append(GO(1, rx) + dg(" │ "))
            out.append(GO(1, rx + 3) + ram_line)

            out.append(GO(2, 0) + dg("─" * (W-1)))

            mid = max(H//2 - 3, 5)
            if s:
                dot = gn("●") if s.get("num_circuits",0) > 0 else yl("○")
                host = s.get("host","127.0.0.1"); port = s.get("port",8080)
                count = s.get("num_circuits",0); noauth = s.get("no_auth",False)
                uname = s.get("username",""); pwd = s.get("password","")
                pid_str = str(child_pid or s.get("pid",0))

                addr = f"{dot}  {gy(f'{host}:{port}')}  {dg(f'PID {pid_str}')}"
                out.append(GO(mid,0) + _center(addr, W))
                circ = f"Circuits: {gn(str(count))}"
                if target: circ += f" {dg(f'/ {target}')}"
                out.append(GO(mid+1,0) + _center(circ, W))
                bu = s.get("bytes_up",0); bd = s.get("bytes_down",0)
                if last_bytes_time == 0:
                    last_bytes_up = bu; last_bytes_down = bd; last_bytes_time = now
                elif now - last_bytes_time > 0.8:
                    du = now - last_bytes_time
                    bw_up = _bw(max(0, (bu - last_bytes_up) / du * 8))
                    bw_down = _bw(max(0, (bd - last_bytes_down) / du * 8))
                    last_bytes_up = bu; last_bytes_down = bd; last_bytes_time = now
                total_up = _fsz(bu); total_down = _fsz(bd)
                traffic = f"{dg('▲')} {cy(bw_up)} {dg('▼')} {cy(bw_down)}    {dg('▲')} {gy(total_up)}  {dg('▼')} {gy(total_down)}"
                out.append(GO(mid+2,0) + _center(traffic, W))
                if ut > 0:
                    ut_str = f"Uptime: {dg(_dur(ut))}"
                    out.append(GO(mid+3,0) + _center(ut_str, W))
                if not noauth and uname:
                    cr = f"{dg(uname)} : {dg(pwd)}"
                    out.append(GO(mid+4,0) + _center(cr, W))
                keys = f"{dg('[G]')} Generate    {dg('[T]')} Terminate    {dg('[Q]')} Quit"
                out.append(GO(mid+6,0) + _center(keys, W))
                if launch_msg:
                    out.append(GO(mid-2,0) + _center(launch_msg, W))
            else:
                out.append(GO(mid,0) + _center(rd("Proxy not running"), W))
                keys = f"{dg('[L]')} Launch    {dg('[G]')} Generate    {dg('[Q]')} Quit"
                out.append(GO(mid+2,0) + _center(keys, W))
                if launch_msg:
                    out.append(GO(mid-2,0) + _center(launch_msg, W))

            pm_str = _fsz(pm) if pm > 0 else "N/A"
            out.append(GO(H, 1) + dg(f"PID {os.getpid()}  {pm_str}  Python"))
            out.append(GO(H, W-20) + dg(f"{CORES} threads"))

            sys.stdout.write("".join(out)); sys.stdout.flush()

            launch_msg = ""

            k = await _key(to=1.0)
            if k is None: continue
            if k == "esc": continue

            running = s is not None

            if si.is_set():
                si.clear()
                if running:
                    for _ in range(8):
                        dlg = f"{yl('Stop proxy?')}  {dg('[Y]')} Yes   {dg('[N]')} Keep in bg   {dg('[Esc]')} Cancel"
                        sys.stdout.write(GO(H//2,0) + _center(dlg, W)); sys.stdout.flush()
                        k2 = await _key()
                        if k2 == "esc" or k2 is None: break
                        if k2 == "y":
                            if child: child.terminate(); child.wait(timeout=5)
                            _ds(); sys.stdout.write(SHOW); return
                        if k2 == "n":
                            bg_pid = child_pid or (s.get("pid",0) if s else 0)
                            sys.stdout.write(f"{CLR}{GO(H//2,W//2-20)}{gn('Proxy running in bg. PID '+str(bg_pid))}")
                            sys.stdout.flush()
                            sys.stdout.write(GO(H-1,0) + dg("Auto-closing in 5s...")); sys.stdout.flush()
                            await asyncio.sleep(5)
                            sys.stdout.write(SHOW); return
                    continue
                else:
                    break

            if k == "q":
                if running:
                    for _ in range(5):
                        dlg = f"{yl('Stop proxy and quit?')}  {dg('[Y]')} Stop   {dg('[N]')} Keep in bg   {dg('[Esc]')} Cancel"
                        out2 = [GO(H//2,0) + _center(dlg, W)]
                        sys.stdout.write("".join(out2)); sys.stdout.flush()
                        k2 = await _key()
                        if k2 == "esc" or k2 is None: break
                        if k2 == "y":
                            if child: child.terminate(); child.wait(timeout=5)
                            _ds(); sys.stdout.write(SHOW); return
                        if k2 == "n":
                            bg_pid = child_pid or s.get("pid",0)
                            sys.stdout.write(f"{CLR}{GO(H//2,W//2-20)}{gn('Proxy running in background. PID '+str(bg_pid))}")
                            sys.stdout.flush()
                            sys.stdout.write(GO(H-1,0) + dg("Auto-closing in 5s...")); sys.stdout.flush()
                            await asyncio.sleep(5)
                            sys.stdout.write(SHOW); return
                    continue
                else:
                    break

            elif k == "l" and not running:
                if target == 0:
                    fetch_start = time.monotonic()
                    loop = asyncio.get_running_loop()
                    progress = ["Fetching consensus..."]
                    def _progress(msg):
                        progress[0] = msg
                    def _do_fetch():
                        from torproxy.consensus import fetch_fresh_consensus, load_relays
                        base = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
                        cpath = os.path.join(base,"shared_cache","cached-microdesc-consensus")
                        mpath = os.path.join(base,"shared_cache","cached-microdescs")
                        ok = fetch_fresh_consensus(cpath, mpath, progress_callback=_progress)
                        if ok:
                            relays = load_relays(cpath, mpath)
                            exits = [r for r in relays if r.is_exit()]
                            return ("ok", len(set(r.ip for r in exits)))
                        return ("fail", None)
                    ff = loop.run_in_executor(None, _do_fetch)
                    while not ff.done():
                        elapsed = time.monotonic() - fetch_start
                        sp = "|/-\\"[int(elapsed * 4) % 4]
                        display = cy(f"{sp}  {progress[0]}")
                        sys.stdout.write(GO(mid-2,0) + _center(display, W) + "\033[K"); sys.stdout.flush()
                        await asyncio.sleep(0.15)
                    try:
                        result = ff.result()
                        if result[0] == "ok":
                            target = result[1]
                            launch_msg = gn(f"Fetched: {target} unique exit IPs")
                        else:
                            launch_msg = yl("Consensus fetch failed, launching anyway...")
                    except Exception as e:
                        launch_msg = yl(f"Fetch error: {str(e)[:40]}, launching anyway...")
                    sys.stdout.write(GO(mid-2,0) + _center(launch_msg, W)); sys.stdout.flush()
                    await asyncio.sleep(0.8)
                launch_msg = cy("Building circuits...")
                sys.stdout.write(GO(mid-2,0) + _center(launch_msg, W)); sys.stdout.flush()
                child = subprocess.Popen(
                    [sys.executable,"-m","torproxy","--headless","--child"],
                    stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                child_pid = child.pid; started = time.monotonic()
                for _ in range(40):
                    await asyncio.sleep(0.5)
                    ns = _rs()
                    if ns and ns.get("num_circuits",0) > 0: break
                    if child.poll() is not None:
                        launch_msg = rd("Child process died")
                        child = None; child_pid = 0; started = 0
                        break
                else:
                    launch_msg = yl("Still building...")

            elif k == "g":
                import uuid
                host = s.get("host","127.0.0.1") if s else "127.0.0.1"
                port = s.get("port",8080) if s else 8080
                uname = s.get("username","") if s else ""
                pwd = s.get("password","") if s else ""

                mode_msg = f"{gy('[R]')} Rotating (new IP each request)    {gy('[S]')} Sticky (same IP per session)"
                sys.stdout.write(GO(H//2,0) + _center(mode_msg, W)); sys.stdout.flush()
                mode = None
                while mode is None:
                    mk = await _key()
                    if mk == "r": mode = "rotating"; break
                    if mk == "s": mode = "sticky"; break
                    if mk == "esc": mode = "cancel"; break

                if mode == "cancel": continue

                ttl = 30
                if mode == "sticky":
                    ttl_msg = f"{gy('Session TTL in minutes? [30] (0 = unlimited)')}"
                    sys.stdout.write(GO(H//2+1,0) + _center(ttl_msg, W))
                    sys.stdout.write(GO(H//2+2,0) + "\033[2K"); sys.stdout.flush()
                    raw = ""
                    while True:
                        ak = await _key()
                        if ak == "enter": break
                        if ak == "esc": mode = "cancel"; break
                        if ak == "bs": raw = raw[:-1]
                        elif isinstance(ak,str) and ak.isdigit(): raw += ak
                        sys.stdout.write(GO(H//2+2,0) + "\033[2K" + _center(raw if raw else "30", W))
                        sys.stdout.flush()
                    if mode == "cancel": continue
                    ttl = int(raw) if raw else 30

                amt_msg = f"{gy('How many? [100]')}"
                row = H//2 + (3 if mode == "sticky" else 1)
                sys.stdout.write(GO(row,0) + _center(amt_msg, W))
                sys.stdout.write(GO(row+1,0) + "\033[2K"); sys.stdout.flush()
                raw = ""
                while True:
                    ak = await _key()
                    if ak == "enter": break
                    if ak == "esc": mode = "cancel"; break
                    if ak == "bs": raw = raw[:-1]
                    elif isinstance(ak,str) and ak.isdigit(): raw += ak
                    sys.stdout.write(GO(row+1,0) + "\033[2K" + _center(raw if raw else "100", W))
                    sys.stdout.flush()
                if mode == "cancel": continue
                count = int(raw) if raw else 100

                lines = []
                for i in range(count):
                    if mode == "sticky":
                        sid = uuid.uuid4().hex[:12]
                        ttl_suffix = f"-time-{ttl}" if ttl > 0 else ""
                        line = f"http://{uname}-session-{sid}{ttl_suffix}:{pwd}@{host}:{port}"
                    else:
                        line = f"http://{uname}:{pwd}@{host}:{port}"
                    lines.append(line)

                fname = f"proxies_{uuid.uuid4().hex[:8]}.txt"
                fpath = ""
                def _file_dialog():
                    try:
                        import tkinter as tk
                        from tkinter import filedialog
                        root = tk.Tk(); root.withdraw()
                        root.attributes("-topmost", True)
                        path = filedialog.asksaveasfilename(
                            initialfile=fname, title="Save Proxy List",
                            filetypes=[("Text files","*.txt"),("All files","*.*")])
                        root.destroy()
                        return path if path else ""
                    except: return ""
                fpath = await asyncio.get_running_loop().run_in_executor(None, _file_dialog)
                if not fpath:
                    dl = os.path.join(os.path.expanduser("~"), "Downloads")
                    if not os.path.isdir(dl): dl = os.getcwd()
                    fpath = os.path.join(dl, fname)
                with open(fpath,"w") as f: f.write("\n".join(lines)+"\n")
                launch_msg = gn(f"Saved: {fpath} ({count} {mode})")

            elif k == "t" and running:
                if child: child.terminate(); child.wait(timeout=5)
                elif s:
                    try: os.kill(s["pid"], 9)
                    except: pass
                child = None; child_pid = 0; started = 0; target = 0; _ds()

    except KeyboardInterrupt:
        pass
    finally:
        sys.stdout.write(SHOW + "\n")
        if child:
            child.terminate()
            try: child.wait(timeout=3)
            except: child.kill()
        _ds()
        sys.stdout.write("\n"); sys.stdout.flush()

if __name__ == "__main__":
    asyncio.run(run())
