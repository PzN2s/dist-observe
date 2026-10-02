"""5-hour production-like load: gentle waves + very slow native leak with a
composite burst every 30 minutes. Prints PHASE markers + PID. Leak budget:
1MB/30s ≈ 600MB over 5h — visible to ffi-track, never OOM-threatening."""
import ctypes, socket, threading, time, os
import multiprocessing as mp

libc = ctypes.CDLL("libc.so.6", use_errno=True)
libc.malloc.restype = ctypes.c_void_p
libc.memset.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_size_t]

stop = False
phase = ["CRUISE"]
t0 = time.time()
hold = []

def el():
    return time.time() - t0

def log(msg):
    print(f"[{el():7.1f}s][{phase[0]}] {msg}", flush=True)

def wave():
    x = 0
    while not stop:
        t = time.time()
        while time.time() - t < 0.25:
            x = (x + 1) % 5_000_000
        time.sleep(0.75)

def burn_proc(ev):
    x = 0
    while not ev.is_set():
        x += 1

def server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 18926))
    srv.listen(8)
    srv.settimeout(0.5)
    while not stop:
        try:
            c, _ = srv.accept()
            threading.Thread(target=drain, args=(c,), daemon=True).start()
        except socket.timeout:
            pass

def drain(c):
    try:
        while c.recv(65536):
            pass
    except OSError:
        pass
    finally:
        c.close()

def blast(mb=120):
    try:
        s = socket.create_connection(("127.0.0.1", 18926), timeout=10)
        chunk = b"q" * 65536
        sent = 0
        while sent < mb * 1024 * 1024:
            s.sendall(chunk)
            sent += len(chunk)
        s.close()
    except OSError as e:
        log(f"blast err {e}")

print(f"PID={os.getpid()}", flush=True)
threading.Thread(target=server, daemon=True).start()
for _ in range(2):
    threading.Thread(target=wave, daemon=True).start()
log("cruise: ripple + 1MB/30s native leak")

DUR = 5 * 3600
BURST_EVERY = 1800
next_burst = BURST_EVERY
t_end = t0 + DUR
n = 0
while time.time() < t_end and not stop:
    # slow leak tick
    p = libc.malloc(1024 * 1024)
    if p:
        libc.memset(p, 0xAB, 1024 * 1024)
        hold.append(p)
    if time.time() >= t0 + next_burst:
        n += 1
        phase[0] = f"BURST-{n}"
        log(f"composite burst {n}: 6x burn + blast (2 min)")
        ev = mp.Event()
        ps = [mp.Process(target=burn_proc, args=(ev,)) for _ in range(6)]
        [x.start() for x in ps]
        threading.Thread(target=blast, args=(120,), daemon=True).start()
        time.sleep(120)
        ev.set()
        [x.join(timeout=10) for x in ps]
        phase[0] = "CRUISE"
        log(f"burst {n} over, back to cruise (leaked {len(hold)}MB)")
        next_burst += BURST_EVERY
    time.sleep(30)

log(f"soak complete ({len(hold)}MB leaked total)")
