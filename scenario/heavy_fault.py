"""Heavy fault injection: push PAST thresholds on purpose.

  0:00-0:45  BASELINE  idle server only → expect silence
  0:45-3:15  HEAVY     8x cpu burn (all cores) + ~3GB touched allocation
                       (spills to swap: ACTIVE paging) + 2x TCP blast
                       → expect CPU>90 + RAM>90 + pgout spike in ONE window,
                          retrans flat (loopback) → network quiet
  3:15-4:15  RECOVERY  release everything → silence must return

Sized for a 7.7GB box (leave swap headroom; never threaten OOM).
"""
import ctypes, socket, threading, time, os
import multiprocessing as mp

libc = ctypes.CDLL("libc.so.6", use_errno=True)
libc.malloc.restype = ctypes.c_void_p
libc.memset.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_size_t]

stop = False
phase = ["BASELINE"]
t0 = time.time()
hold = []

def el():
    return time.time() - t0

def log(msg):
    print(f"[{el():6.1f}s][{phase[0]}] {msg}", flush=True)

def burn():
    x = 0
    while not stop:
        x += 1

def burn_proc(stop_ev):
    # Separate PROCESS: Python threads share one GIL (~1 core); processes
    # actually saturate all cores. This is what pushes CPU past 90%.
    x = 0
    while not stop_ev.is_set():
        x += 1

def server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 18925))
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

def blast(mb=150):
    try:
        s = socket.create_connection(("127.0.0.1", 18925), timeout=10)
        chunk = b"z" * 65536
        sent = 0
        while sent < mb * 1024 * 1024:
            s.sendall(chunk)
            sent += len(chunk)
        s.close()
    except OSError as e:
        log(f"blast err {e}")

print(f"PID={os.getpid()}", flush=True)
threading.Thread(target=server, daemon=True).start()
log("baseline: idle")

time.sleep(45)
phase[0] = "HEAVY"
log("FAULT ON: 8x burn PROCESSES + 3GB touched + blasts")
stop_ev = mp.Event()
burners = [mp.Process(target=burn_proc, args=(stop_ev,)) for _ in range(8)]
[p.start() for p in burners]
for i in range(12):  # 12 x 256MB = 3GB
    p = libc.malloc(256 * 1024 * 1024)
    if p:
        libc.memset(p, 0xCD, 256 * 1024 * 1024)
        hold.append(p)
    time.sleep(0.4)
log(f"holding {len(hold)*256}MB native; blasting")
threading.Thread(target=blast, args=(150,), daemon=True).start()
time.sleep(50)
threading.Thread(target=blast, args=(150,), daemon=True).start()

time.sleep(60)
phase[0] = "RECOVERY"
log("releasing all native buffers + stopping burners")
hold.clear()
import gc; gc.collect()
stop_ev.set()
for p in burners:
    p.join(timeout=5)
stop = True
time.sleep(60)
log("done")
