"""Production-like composite scenario with a documented incident timeline.

Simulates one AI-agent worker node: inference-ish matmul churn (CPU),
KV-cache-like growth + a slow native leak through ctypes (FFI blind spot),
and bursty egress traffic (TCP). Phases (accelerated ~12x vs prod):

  0:00-3:00  BASELINE   light ripple only → expect near-silence (FP check)
  3:00-8:00  SLOW LEAK  +1MB/2s native leak + moderate CPU waves → FFI story
  8:00-10:00 COMPOSITE  CPU burn + fast churn + TCP blast together → all
                        detectors must fire inside ONE window (the story test)
  10:00-12:00 RECOVERY  everything stops → alerts must go quiet again

Prints PHASE markers + own PID (for ffi-track) to stdout.
"""
import ctypes, socket, threading, time, sys

libc = ctypes.CDLL("libc.so.6", use_errno=True)
libc.malloc.restype = ctypes.c_void_p
libc.memset.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_size_t]

stop = False
phase = ["BASELINE"]
leak_ptrs = []
t0 = time.time()

def el():
    return time.time() - t0

def log(msg):
    print(f"[{el():6.1f}s][{phase[0]}] {msg}", flush=True)

def cpu_wave():
    x = 0
    while not stop:
        # moderate wave: busy 300ms, idle 700ms
        t = time.time()
        while time.time() - t < 0.3:
            x += 1
            if x > 5_000_000:
                x = 0
        time.sleep(0.7)

def cpu_burn():
    x = 0
    while not stop:
        x += 1

def slow_leak():
    while not stop:
        p = libc.malloc(1 * 1024 * 1024)
        if p:
            libc.memset(p, 0xAB, 1 * 1024 * 1024)
            leak_ptrs.append(p)
        time.sleep(2.0)

def tcp_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 18924))
    srv.listen(8)
    srv.settimeout(0.5)
    while not stop:
        try:
            c, _ = srv.accept()
            threading.Thread(target=lambda: drain(c), daemon=True).start()
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

def tcp_blast(mb=150):
    try:
        s = socket.create_connection(("127.0.0.1", 18924), timeout=5)
        chunk = b"y" * 65536
        sent = 0
        while sent < mb * 1024 * 1024:
            s.sendall(chunk)
            sent += len(chunk)
        s.close()
    except OSError as e:
        log(f"blast err {e}")

print(f"PID={__import__('os').getpid()}", flush=True)
threading.Thread(target=tcp_server, daemon=True).start()
waves = [threading.Thread(target=cpu_wave, daemon=True) for _ in range(2)]
[t.start() for t in waves]
log("baseline ripple on (2x wave threads)")

time.sleep(180)
phase[0] = "SLOW LEAK"
log("starting +1MB/2s native leak + keep waves")
threading.Thread(target=slow_leak, daemon=True).start()

time.sleep(300)
phase[0] = "COMPOSITE"
log("INCIDENT: cpu burn x4 + fast churn + tcp blast x2 (expect ONE window, full story)")
burners = [threading.Thread(target=cpu_burn, daemon=True) for _ in range(4)]
[t.start() for t in burners]
threading.Thread(target=tcp_blast, args=(150,), daemon=True).start()
time.sleep(40)
threading.Thread(target=tcp_blast, args=(150,), daemon=True).start()

time.sleep(80)
phase[0] = "RECOVERY"
log("stopping all load — alerts must go quiet again")
stop = True
time.sleep(120)
log("done")
