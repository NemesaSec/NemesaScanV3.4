import socket
import threading
import queue
import time
import datetime
import os
import sys

DEFAULT_THREADS = 120
SMART_PORTS = [21,22,23,25,53,67,68,80,110,123,135,139,143,161,443,445,465,514,587,631,993,995,1433,1521,2049,3306,3389,5900,8080]

def clear():
    try: os.system("clear")
    except: pass

def header():
    print("===================================")
    print("         NemesaScan V3.4")
    print("===================================\n")

def logo_anim(t):
    frames=["NemesaScan V3.4"," NemesaScan V3.4.","  NemesaScan V3.4..","   NemesaScan V3.4..."]
    end=time.time()+t
    i=0
    while time.time()<end:
        sys.stdout.write("\r"+frames[i%4])
        sys.stdout.flush()
        time.sleep(0.15)
        i+=1
    sys.stdout.write("\r"+" "*40+"\r")

def build_queue(startp,endp,smart=False):
    q=queue.Queue()
    used=set()
    if smart:
        for p in SMART_PORTS:
            if startp<=p<=endp and p not in used:
                q.put(p); used.add(p)
    for p in range(startp,endp+1):
        if p not in used:
            q.put(p); used.add(p)
    return q

class Scanner:
    def __init__(self,target,ports_q,threads):
        self.target=target
        self.q=ports_q
        self.threads=threads
        self.open=[]
        self.lock=threading.Lock()
        self.total=self.q.qsize()
        self.done=0

    def worker(self):
        while True:
            try: port=self.q.get_nowait()
            except: return
            try:
                s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                s.settimeout(0.2)
                r=s.connect_ex((self.target,port))
                if r==0:
                    srv=self.get_name(port)
                    with self.lock:
                        self.open.append((port,srv))
                        print(f"\n[OPEN] {port} | {srv}")
                s.close()
            except: pass
            with self.lock:
                self.done+=1
            self.q.task_done()

    def get_name(self,port):
        try: return socket.getservbyport(port)
        except: return "unknown"

    def start(self):
        ts=[]
        for _ in range(self.threads):
            t=threading.Thread(target=self.worker)
            t.daemon=True
            ts.append(t)
            t.start()

        while True:
            d=self.done; tot=self.total
            if tot>0:
                pct=(d*100)/tot
                bar_len=40
                filled=int(bar_len*d/tot)
                bar="["+"#"*filled+"-"*(bar_len-filled)+"]"
                sys.stdout.write(f"\r{bar} {d}/{tot} ({pct:.1f}%)")
                sys.stdout.flush()
            if d>=tot: break
            time.sleep(0.15)

        self.q.join()
        print()
        return self.open

def save(target,openp):
    now=datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    fn=f"NemesaScanV3.4_{target}_{now}.txt".replace(":","_")
    f=open(fn,"w")
    f.write("NemesaScan V3.4 Results\n")
    f.write("=======================\n")
    f.write(f"Target: {target}\n")
    f.write(f"Date: {now}\n\n")
    if openp:
        f.write("Open Ports:\n")
        for p,s in openp:
            f.write(f"- {p} ({s})\n")
    else:
        f.write("No open ports found.\n")
    f.close()
    print(f"\nResults saved: {fn}\n")

def main():
    clear()
    header()
    logo_anim(2)

    target=input("Target IP/domain: ").strip()
    if target=="": 
        print("Invalid target."); return

    mode=input("Mode (1=full scan, 2=smart scan): ").strip()
    smart=(mode=="2")

    threads=input(f"Threads (default={DEFAULT_THREADS}): ").strip()
    if threads.isdigit(): threads=int(threads)
    else: threads=DEFAULT_THREADS

    startp=1
    endp=65535

    q=build_queue(startp,endp,smart)

    print("\nStarting scan...\n")
    scanner=Scanner(target,q,threads)
    result=scanner.start()
    save(target,result)

main()
