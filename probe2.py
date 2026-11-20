#!/usr/bin/env python3
# i46232 probe2: from Azure GHA runner EIPs, fingerprint 40.160.7.76 full surface
import os,socket,json,time,urllib.request
JOB=str(os.environ.get("JOB","0"));TOPIC="i46232-s2"
PORTS=[3001,5357,3306,8090,5985,22,80,443]
TARGETS=["40.160.7.76"]
def log(*a):print(" ".join(map(str,a)),flush=True)
def send(tag,text):
    text=str(text)
    for i in range(0,len(text),3400):
        try:
            urllib.request.urlopen(urllib.request.Request("https://ntfy.sh/"+TOPIC,data=((("[j%s %s] "%(JOB,tag))+text[i:i+3400]).encode()),method="POST",headers={"Title":("i46232s2-"+tag)[:60]}),timeout=12).read()
        except Exception as e:log("ntfyerr",str(e)[:60])
def egress():
    for u in ("https://api.ipify.org","https://icanhazip.com"):
        try:return urllib.request.urlopen(u,timeout=10).read().decode().strip()
        except:pass
    return "ERR"
def tcp(h,p,t=5.0):
    st=time.time()
    try:
        s=socket.create_connection((h,p),timeout=t);s.close();return "OPEN:%dms"%round((time.time()-st)*1000)
    except ConnectionRefusedError:return "REFUSED"
    except socket.timeout:return "TIMEOUT"
    except Exception as e:return "ERR:"+str(e)[:30]
def httpget(h,p,path="/",tls=False,timeout=8):
    s=None
    try:
        s=socket.create_connection((h,p),timeout=timeout)
        if tls:
            import ssl;ctx=ssl.create_default_context();ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE
            s=ctx.wrap_socket(s,server_hostname=h)
        s.sendall(("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: probe\r\nConnection: close\r\n\r\n"%(path,h)).encode())
        d=b""
        while True:
            c=s.recv(8192)
            if not c:break
            d+=c
            if len(d)>20000:break
        return d[:1200].decode("latin-1","replace")
    except Exception as e:return "ERR:"+str(e)[:60]
    finally:
        try:
            if s:s.close()
        except:pass
def main():
    ip=egress();log("=== j%s egress %s ==="%(JOB,ip))
    rep={"job":JOB,"egress":ip}
    for h in TARGETS:
        for p in PORTS:
            st=tcp(h,p);rep["%s:%d"%(h,p)]=st
            if st.startswith("OPEN") and p in (3001,5357,8090,80,443):
                body=httpget(h,p,"/",tls=(p==443))
                line=(body or "").split("\r\n")
                head=" | ".join(line[:6])
                log(h,p,st,"=>",head[:200])
                send("svc","%s:%d %s %s"%(h,p,st,head[:300]))
                if p==3001:
                    for path in ("/api/status","/api/setup"):
                        bb=httpget(h,p,path)
                        send("api","%s:%d%s -> %s"%(h,p,path,(bb or '')[:250]))
    send("summary",json.dumps(rep)[:4000])
if __name__=="__main__":main()
