import socket,sys
from IPy import IP

def scan(t):
 try:ip=IP(t);ip=t
 except:ip=socket.gethostbyname(t)
 print(f'\n[-] Scanning {t}')
 for p in range(1,500):
  try:
   s=socket.socket();s.settimeout(1);s.connect((ip,p))
   try:
    if p in[21,22,25,110,143]:b=s.recv(1024).decode('utf-8',errors='ignore').strip()
    elif p in[80,8080]:s.send(b"GET / HTTP/1.1\r\n\r\n");b=s.recv(1024).decode('utf-8',errors='ignore').strip()
    elif p==443:b="HTTPS"
    else:b=s.recv(512).decode('utf-8',errors='ignore').strip() if s.recv(512) else None
    print(f'[+] {p}: {b[:50] if b else "Open"}')
   except:print(f'[+] {p}: Open')
   s.close()
  except:pass

if __name__=="__main__":
 for t in input('[+] Targets: ').split(','):scan(t.strip())
