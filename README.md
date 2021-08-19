# eBPF-ctf2021
https://ebpf.io/summit-2021/ctf/


---
# CTF3

```curl localhost:1977```
<br>as expected connection dropped.

```ps -ax``` <br>
thousands of /usr/bin/defense-droid running <br>
pid 1 /usr/bin/container <br>
pid 11 /usr/bin/password-server

### cheat
```/usr/bin/password-server :8080 && curl localhost:8080```

## try1
```chmod -x /usr/bin/defence-droid
pkill -f '/usr/bin/defence-droid'
```
<br>container quits
<br>

## try2
```
pkill --signal 19 -f '/usr/bin/defence-droid'
```
<br>nothing happens and port is still blocked.
<br>

## Success
```
pkill --signal 9 -f '/usr/bin/defence-droid && curl localhost:1977'
```

```
root@bc9b845891e1:/# pkill --signal 9 -f '/usr/bin/defense-droid' && curl localhost:1977
2021/08/19 08:16:24 intrusion detected! self-destructing!
Welcome, Imperial Commander! The secret passphrase is: eCHO-33-32-37
root@bc9b845891e1:/#
```

---
