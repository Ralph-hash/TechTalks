# SSH Tunnelling

## Demo

On Both Machines watch all tcp connections:
```
watch -n0 ss -t
```

This demo is between two machines, one on the trusted CIL network and one on the untrusted Corona Lab netowrk (`10.90.208.201`)

Observe that there are no http connections allowed between the trusted and untrusted.

Trusted:
```
python3 -m http.server 8080
wget http://localhost:8080
```

Untrusted:
```
wget http://10.90.108.32:8080
```

As you can see the connection cannot be made.

On both the trusted and the untrusted, allow for tunnelling, ip forwarding (this would be for setting up a VPN), then restart the ssh service since we made changes to the configuration.
``` 
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
vim /etc/ssh/sshd_config (PermitTunnel yes) (on untrusted also: PermitRootLogin)
systemctl restart sshd
```

From the trusted machine, create the tunnel
```
ssh -NTCf -w 0:0 10.90.208.201
ip link set tun0 up
ip addr add 10.0.0.100/32 peer 10.0.0.200 dev tun0
arp -sD 10.0.0.100 ens160 pub
```

Configure the tunnel on the untrusted side:
```
ip link set tun0 up
ip addr add 10.0.0.200/32 peer 10.0.0.100 dev tun0
```

Now try and use http to the tunnel ip's across machines:

Trusted:
```
python3 -m http.server 8080
wget http://localhost:8080
```

Untrusted:
```
wget http://10.0.0.100:8080
python3 -m http.server 8080
wget http://localhost:8080
```

Trusted:
```
wget http://10.0.0.200:8080
```

## References
- `https://help.ubuntu.com/community/SSH_VPN`

