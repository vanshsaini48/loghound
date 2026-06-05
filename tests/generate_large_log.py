"""Generate a large synthetic auth.log for performance testing."""
import random
import sys
from datetime import datetime, timedelta

def generate(target_mb=500, output="tests/fixtures/large_auth.log"):
    """Generate a synthetic auth.log with ~target_mb lines."""
    base_time = datetime(2026, 3, 15, 0, 0, 0)
    
    # Mix of normal IPs and attacker IPs
    normal_ips = [f"192.168.1.{i}" for i in range(1, 20)]
    attacker_ips = [f"203.0.113.{i}" for i in range(1, 30)]
    all_ips = normal_ips + attacker_ips
    
    users = ["root", "admin", "jdoe", "ubuntu", "deploy", "backup", "www-data", "postgres"]
    
    # Realistic log templates
    templates = [
        "Mar 15 {time} ubuntu-server sshd[{pid}]: Failed password for {user} from {ip} port {port} ssh2",
        "Mar 15 {time} ubuntu-server sshd[{pid}]: Accepted password for {user} from {ip} port {port} ssh2",
        "Mar 15 {time} ubuntu-server sshd[{pid}]: Invalid user {user} from {ip} port {port}",
        "Mar 15 {time} ubuntu-server sudo: {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/usr/bin/apt update",
        "Mar 15 {time} ubuntu-server sudo: {user} : TTY=pts/1 ; PWD=/ ; USER=root ; COMMAND=/bin/systemctl restart nginx",
        "Mar 15 {time} ubuntu-server sshd[{pid}]: Connection closed by {ip} port {port}",
        "Mar 15 {time} ubuntu-server sshd[{pid}]: Received disconnect from {ip} port {port}",
        "Mar 15 {time} ubuntu-server systemd-logind[{pid}]: New session {port} of user {user}.",
    ]
    
    target_bytes = target_mb * 1024 * 1024
    written = 0
    lines = 0
    
    print(f"Generating {target_mb} MB synthetic auth.log...")
    
    with open(output, 'w') as f:
        while written < target_bytes:
            t = base_time + timedelta(seconds=random.randint(0, 86400))
            time_str = t.strftime("%H:%M:%S")
            line = random.choice(templates).format(
                time=time_str,
                pid=random.randint(1000, 99999),
                user=random.choice(users),
                ip=random.choice(all_ips),
                port=random.randint(30000, 65000),
            )
            f.write(line + "\n")
            written += len(line) + 1
            lines += 1
            
            if lines % 100000 == 0:
                print(f"  {written / 1024 / 1024:.1f} MB ({lines:,} lines)...", flush=True)
    
    print(f"✓ Generated {written / 1024 / 1024:.1f} MB ({lines:,} lines) -> {output}")
    return output

if __name__ == "__main__":
    size = int(sys.argv[1]) if len(sys.argv) > 1 else 500
    generate(target_mb=size)
