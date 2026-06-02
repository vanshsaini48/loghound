"""Generate synthetic auth.log for memory/throughput testing."""
import random
from datetime import datetime, timedelta
from pathlib import Path


def _fmt_ts(dt):
    """Syslog timestamp: 'Jun  2 10:15:01'."""
    day = str(dt.day)
    day_field = f" {day}" if dt.day < 10 else day
    return f"{dt.strftime('%b')} {day_field} {dt.strftime('%H:%M:%S')}"


def generate_log(path, target_mb=100, seed=42):
    """Write synthetic auth.log with embedded brute-force patterns."""
    rng = random.Random(seed)
    hostname = "webserver01"
    users = [f"user{i}" for i in range(20)]
    normal_ips = [f"10.0.1.{i}" for i in range(1, 30)]
    brute_ips = [f"203.0.113.{i}" for i in range(1, 6)]

    target_bytes = target_mb * 1024 * 1024
    t = datetime(2026, 6, 1, 0, 0, 0)
    written = 0
    pid = 1000

    with open(path, "w") as f:
        while written < target_bytes:
            t += timedelta(seconds=rng.uniform(0.05, 1.5))
            ts = _fmt_ts(t)
            pid = (pid % 60000) + 1

            # ~0.2% chance of brute-force burst (6-15 failures from one IP)
            if rng.random() < 0.002:
                ip = rng.choice(brute_ips)
                for _ in range(rng.randint(6, 15)):
                    user = rng.choice(users)
                    line = (
                        f"{ts} {hostname} sshd[{pid}]: "
                        f"Failed password for {user} from {ip} "
                        f"port {rng.randint(30000, 60000)} ssh2\n"
                    )
                    f.write(line)
                    written += len(line)
                    t += timedelta(seconds=rng.uniform(0.5, 3.0))
                    ts = _fmt_ts(t)
                continue

            # Normal traffic mix
            ip = rng.choice(normal_ips)
            user = rng.choice(users)
            r = rng.random()
            if r < 0.6:
                msg = f"Accepted password for {user} from {ip} port {rng.randint(30000, 60000)} ssh2"
            elif r < 0.8:
                msg = f"Failed password for {user} from {ip} port {rng.randint(30000, 60000)} ssh2"
            elif r < 0.9:
                msg = f"session opened for user {user} by (uid=0)"
            else:
                msg = f"session closed for user {user}"

            line = f"{ts} {hostname} sshd[{pid}]: {msg}\n"
            f.write(line)
            written += len(line)

    return Path(path)


if __name__ == "__main__":
    import sys
    mb = int(sys.argv[1]) if len(sys.argv) > 1 else 100
    out = sys.argv[2] if len(sys.argv) > 2 else "/tmp/large_auth.log"
    p = generate_log(out, target_mb=mb)
    print(f"Generated {p.stat().st_size / 1024 / 1024:.1f} MB -> {p}")
