import subprocess

blocked_ips = set()

def block_ip(ip):

    if ip in blocked_ips:
        return

    try:
        subprocess.run(
            ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
            check=True
        )
        blocked_ips.add(ip)
        print(f"[🔥 BLOCKED] IP {ip} has been blocked by firewall")

    except Exception as  e:
        print(f"[ERROR] Could not block IP {ip}: {e}")
