"""Gera exports sintéticos no formato real (3 colunas) + arquivo de ataques,
para testar treino, inferência e scanner sem os dados reais."""
import random, datetime as dt, csv, sys
random.seed(7)
TZ = dt.timezone(dt.timedelta(hours=-3))
DAY0 = dt.datetime(2026, 9, 17, 0, 0, tzinfo=TZ)
HOSTS = {"ROTEADOR_1": ("bridgeWAN", ["bridgeAdm", "bridgeDesenvolvimento", "bridgeInfra"], "10.0.1."),
         "ROTEADOR_2": ("ether1", ["bridgeSEC_B", "bridgeSEC_C"], None)}
NETS = {"bridgeSEC_B": "10.0.2.", "bridgeSEC_C": "10.0.3."}
EXT = ["142.250.78.", "172.217.29.", "35.186.224.", "157.240.12.", "20.190.160."]
def ns(t): return int(t.timestamp() * 1e9)
def line_norm(t):
    h = random.choice(list(HOSTS)); wan, lans, net = HOSTS[h]; lan = random.choice(lans)
    ip = (net or NETS[lan]) + str(random.randint(20, 60))
    ext = random.choice(EXT) + str(random.randint(1, 250))
    p = random.random()
    if p < 0.45:
        return h, f"access forward: in:{lan} out:{wan}, src-mac aa:bb:cc:{random.randint(10,99)}:4a:8e, proto TCP (ACK), {ip}:{random.randint(32768,60999)}->{ext}:443, len {random.randint(52,1400)}"
    if p < 0.75:
        return h, f"access forward: in:{wan} out:{lan}, src-mac aa:bb:cc:00:00:01, proto TCP (ACK,PSH), {ext}:443->{ip}:{random.randint(32768,60999)}, len {random.randint(52,1400)}"
    if p < 0.95:
        return h, f"access forward: in:{lan} out:{wan}, src-mac aa:bb:cc:{random.randint(10,99)}:4a:8e, proto UDP, {ip}:{random.randint(32768,60999)}->10.0.0.53:53, len {random.randint(60,120)}"
    return h, f"access forward: in:{lan} out:{wan}, src-mac aa:bb:cc:{random.randint(10,99)}:4a:8e, proto TCP (SYN), {ip}:{random.randint(32768,60999)}->{ext}:443, len 60"

def gen(days=2, rate_per_min=60, out_prefix="export"):
    rows = []
    for d in range(days):
        for m in range(24 * 60):
            base = DAY0 + dt.timedelta(days=d, minutes=m)
            hour = base.hour
            k = rate_per_min if 7 <= hour <= 18 else rate_per_min // 5
            for _ in range(k):
                t = base + dt.timedelta(seconds=random.random() * 60)
                h, l = line_norm(t); rows.append((ns(t), h, l))
    attacks = []
    atk_ip = "10.0.1.21"
    # 1) scan lento (abaixo do limiar): 1 porta a cada 20 s por 3 h, dia 1
    s = DAY0 + dt.timedelta(days=0, hours=10); e = s + dt.timedelta(hours=3)
    t, port = s, 1
    while t < e:
        rows.append((ns(t), "ROTEADOR_1", f"access forward: in:bridgeInfra out:bridgeWAN, src-mac aa:bb:cc:00:00:02, proto TCP (SYN), {atk_ip}:{random.randint(40000,60000)}->10.0.1.254:{port}, len 60"))
        t += dt.timedelta(seconds=20); port += 1
    attacks.append((s, e, atk_ip, "abaixo", "real", "portscan_lento"))
    # 2) scan rápido (acima do limiar), contra o roteador, com log do firewall
    s = DAY0 + dt.timedelta(days=1, hours=15); e = s + dt.timedelta(minutes=2)
    t, port = s, 1
    while t < e:
        pre = "PORT-SCAN_atk input" if port % 5 == 0 else "access input"
        rows.append((ns(t), "ROTEADOR_1", f"{pre}: in:bridgeInfra out:(unknown 0), src-mac aa:bb:cc:00:00:02, proto TCP (SYN), {atk_ip}:{random.randint(40000,60000)}->10.0.1.1:{port}, len 44"))
        t += dt.timedelta(milliseconds=40); port += 1
    attacks.append((s, e, atk_ip, "acima", "real", "portscan_rapido"))
    # 3) força bruta lenta (sintético): SSH 1 tentativa/30 s por 2 h, dia 2
    s = DAY0 + dt.timedelta(days=1, hours=9); e = s + dt.timedelta(hours=2)
    t = s
    while t < e:
        rows.append((ns(t), "ROTEADOR_2", f"access forward: in:bridgeSEC_B out:ether1, src-mac aa:bb:cc:00:00:03, proto TCP (SYN), 10.0.2.99:{random.randint(40000,60000)}->200.10.20.30:22, len 60"))
        t += dt.timedelta(seconds=30)
    attacks.append((s, e, "10.0.2.99", "abaixo", "sintetico", "bruteforce_ssh"))
    # duplicatas de syslog (~5%) com ns diferentes
    for r in random.sample(rows, len(rows) // 20):
        rows.append((r[0] + random.randint(1, 900) * 1000, r[1], r[2]))
    rows.sort()
    files = {}
    for ts, h, l in rows:
        day = dt.datetime.fromtimestamp(ts / 1e9, TZ).strftime("%Y-%m-%d")
        files.setdefault(f"{out_prefix}/{h}_{day}.txt", []).append(f"{ts}\t{h}\t{l}")
    import os; os.makedirs(out_prefix, exist_ok=True)
    for f, ls in files.items():
        open(f, "w").write("\n".join(ls) + "\n")
    with open("ataques.csv", "w", newline="") as fh:
        w = csv.writer(fh); w.writerow(["start", "end", "src_ip", "regime", "origem", "tipo"])
        for s, e, ip, rg, org, tp in attacks:
            w.writerow([s.strftime("%Y-%m-%d %H:%M:%S"), e.strftime("%Y-%m-%d %H:%M:%S"), ip, rg, org, tp])
    print(len(rows), "linhas;", sorted(files))
if __name__ == "__main__":
    gen(rate_per_min=int(sys.argv[1]) if len(sys.argv) > 1 else 60)
