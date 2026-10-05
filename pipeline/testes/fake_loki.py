"""Loki falso (query_range + push) para testar o scanner sem o servidor real.
Serve um export deslocado no tempo para que o trecho escolhido termine 'agora'."""
import json, sys, time, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
import polars as pl
sys.path.insert(0, ".."); sys.path.insert(0, ".")
import common_features_polars as cf
df = cf.read_export(sys.argv[1]).sort("ts")
fim_dados = int(sys.argv[2]) if len(sys.argv) > 2 else int(df["ts"].max())
shift = time.time_ns() - fim_dados + 30 * 10**9     # o trecho continua chegando por 30 s
df = df.with_columns(pl.col("ts") + shift)
PUSHED = []
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        q = parse_qs(urlparse(self.path).query)
        s, e, lim = int(q["start"][0]), int(q["end"][0]), int(q["limit"][0])
        now = time.time_ns()
        sel = df.filter((pl.col("ts") >= s) & (pl.col("ts") < min(e, now))).head(lim)
        res = [{"stream": {"job": "mikrotik-firewall", "hostname": h},
                "values": [[str(t), c] for t, c in zip(g["ts"], g["content"])]}
               for (h,), g in sel.group_by(["hostname"])]
        body = json.dumps({"status": "success", "data": {"resultType": "streams", "result": res}}).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
        self.wfile.write(body)
    def do_POST(self):
        n = int(self.headers["Content-Length"]); body = json.loads(self.rfile.read(n))
        for st in body["streams"]:
            PUSHED.extend((st["stream"], v) for v in st["values"])
        open("pushed.json", "w").write(json.dumps(PUSHED[-50:], ensure_ascii=False))
        self.send_response(204); self.end_headers()
srv = ThreadingHTTPServer(("127.0.0.1", 3199), H)
print("fake loki pronto", flush=True); srv.serve_forever()
