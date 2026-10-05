import json, re, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
import polars as pl, glob
sys.path.insert(0, ".."); sys.path.insert(0, ".")
import common_features_polars as cf
df = pl.concat([cf.read_export(f) for f in sorted(glob.glob("export/*.txt"))]).sort("ts")
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def send(self, obj):
        b = json.dumps(obj).encode(); self.send_response(200)
        self.send_header("Content-Type", "application/json"); self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        u = urlparse(self.path); q = parse_qs(u.query)
        m = re.search(r'hostname="([^"]+)"', q.get("query", [""])[0])
        d = df.filter(pl.col("hostname") == m.group(1)) if m else df
        if u.path.endswith("/values"):
            return self.send({"status": "success", "data": sorted(df["hostname"].unique().to_list())})
        if u.path.endswith("/query"):
            secs = int(re.search(r"\[(\d+)s\]", q["query"][0]).group(1)); t = int(q["time"][0])
            n = d.filter((pl.col("ts") > t - secs * 10**9) & (pl.col("ts") <= t)).height
            return self.send({"status": "success", "data": {"resultType": "vector",
                              "result": [{"metric": {}, "value": [t / 1e9, str(n)]}]}})
        s, e, lim = int(q["start"][0]), int(q["end"][0]), int(q["limit"][0])
        sel = d.filter((pl.col("ts") >= s) & (pl.col("ts") < e)).head(lim)
        res = [{"stream": {"job": "mikrotik-firewall", "hostname": h},
                "values": [[str(t), c] for t, c in zip(g["ts"], g["content"])]}
               for (h,), g in sel.group_by(["hostname"])]
        self.send({"status": "success", "data": {"resultType": "streams", "result": res}})
ThreadingHTTPServer(("127.0.0.1", 3198), H).serve_forever()
