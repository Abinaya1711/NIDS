import json, sqlite3

# Check eve.json
print("=== EVE.JSON ALERTS ===")
with open("logs/eve.json", "r") as f:
    lines = f.readlines()

alerts = []
for line in lines:
    line = line.strip()
    if not line:
        continue
    try:
        obj = json.loads(line)
        if "alert" in obj:
            alerts.append(obj)
    except:
        pass

sevs = {}
for a in alerts:
    s = a["alert"].get("severity", "?")
    sevs[s] = sevs.get(s, 0) + 1

print(f"Total alerts in eve.json: {len(alerts)}")
print(f"Severity distribution: {sevs}")

# Show last 4 alerts
print("\n--- Last 4 alerts ---")
for a in alerts[-4:]:
    print(json.dumps({
        "severity": a["alert"].get("severity"),
        "signature": a["alert"].get("signature"),
        "src_ip": a.get("src_ip"),
        "dest_ip": a.get("dest_ip"),
    }))

# Check database
print("\n=== DATABASE ALERTS ===")
try:
    conn = sqlite3.connect("nids.db")
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM alerts")
    total = cur.fetchone()[0]
    print(f"Total alerts in DB: {total}")
    
    cur.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity")
    for row in cur.fetchall():
        print(f"  Severity {row[0]}: {row[1]}")
    
    print("\n--- Sample alerts per severity ---")
    for sev in [1, 2, 3, 4]:
        cur.execute("SELECT signature, src_ip, dest_ip FROM alerts WHERE severity=? LIMIT 1", (sev,))
        row = cur.fetchone()
        if row:
            print(f"  Sev {sev}: sig={row[0]}, src={row[1]}, dst={row[2]}")
        else:
            print(f"  Sev {sev}: NO ALERTS FOUND")
    
    conn.close()
except Exception as e:
    print(f"DB error: {e}")
