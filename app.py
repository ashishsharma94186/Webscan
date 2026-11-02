import json, sqlite3, datetime as dt
from flask import Flask, request, jsonify, render_template, g
import scanner

app = Flask(__name__, template_folder=".")
DB = "scans.db"


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
        g.db.execute("CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY, target TEXT, "
                     "created TEXT, findings TEXT)")
    return g.db


@app.teardown_appcontext
def close(_):
    d = g.pop("db", None)
    if d:
        d.close()


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/scan")
def api_scan():
    data = request.get_json(force=True)
    url = (data.get("url") or "").strip()
    if not url.startswith(("http://", "https://")):
        return jsonify(error="URL must start with http:// or https://"), 400
    try:
        findings = scanner.scan(url, confirmed=bool(data.get("confirmed")))
    except PermissionError as e:
        return jsonify(error=str(e)), 403
    except Exception as e:
        return jsonify(error=f"Scan failed: {e}"), 502
    cur = db().execute("INSERT INTO scans(target, created, findings) VALUES(?,?,?)",
                       (url, dt.datetime.utcnow().isoformat(timespec="seconds"), json.dumps(findings)))
    db().commit()
    return jsonify(id=cur.lastrowid, target=url, findings=findings)


@app.get("/api/scans")
def api_scans():
    rows = db().execute("SELECT id, target, created FROM scans ORDER BY id DESC LIMIT 20").fetchall()
    return jsonify([dict(r) for r in rows])


@app.get("/api/scans/<int:sid>")
def api_scan_get(sid):
    r = db().execute("SELECT * FROM scans WHERE id=?", (sid,)).fetchone()
    if not r:
        return jsonify(error="Not found"), 404
    return jsonify(id=r["id"], target=r["target"], created=r["created"], findings=json.loads(r["findings"]))


@app.get("/report/<int:sid>")
def report(sid):
    r = db().execute("SELECT * FROM scans WHERE id=?", (sid,)).fetchone()
    if not r:
        return "Not found", 404
    return render_template("report.html", scan=r, findings=json.loads(r["findings"]))


if __name__ == "__main__":
    app.run(port=5000, debug=False)
