"""Deliberately vulnerable LAB target. Run on localhost only: python demo_target.py"""
from flask import Flask, request
app = Flask(__name__)

@app.get("/")
def home():
    q = request.args.get("q", "")
    if "'" in q:   # simulates a leaked DB error
        return "sqlite3.OperationalError: unrecognized token near \"'\"", 500
    resp = app.make_response(f"""<h1>Lab target</h1><p>You searched: {q}</p>
      <form method="post" action="/login"><input name="user">
      <input type="password" name="pw"><button>Login</button></form>""")
    resp.set_cookie("session", "abc123")
    return resp

@app.get("/.env")
def env():
    return "SECRET_KEY=lab-only"

if __name__ == "__main__":
    app.run(port=8000)
