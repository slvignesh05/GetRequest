from flask import Flask, request, render_template_string, redirect
import json, datetime, os

app = Flask(__name__)
LOG_FILE = "requests.json"

# Initialize storage file
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, "w") as f:
        json.dump([], f)

HTML_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Local RequestBin</title>
  <style>
    body { font-family: system-ui; margin: 20px; background: #f9fafb; color: #111; }
    h1 { text-align: center; }
    .req { background: white; margin: 1em 0; padding: 1em; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    pre { background: #f3f4f6; padding: 10px; border-radius: 6px; overflow-x: auto; }
    .method { font-weight: bold; color: #2563eb; }
    .refresh { display: inline-block; margin: 10px 0; background: #2563eb; color: white; padding: 6px 12px; border-radius: 6px; text-decoration: none; }
  </style>
</head>
<body>
  <h1>📬 Local RequestBin</h1>
  <a href="/" class="refresh">🔄 Refresh</a>
  <a href="/clear" class="refresh" style="background:#dc2626">🗑 Clear</a>
  {% for r in requests|reverse %}
  <div class="req">
    <div><span class="method">{{r["method"]}}</span> — {{r["time"]}}</div>
    <div><b>Headers:</b><pre>{{r["headers"]}}</pre></div>
    <div><b>Body:</b><pre>{{r["body"]}}</pre></div>
  </div>
  {% endfor %}
</body>
</html>
"""

@app.route("/", methods=["GET"])
def view_requests():
    with open(LOG_FILE) as f:
        data = json.load(f)
    return render_template_string(HTML_TEMPLATE, requests=data)

@app.route("/clear")
def clear_requests():
    with open(LOG_FILE, "w") as f:
        json.dump([], f)
    return redirect("/")

@app.route("/", methods=["POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
def log_request():
    req_data = {
        "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "method": request.method,
        "headers": dict(request.headers),
        "body": request.get_data(as_text=True)
    }
    with open(LOG_FILE) as f:
        data = json.load(f)
    data.append(req_data)
    with open(LOG_FILE, "w") as f:
        json.dump(data, f, indent=2)
    print(f"\n📩 Received {request.method} request at {req_data['time']}")
    return "✅ Logged!", 200

if __name__ == "__main__":
    app.run(port=5000)
