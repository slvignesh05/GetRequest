# 📬 Get A Request — Self-Hosted Webhook Inspector with Flask & Ngrok

**GetRequest** is a lightweight, self-hosted alternative to tools like [webhook.site](https://webhook.site) or [RequestBin](https://requestbin.com/).  
It allows you to **inspect, capture, and debug incoming HTTP requests** locally — with a simple web-based interface and persistent logging.

This is project is really useful when you don't want to expose your secrets to third parties!.

This project is ideal for developers testing **webhooks, APIs, or third-party integrations** that need a public endpoint without exposing an entire backend.

---

## 🧠 Overview

When you run this project locally:
- It starts a **Flask web server** on port `5000`.
- You expose it publicly using **ngrok**.
- Any HTTP request (GET, POST, PUT, DELETE, etc.) sent to your ngrok URL is **forwarded to your local Flask app**.
- The app logs request details (method, headers, body, timestamp) in a JSON file and displays them in a **clean web dashboard**.

---

## 🚀 Features

✅ **Simple Setup** — Run locally in minutes  
🌐 **Ngrok Integration** — Instantly expose your local endpoint  
📋 **Detailed Logging** — Capture request method, headers, and body  
💾 **Persistent Storage** — Logs saved automatically in `requests.json`  
🖥 **Web Dashboard** — View requests in a modern, minimal UI  
🧹 **Clear Logs Button** — Wipe all saved requests with one click  
🔒 **Secure & Local** — Nothing leaves your system unless tunneled  

---

## 🛠️ Requirements

Before you begin, ensure you have:

- **Python 3.7+**
- **pip (Python package manager)**
- **ngrok** installed ([Download ngrok](https://ngrok.com/download))

---

2️⃣ Install Dependencies
pip install flask

3️⃣ Run the Application
python requestbin.py


This starts the Flask server on http://127.0.0.1:5000

4️⃣ Expose Locally via Ngrok

In a new terminal:

ngrok http 5000


You’ll get a public HTTPS URL, e.g.:

https://abcd1234.ngrok.io


This URL is your temporary public endpoint for receiving requests.

🧩 Project Structure
.
├── requestbin.py        # Flask app that handles and logs requests
├── requests.json        # Automatically created file storing logs
└── README.md            # Documentation

💻 Usage
▶️ 1. Send a Test Request

Use curl, Postman, or any webhook service:

curl -X POST -H "Content-Type: application/json" \
     -d '{"message":"Hello RequestBin!"}' \
     https://abcd1234.ngrok.io

▶️ 2. View Requests in Browser

Open the dashboard locally:

👉 http://127.0.0.1:5000

You’ll see:

HTTP method (GET, POST, etc.)

Timestamp

Request headers

Request body

Each incoming request appears as a separate card in the interface.

▶️ 3. Clear Logged Requests

Click the 🗑 Clear button on the dashboard
OR visit:

http://127.0.0.1:5000/clear


This resets the requests.json file.

## ⚙️ Installation Steps

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/<your-username>/local-requestbin.git
cd local-requestbin
