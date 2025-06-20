# acm-sqli

`acm-sqli` is a lightweight SQL Injection detection microservice that leverages [`sqlmap`](https://github.com/sqlmapproject/sqlmap) to automatically assess whether input endpoints are vulnerable to SQLi. It is designed to be integrated into larger security tools (like DAST scanners) through a simple REST API.

---

## 🚀 Features

* Supports GET, POST, DELETE, PUT, PATCH methods
* Accepts both form and JSON body payloads
* Returns vulnerability status and injection payload
* Async scanning via scan IDs
* Scan cancelation and listing capabilities
* Configurable threads, risk, level, and technique depth

---

## ⚙️ Requirements

* Go 1.18+
* Python 3
* Clone [`sqlmap`](https://github.com/sqlmapproject/sqlmap) locally:

```bash
git clone https://github.com/sqlmapproject/sqlmap.git
```

---

## 🛠️ Setup

```bash
go build -o acm-sqli
./acm-sqli
```

Default server runs at `http://localhost:8080`

---

## 📤 API: Submit Scan

**POST** `/acm/v1/sqlmap`

### Request Body

```json
{
  "threads": 10,
  "level": 5,
  "risk": 1,
  "time_based": false,
  "url": [
    {
      "url": "https://demo.testfire.net/doLogin",
      "http_method": "POST",
      "form_params": "uid,passw,btnSubmit",
      "body_params": "",
      "headers": {
        "Cookie": "sessionid=abc123"
      }
    },
    {
      "url": "https://demo.testfire.net/?mode=FUZZ",
      "http_method": "GET",
      "form_params": "",
      "body_params": ""
    }
  ]
}
```

### Response

```json
[
  {
    "id": "acm-uuid-1",
    "url": "https://demo.testfire.net/doLogin",
    "vulnerable": false,
    "payload": "",
    "status": "running"
  },
  ...
]
```

---

## 🔍 API: Get Scan Status

**GET** `/acm/v1/sqlmap/:id/status`

### Sample

```bash
curl http://localhost:8080/acm/v1/sqlmap/acm-uuid-1/status
```

### Response

```json
{
  "status": "done"
}
```

---

## 📄 API: Get Scan Result

**GET** `/acm/v1/sqlmap/:id/result`

### Sample

```bash
curl http://localhost:8080/acm/v1/sqlmap/acm-uuid-1/result
```

### Response

```json
{
  "id": "acm-uuid-1",
  "url": "https://demo.testfire.net/doLogin",
  "vulnerable": true,
  "payload": "uid=admin'--",
  "status": "done"
}
```

---

## 📋 API: List All Scans

**GET** `/acm/v1/sqlmap`

### Response

```json
[
  {
    "id": "acm-uuid-1",
    "url": "https://demo.testfire.net/doLogin",
    "status": "done"
  },
  {
    "id": "acm-uuid-2",
    "url": "https://demo.testfire.net/?mode=FUZZ",
    "status": "running"
  }
]
```

---

## ❌ API: Cancel Scan

**DELETE** `/acm/v1/sqlmap/:id`

### Sample

```bash
curl -X DELETE http://localhost:8080/acm/v1/sqlmap/acm-uuid-2
```

### Response

```json
{
  "status": "cancelled"
}
```

---

## 📌 Notes

* If `form_params` is used, tool sends `application/x-www-form-urlencoded`
* If `body_params` is used, tool sends `application/json`
* `FUZZ` in the URL is replaced with payload like `1*` for GET-based tests
* Payload results are returned via `[PAYLOAD]` marker in sqlmap output
* Tool does **not dump** data — only checks for SQLi existence

---

## 🔐 Use Case

This tool is ideal for:

* Automated scanning in CI pipelines
* DAST integration
* Custom red-team orchestration
* Lightweight API security testing

---

## 🧪 Debugging

* All sqlmap output is printed to console (for now)
* `skipped` status indicates unsupported or incomplete input
* To enable file logs, modify `processInputWithCancel()` to write `out.String()` to file

---

## 🤝 License

MIT

---

Contributions welcome!
