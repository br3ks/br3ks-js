# br3k-js

Passive JavaScript endpoint & parameter extractor for Burp Suite.

---

# Features

## JavaScript Detection

Automatically detects JavaScript responses based on:

* `.js` file extension
* `Content-Type: javascript`
* `Content-Type: ecmascript`

---

## Endpoint Extraction

Extracts:

```text
/api/user
/v1/auth/login
https://api.example.com/graphql
```

Useful for:

* hidden APIs
* undocumented routes
* internal endpoints
* microservice discovery

---

## Query Parameter Extraction

Detects query parameters from JavaScript:

```text
?id=
&page=
&token=
```

Example findings:

```text
userId
session
redirect
callback
access_token
```

---

## JSON Key Extraction

Extracts JSON body keys:

```json
{
  "username": "",
  "email": "",
  "role": ""
}
```

Useful for:

* request body mapping
* API fuzzing
* parameter discovery

---

## FormData Extraction

Detects:

```javascript
formData.append("file", file)
```

Useful for:

* upload endpoints
* multipart forms
* hidden form parameters

---

## Header Extraction

Extracts sensitive or custom headers:

```text
Authorization
X-Api-Key
X-CSRF-Token
Content-Type
```

Useful for:

* auth analysis
* API testing
* token discovery

---

## Beautiful UI

Includes:

* statistics cards
* sortable table
* activity log
* export CSV
* clear results button

---

# Screenshots

## Main UI

```text
+------------------------------------------------------+
| br3k-js                                              |
| Passive JavaScript endpoint & parameter extractor    |
+------------------------------------------------------+

+------------+------------+------------+
| JS Files   | Findings   | Mode       |
| 15         | 203        | Passive    |
+------------+------------+------------+

+------------------------------------------------------+
| Type          | Value           | Source JS          |
+------------------------------------------------------+
| Endpoint      | /api/user       | app.js             |
| Query Param   | token           | auth.js            |
| JSON Key      | username        | login.js           |
+------------------------------------------------------+
```

---

# Requirements

* Java 21
* Burp Suite Community or Professional
* Gradle Wrapper

---

# Installation

## 1. Clone or create project

```powershell
mkdir br3k-js
cd br3k-js
```

---

## 2. Generate Gradle Wrapper

```powershell
gradle wrapper --gradle-version 9.0.0
```

---

## 3. Build extension

```powershell
.\gradlew.bat clean jar
```

Output:

```text
build\libs\br3k-js-1.0.0.jar
```

---

# Load Extension into Burp

```text
Burp Suite
→ Extensions
→ Installed
→ Add
→ Extension type: Java
→ Select:
build\libs\br3k-js-1.0.0.jar
```

---

# Usage

## Step 1

Enable Burp Proxy.

---

## Step 2

Browse the target application through Burp.

---

## Step 3

Open the `br3k-js` tab.

---

## Step 4

Review extracted:

* endpoints
* parameters
* headers
* JSON keys
* FormData keys

---

## Step 5

Export findings to CSV if needed.

---

# CSV Export Example

```csv
Type,Value,Source JS
Endpoint,/api/login,auth.js
Query Param,token,main.js
JSON Key,username,login.js
```

---

# Architecture

```text
Browser
   ↓
Burp Proxy
   ↓
br3k-js Extension
   ↓
JavaScript Analyzer
   ↓
UI Table + CSV Export
```

---

# Detection Logic

## Endpoint Regex

```regex
["']((?:https?:)?//[^"']+|/[a-zA-Z0-9_./?=&%-]{2,})["']
```

---

## Query Parameter Regex

```regex
[?&]([a-zA-Z0-9_\-]{2,})=
```

---

## JSON Key Regex

```regex
["']([a-zA-Z0-9_\-]{2,})["']\s*:
```

---

# Future Features

Planned:

* GraphQL detection
* JWT detection
* Secret scanning
* WebSocket route detection
* JS beautifier
* Source map parser
* AST parsing
* Passive scanner issues
* Context menu integration
* Request replay

---

# Legal Notice

Use only on systems you own or are explicitly authorized to test.

The author is not responsible for misuse.

---

# Tech Stack

* Java 21
* Burp Montoya API
* Swing UI
* Gradle Wrapper

---

# License

MIT
