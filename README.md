# br3k-js

Passive JavaScript endpoint & parameter extractor for Burp Suite.

---

# Features

## JavaScript & HTML script Detection

Automatically detects and analyzes JavaScript and HTML script blocks based on:

* `.js` and `.html` file extensions
* `Content-Type: javascript`, `Content-Type: ecmascript`, or `Content-Type: html`
* Extracts and scans inline JavaScript code inside `<script>` blocks in HTML pages

---

## Manual Scan (Context Menu Integration)

* Right-click one or multiple HTTP requests inside **HTTP History** (or other Burp Suite tools like Target/Repeater).
* Select **"Analyze JS/HTML in br3k-js"** to run a manual on-demand analysis on selected items asynchronously without blocking the UI.

---

## Scope & HTML Filtering

* **Only In-Scope Filter**: An option to only analyze in-scope targets, dramatically reducing out-of-scope widget and analytics noise.
* **Analyze HTML Toggle**: Easily enable/disable analysis of HTML script tags on the fly.

---

## Interactive UI Filters

* **Real-time Search Bar**: Type in the search box to immediately filter findings by type, value, or source URL.
* **Category Type Filter**: Dropdown menu to filter results by type (`Endpoint`, `Query Param`, `JSON Key`, `FormData Key`, `Header`).
* **Visible / Total Findings Count**: Shows filtered results out of the total findings dynamically (e.g., `25 / 203`).

---

## Endpoint Extraction

Extracts paths and full URLs:

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

Detects query parameters from strings and modern JS methods (such as `URLSearchParams.append`):

```text
?id=
&page=
&token=
```

Example findings:

* `userId`
* `session`
* `redirect`
* `callback`
* `access_token`

---

## JSON Key Extraction

Extracts JSON body keys and modern JavaScript object properties (including unquoted keys like `{ username: "admin" }`):

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

Detects keys appended to multipart/form-data objects:

```javascript
formData.append("file", file)
```

Useful for:

* upload endpoints
* multipart forms
* hidden form parameters

---

## Header Extraction

Extracts sensitive or custom headers matching API keys, tokens, or common auth formats:

```text
Authorization
X-Api-Key
X-CSRF-Token
Content-Type
X-Auth-Token
```

---

# Screenshots

## Main UI

```text
+------------------------------------------------------+
| br3k-js                                              |
| Passive JavaScript endpoint & parameter extractor    |
+------------------------------------------------------+

+-------------------+------------+------------+
| JS & HTML Files   | Findings   | Mode       |
| 15                | 203        | Passive    |
+-------------------+------------+------------+

+------------------------------------------------------+
| [Clear Results] [Export CSV]      [ ] Only In-Scope  |
|                                   [x] Analyze HTML   |
|                                                      |
| Filter Search: [           ]  Filter Type: [All    ] |
+------------------------------------------------------+

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

Enable Burp Proxy or select existing traffic in Burp Suite.

---

## Step 2

Browse the target application or right-click selected items in **HTTP History** and choose **"Analyze JS/HTML in br3k-js"**.

---

## Step 3

Open the `br3k-js` tab.

---

## Step 4

Review and filter extracted findings:

* Search for specific keywords using **Filter Search**.
* Drill down using **Filter Type** dropdown.

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
Browser / HTTP History
   ↓
br3k-js Extension (Passive HTTP Interceptor / Manual Trigger)
   ↓
Scope / HTML Filters check
   ↓
JavaScript & Script Block Parser
   ↓
Interactive UI Table (with Search, Type Filters & CSV Export)
```

---

# Detection Logic

All patterns are compiled with case-insensitive features and support backticks (`` ` ``) for template literal support.

## Endpoint Regex

```regex
["`']((?:https?:)?//[^"`']+|/[a-zA-Z0-9_./?=&%\-]{2,})["`']
```

---

## Query Parameter Regex

Matches standard parameters inside string values and `URLSearchParams` object append/set operations.

```regex
[?&]([a-zA-Z0-9_\-]{2,})=|(?:\bparams|\bsearchParams)\.(?:append|set|get|has)\(["'`]([a-zA-Z0-9_\-]{2,})["'`]
```

---

## JSON Key & Object Property Regex

Matches quoted JSON keys as well as modern unquoted object keys (e.g. `{ username: "admin" }`).

```regex
["`']([a-zA-Z0-9_\-]{2,})["`']\s*:|\b([a-zA-Z0-9_\-]{2,})\s*:\s*(?:["`'{]|-?\d|true|false|null|\[)
```

---

## HTML Script Tag Extraction Regex

```regex
<script[^>]*>(.*?)</script>
```

---

# Future Features

Planned:

* GraphQL schema detection
* JWT verification checks
* Secret / Token scanning (detect keys/passwords)
* WebSocket route detection
* JS beautifier
* Source map parser
* AST parsing
* Passive scanner issues reporter
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
