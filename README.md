# Directory Structure Viewer

![PHP](https://img.shields.io/badge/PHP-7.4%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Self Hosted](https://img.shields.io/badge/self--hosted-yes-brightgreen)
![Lightweight](https://img.shields.io/badge/dependencies-none-lightgrey)

A lightweight **web-based tool for exploring directory structures across multiple repositories** and quickly extracting file contents for development workflows.

This tool is especially useful when working with **AI coding assistants or AI agents**, allowing developers to quickly browse a project, select relevant files, and copy their contents into prompts.

Built with **PHP (backend)** and **Vue.js (frontend)**.
Designed to be **self-hosted, simple, and fast**.

---

# Why This Project Exists

When working with AI coding tools, developers often need to:

* inspect a repository structure
* select a few relevant files
* copy file contents
* provide them as context to an AI assistant

Doing this manually is slow and repetitive.

**Directory Structure Viewer** solves this by providing:

* a quick way to browse repositories
* a workspace to collect relevant files
* instant access to file contents
* easy copy/download functionality

This makes it much easier to **prepare context for AI agents**.

---

# Features

* Browse **multiple repositories or base directories**
* View directory structures in a **tree layout**
* Select files and add them to a **working space**
* Preview file contents directly in the browser
* Download individual files or selected files
* Quickly copy code snippets for use with AI prompts
* Lightweight architecture (no database required)
* Token-based authentication
* Simple JSON-based configuration

---

# Screenshot

<p align="center">
  <img src="screenshot.png" width="100%">
</p>

---

# Requirements

* PHP 7.4 or newer
* Web server (Apache, Nginx, Caddy, etc.)

No database required.

---

# Installation

Clone the repository:

```bash
git clone https://github.com/cloudpad9/directory-structure-viewer.git
cd directory-structure-viewer
```

Create runtime configuration files:

```bash
cp users.example.json users.json
cp tokens.example.json tokens.json
cp auth_tokens.example.json auth_tokens.json
```

Ensure the web server has write permission for these files.

Example:

```bash
chmod 664 *.json
```

---

# Running the Application

Place the project in your web server directory.

Example:

```
/var/www/html/directory-structure-viewer
```

Then open the application in your browser:

```
http://localhost/directory-structure-viewer
```

---

# Authentication

The application uses **token-based authentication**.

Workflow:

1. User logs in using username and password
2. The server generates a secure authentication token
3. The token is used for subsequent API requests
4. Tokens automatically expire after a configurable time

Authentication data is stored in:

```
users.json
auth_tokens.json
```

---

# Security Notes

* Passwords are stored using **bcrypt hashing**
* Login attempts are **rate limited**
* Authentication tokens are **cryptographically secure**
* Tokens automatically expire

For production deployments, it is recommended to:

* enable **HTTPS**
* optionally protect the app using **web server authentication**
* restrict access using **IP whitelisting**

---

# Project Structure

```
.
├── api.php
├── change_password.php
├── index.html
├── users.example.json
├── tokens.example.json
├── auth_tokens.example.json
├── .gitignore
└── README.md
```

---

# Configuration Files

Runtime data is stored in JSON files.

| File             | Purpose                      |
| ---------------- | ---------------------------- |
| users.json       | User accounts                |
| tokens.json      | Login attempt tracking       |
| auth_tokens.json | Active authentication tokens |

These files are ignored by Git via `.gitignore`.

---

# Typical Workflow

A common workflow when working with AI coding assistants:

1. Open the repository in **Directory Structure Viewer**
2. Browse the project structure
3. Select the files relevant to the task
4. Add them to the **working space**
5. Copy or download the file contents
6. Provide them as context to an AI agent

This makes it much easier to **prepare structured input for AI tools**.

---

# Use Cases

* Preparing project context for AI coding assistants
* Exploring unfamiliar codebases
* Quickly copying relevant source files
* Lightweight internal developer tooling
* Remote repository browsing

---

# Contributing

Contributions are welcome.

If you'd like to improve the project:

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

---

# License

MIT License

---

# Keywords

directory structure viewer
file tree explorer
web file browser
developer tool
AI coding workflow
self hosted developer utilities
