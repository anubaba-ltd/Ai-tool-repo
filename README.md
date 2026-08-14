# Production Safe Tool Portal - MySQL Version

This version saves all portal data in MySQL database `tool_portal` instead of a JSON file.

## Features

- Admin login
- User login
- Admin user CRUD
- Admin tool CRUD
- Editor role with tool-only create, edit, and delete access
- Tool expiry hours metadata
- Extension download button
- Browser extension installation instructions
- User tool dashboard
- Usage logs saved in MySQL
- Single active session per email/account
- Auto database/table creation on first run

## Local setup with XAMPP / MySQL

### 1. Start MySQL

Open XAMPP Control Panel and start **MySQL**.

### 2. Create database

Open phpMyAdmin:

```text
http://localhost/phpmyadmin
```

Create a new database named:

```text
tool_portal
```

You do not need to create tables manually. The app creates tables automatically on first run.

### 3. Configure .env

Copy `.env.example` to `.env`.

For XAMPP default MySQL, use:

```env
PORT=3000
SESSION_SECRET=change-this-long-random-secret
APP_NAME=Safe Tool Portal

MYSQL_HOST=localhost
MYSQL_PORT=3306
MYSQL_USER=root
MYSQL_PASSWORD=
MYSQL_DATABASE=tool_portal
```

If your MySQL has a password, add it in `MYSQL_PASSWORD`.

### 4. Install dependencies

```bash
npm install
```

### 5. Run the project

```bash
npm start
```

Open:

```text
http://localhost:3000
```

## Default logins

The app seeds these users only when the `users` table is empty:

```text
Admin: admin@example.com / ChangeMe123!
User: user@example.com / User123!
```

## Database tables created automatically

- `users`
- `tools`
- `logs`

## Single-login restriction

Only one active browser/device session is allowed per user email. When the same email logs in on another device/browser, the previous device is automatically logged out on its next request and sees a session expired message.

## Extension install instructions

1. Login as a user.
2. Click **Download Extension**.
3. Extract the downloaded ZIP.
4. Open Chrome/Edge and go to `chrome://extensions`.
5. Enable **Developer mode**.
6. Click **Load unpacked**.
7. Select the extracted extension folder.

## Hostinger note

If you are using Hostinger Premium shared hosting, Node.js apps may not run unless your plan supports Node.js. For this Node.js version, use Hostinger Business/Cloud Node.js app support, VPS, Render, Railway, or another Node.js host.
