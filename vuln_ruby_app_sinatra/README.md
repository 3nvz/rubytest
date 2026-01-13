# vuln_ruby_app_sinatra (Intentionally Vulnerable)

A **small intentionally vulnerable** Ruby app built with Sinatra + SQLite.
Designed for **local security training** (SQLi, IDOR, XSS, missing CSRF).

⚠️ DO NOT deploy this app to the internet.

## Requirements
- Ruby (3.x recommended)
- Bundler (`gem install bundler`)

## Install & Run
```bash
bundle install
ruby db/init_db.rb
ruby app.rb
```

Then open:
- http://localhost:4567

## Demo Users
- alice / password123
- bob / letmein

## Vulnerable Endpoints (for learning)
1) SQL Injection: `POST /login`
   - SQL string concatenation using `username` and `password`.

2) IDOR: `GET /note/:id`
   - No ownership check; logged-in users can access other users' notes by ID.

3) Stored XSS + No CSRF: `POST /note`
   - Content is stored and later rendered without escaping.

4) Reflected XSS: `GET /search?q=...`
   - Query is echoed directly into HTML.

## Reset DB
Delete `db/app.db` and re-run:
```bash
ruby db/init_db.rb
```
