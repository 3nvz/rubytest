# Intentionally vulnerable demo app (for local training only).
# DO NOT deploy to the internet.

require "sinatra"
require "sqlite3"
require "securerandom"

set :bind, "0.0.0.0"
set :port, 4567
enable :sessions

DB_PATH = File.expand_path("db/app.db", __dir__)

def db
  @db ||= SQLite3::Database.new(DB_PATH).tap { |d| d.results_as_hash = true }
end

helpers do
  def current_user
    return nil unless session[:user_id]
    db.get_first_row("SELECT id, username FROM users WHERE id = ?", session[:user_id])
  end

  def require_login!
    redirect "/login" unless current_user
  end
end

get "/" do
  @me = current_user
  erb :index
end

# -------- Vuln #1: SQL Injection in login --------
# Unsafely concatenates user input directly into SQL.
get "/login" do
  erb :login
end

post "/login" do
  u = params["username"].to_s
  p = params["password"].to_s

  # VULNERABLE: SQLi
  sql = "SELECT id, username FROM users WHERE username='#{u}' AND password='#{p}'"
  user = db.get_first_row(sql)

  if user
    session[:user_id] = user["id"]
    redirect "/notes"
  else
    @error = "Invalid credentials"
    erb :login
  end
end


post "/logout" do
  session.clear
  redirect "/"
end

# -------- Notes --------
get "/notes" do
  require_login!
  @me = current_user
  # Shows only *your* notes on the list page...
  @notes = db.execute("SELECT id, title FROM notes WHERE owner_id = ?", @me["id"])
  erb :notes
end

# -------- Vuln #5: Zip Slip via ZIP export --------
# User-controlled filenames inside ZIP archive
get "/notes/export" do
  require_login!
  me = current_user

  notes = db.execute(
    "SELECT title, content FROM notes WHERE owner_id = ?",
    me["id"]
  )

  zip_name = "notes_#{me['username']}.zip"
  zip_path = File.join(Dir.tmpdir, zip_name)

  require "zip"

  Zip::File.open(zip_path, Zip::File::CREATE) do |zip|
    notes.each_with_index do |note, idx|
      # VULNERABLE: title is user-controlled → path traversal
      entry_name = "#{note['title']}.txt"
      zip.get_output_stream(entry_name) do |f|
        f.write(note["content"])
      end
    end
  end

  send_file zip_path, filename: zip_name, type: "application/zip"
end

post "/notes/import" do
  require_login!
  me = current_user

  # Attacker-controlled file path
  path = params["path"].to_s

  begin
    raw = File.read(path)   # VULNERABLE
    data = JSON.parse(raw)

    data.each do |note|
      db.execute(
        "INSERT INTO notes (owner_id, title, content) VALUES (?, ?, ?)",
        me["id"],
        note["title"].to_s,
        note["content"].to_s
      )
    end

    redirect "/notes"
  rescue => e
    halt 500, "Import failed: #{e.message}"
  end
end

get "/admin/logs" do
  require_login!
  me = current_user

  # Intended: only admins should access this
  # Reality: no role check

  log_file = params["file"] || "app.log"

  begin
    # VULNERABLE: user controls file path
    @log_data = File.read(log_file)
  rescue => e
    @log_data = "Error reading log: #{e.message}"
  end

  erb :logs
end

get "/template/preview" do
  require_login!

  template = params["tpl"].to_s

  begin
    # VULNERABLE: user input rendered as ERB
    @output = ERB.new(template).result(binding)
  rescue => e
    @output = "Template error: #{e.message}"
  end

  erb :template_preview
end


# -------- Vuln #2: IDOR (Broken Access Control) --------
# Fetches notes by ID without checking ownership.
get "/note/:id" do
  require_login!
  @me = current_user
  nid = params["id"].to_i
  @note = db.get_first_row("SELECT id, title, content, owner_id FROM notes WHERE id = ?", nid)
  halt 404, "Not found" unless @note
  erb :note
end

post "/webhook/test" do
  require_login!

  url = params["url"].to_s
  payload = params["payload"].to_s

  begin
    uri = URI.parse(url)

    # VULNERABLE: no allowlist, no scheme/host validation
    res = Net::HTTP.post(
      uri,
      payload,
      { "Content-Type" => "application/json" }
    )

    @result = "Status: #{res.code}\n\n#{res.body}"
  rescue => e
    @result = "Request failed: #{e.message}"
  end

  erb :webhook_test
end

post "/notes/restore" do
  require_login!
  me = current_user

  yaml_data = params["backup"].to_s

  begin
    # VULNERABLE: unsafe deserialization
    data = YAML.load(yaml_data)

    data.each do |note|
      db.execute(
        "INSERT INTO notes (owner_id, title, content) VALUES (?, ?, ?)",
        me["id"],
        note["title"].to_s,
        note["content"].to_s
      )
    end

    redirect "/notes"
  rescue => e
    halt 500, "Restore failed: #{e.message}"
  end
end

post "/image/resize" do
  require_login!

  image = params["image"].to_s
  width = params["width"].to_s
  height = params["height"].to_s

  output = "/tmp/resized_#{SecureRandom.hex(4)}.png"

  # VULNERABLE: shell command injection
  cmd = "convert #{image} -resize #{width}x#{height} #{output}"
  result = `#{cmd}`

  "Image resized and saved to #{output}<br><pre>#{result}</pre>"
end

post "/plugins/load" do
  require_login!

  plugin = params["plugin"].to_s

  begin
    # VULNERABLE: user-controlled require
    require plugin

    @status = "Plugin loaded: #{plugin}"
  rescue => e
    @status = "Failed to load plugin: #{e.message}"
  end

  erb :plugin_loader
end

get "/auth/github" do
  # Generate state but never store it
  state = SecureRandom.hex(16)

  redirect "https://github.com/login/oauth/authorize" \
           "?client_id=dummy_client_id" \
           "&redirect_uri=http://localhost:4567/auth/github/callback" \
           "&state=#{state}"
end

get "/auth/github/callback" do
  code  = params["code"]
  state = params["state"]

  # VULNERABLE:
  # - state is never checked
  # - attacker-controlled OAuth response accepted blindly

  # Simulate GitHub user identity returned from token exchange
  github_username = params["user"] || "attacker"

  # Auto-provision user
  user = db.get_first_row(
    "SELECT id FROM users WHERE username = ?",
    github_username
  )

  unless user
    db.execute(
      "INSERT INTO users (username, password) VALUES (?, ?)",
      github_username,
      SecureRandom.hex(8)
    )
    user = db.get_first_row(
      "SELECT id FROM users WHERE username = ?",
      github_username
    )
  end

  session[:user_id] = user["id"]
  redirect "/"
end


get "/password/reset" do
  erb :password_reset_request
end

post "/password/reset" do
  user = db.get_first_row(
    "SELECT id FROM users WHERE username = ?",
    params["username"].to_s
  )

  if user
    token = SecureRandom.hex(16)

    # Token stored but NEVER expires or invalidates
    db.execute(
      "UPDATE users SET reset_token = ? WHERE id = ?",
      token,
      user["id"]
    )

    @link = "http://localhost:4567/password/reset/#{token}"
  end

  erb :password_reset_sent
end

get "/password/reset/:token" do
  @token = params["token"]
  erb :password_reset_form
end

post "/password/reset/:token" do
  token = params["token"].to_s
  new_pw = params["password"].to_s

  user = db.get_first_row(
    "SELECT id FROM users WHERE reset_token = ?",
    token
  )

  halt 400, "Invalid token" unless user

  # Password updated…
  db.execute(
    "UPDATE users SET password = ? WHERE id = ?",
    new_pw,
    user["id"]
  )

  # VULNERABLE: reset_token NOT cleared
  redirect "/login"
end

# -------- Vuln #3: Stored XSS + Missing CSRF --------
# Stores arbitrary HTML/JS in note content; later rendered without escaping.
get "/note/new" do
  require_login!
  erb :new_note
end

post "/note" do
  require_login!
  me = current_user
  title = params["title"].to_s
  content = params["content"].to_s
  db.execute("INSERT INTO notes (owner_id, title, content) VALUES (?, ?, ?)", me["id"], title, content)
  redirect "/notes"
end

# -------- Vuln #4: Reflected XSS --------
get "/search" do
  @q = params["q"].to_s
  erb :search
end

get "/profile" do
  require_login!
  @me = current_user
  erb :profile
end

post "/profile" do
  require_login!
  me = current_user

  # VULNERABLE: blindly updating all params
  params.each do |k, v|
    next if k == "captures" || k == "splat"
    db.execute(
      "UPDATE users SET #{k} = ? WHERE id = ?",
      v.to_s,
      me["id"]
    )
  end

  redirect "/profile"
end

get "/invite/accept/:token" do
  require_login!
  token = params["token"]

  invite = db.get_first_row(
    "SELECT * FROM invites WHERE token = ?",
    token
  )

  halt 404, "Invalid invite" unless invite
  halt 400, "Invite already used" if invite["used"] == 1

  erb :invite_accept
end

post "/invite/accept/:token" do
  require_login!
  token = params["token"]
  me = current_user

  invite = db.get_first_row(
    "SELECT * FROM invites WHERE token = ?",
    token
  )

  halt 404, "Invalid invite" unless invite
  halt 400, "Invite already used" if invite["used"] == 1

  # VULNERABLE:
  # - no transaction
  # - no locking
  # - race window here

  db.execute(
    "UPDATE users SET role = ? WHERE id = ?",
    invite["role"],
    me["id"]
  )

  db.execute(
    "UPDATE invites SET used = 1 WHERE id = ?",
    invite["id"]
  )

  redirect "/"
end
