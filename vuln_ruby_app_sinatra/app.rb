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
