require "sqlite3"

DB_PATH = File.expand_path("app.db", __dir__)
SCHEMA  = File.expand_path("schema.sql", __dir__)
SEED    = File.expand_path("seed.sql", __dir__)

db = SQLite3::Database.new(DB_PATH)

schema = File.read(SCHEMA)
seed   = File.read(SEED)

db.execute_batch(schema)
db.execute_batch(seed)

puts "Initialized database at #{DB_PATH}"
