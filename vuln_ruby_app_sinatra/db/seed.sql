-- Seed data (two users + notes)
INSERT OR IGNORE INTO users (id, username, password) VALUES
  (1, 'alice', 'password123'),
  (2, 'bob',   'letmein');

INSERT OR IGNORE INTO notes (id, owner_id, title, content) VALUES
  (1, 1, 'Alice Note 1', 'Hello from Alice.'),
  (2, 1, 'Alice Secret', 'Alice secret: <b>do not share</b>.'),
  (3, 2, 'Bob Note 1',   'Hello from Bob.'),
  (4, 2, 'Bob Draft',    'Try XSS: <script>alert("stored xss")</script>');
