const Database = require('better-sqlite3');
const path = require('path');

try {
  const dbPath = path.join(__dirname, '..', 'db.sqlite');
  const db = new Database(dbPath);
  const info = db.prepare('DELETE FROM users').run();
  console.log(`Users cleared. Deleted rows: ${info.changes}`);
  process.exit(0);
} catch (e) {
  console.error('Failed to clear users:', e);
  process.exit(1);
}
