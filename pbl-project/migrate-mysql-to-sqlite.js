const mysql = require('mysql2/promise');
const Database = require('better-sqlite3');

(async () => {
  // read MySQL credentials from env or change here
  const host = process.env.MYSQL_HOST || 'localhost';
  const user = process.env.MYSQL_USER || 'root';
  const password = process.env.MYSQL_PASS || process.env.MYSQL_PASSWORD || '';
  const database = process.env.MYSQL_DB || 'cricketdb';

  if (!password) {
    console.error('Set MYSQL_PASS (or MYSQL_PASSWORD) environment variable with your MySQL password.');
    process.exit(1);
  }

  console.log('Connecting to MySQL...');
  const mysqlConn = await mysql.createConnection({ host, user, password, database });

  console.log('Opening SQLite db.sqlite...');
  const sqlite = new Database('./db.sqlite');

  // create tables in sqlite if missing (same schema as server.js)
  sqlite.prepare(`
    CREATE TABLE IF NOT EXISTS teams (
      team_id TEXT PRIMARY KEY,
      team_name TEXT,
      country_name TEXT,
      team_rank INTEGER,
      no_of_wins INTEGER DEFAULT 0,
      no_of_loses INTEGER DEFAULT 0,
      no_of_draws INTEGER DEFAULT 0
    )`).run();

  sqlite.prepare(`
    CREATE TABLE IF NOT EXISTS players (
      player_id TEXT PRIMARY KEY,
      player_name TEXT,
      team_id TEXT,
      batting_average REAL,
      no_of_totalruns INTEGER DEFAULT 0,
      no_of_wickets INTEGER DEFAULT 0,
      type_of_bowler TEXT,
      no_of_sixes INTEGER DEFAULT 0
    )`).run();

  sqlite.prepare(`
    CREATE TABLE IF NOT EXISTS matches (
      match_id TEXT PRIMARY KEY,
      match_date TEXT,
      match_time TEXT,
      team_1_name TEXT,
      team_2_name TEXT,
      winner TEXT,
      stadium TEXT
    )`).run();

  sqlite.prepare(`
    CREATE TABLE IF NOT EXISTS umpires (
      umpire_id TEXT PRIMARY KEY,
      umpire_name TEXT,
      country TEXT,
      no_of_matches INTEGER DEFAULT 0
    )`).run();

  async function copyTable(tbl, cols) {
    console.log(`Copying ${tbl}...`);
    const [rows] = await mysqlConn.execute(`SELECT ${cols.join(', ')} FROM ${tbl}`);
    const insertSql = `INSERT OR REPLACE INTO ${tbl} (${cols.join(', ')}) VALUES (${cols.map(c => '?').join(', ')})`;
    const stmt = sqlite.prepare(insertSql);
    const tx = sqlite.transaction((items) => {
      for (const r of items) {
        const vals = cols.map(c => r[c]);
        stmt.run(vals);
      }
    });
    tx(rows);
    console.log(`${tbl}: ${rows.length} rows copied.`);
  }

  try {
    await copyTable('teams', ['team_id','team_name','country_name','team_rank','no_of_wins','no_of_loses','no_of_draws']);
    await copyTable('players', ['player_id','player_name','team_id','batting_average','no_of_totalruns','no_of_wickets','type_of_bowler','no_of_sixes']);
    await copyTable('matches', ['match_id','match_date','match_time','team_1_name','team_2_name','winner','stadium']);
    await copyTable('umpires', ['umpire_id','umpire_name','country','no_of_matches']);
    console.log('Migration complete.');
  } catch (e) {
    console.error('Migration error:', e.message);
  } finally {
    await mysqlConn.end();
    sqlite.close();
  }
})();