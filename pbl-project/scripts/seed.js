const Database = require('better-sqlite3');
const path = require('path');

try {
  const dbPath = path.join(__dirname, '..', 'db.sqlite');
  const db = new Database(dbPath);
  try { db.pragma('foreign_keys = ON'); } catch(_) {}

  // Create schema if missing (matches server.js)
  db.prepare(`
  CREATE TABLE IF NOT EXISTS teams (
    team_id TEXT PRIMARY KEY,
    team_name TEXT,
    country_name TEXT,
    team_rank INTEGER,
    no_of_wins INTEGER DEFAULT 0,
    no_of_loses INTEGER DEFAULT 0,
    no_of_draws INTEGER DEFAULT 0,
    deleted_at TEXT
  )`).run();
  db.prepare(`
  CREATE TABLE IF NOT EXISTS players (
    player_id TEXT PRIMARY KEY,
    player_name TEXT,
    team_id TEXT,
    batting_average REAL,
    no_of_totalruns INTEGER DEFAULT 0,
    no_of_wickets INTEGER DEFAULT 0,
    type_of_bowler TEXT,
    no_of_sixes INTEGER DEFAULT 0,
    economy REAL DEFAULT NULL,
    deleted_at TEXT
  )`).run();
  db.prepare(`
  CREATE TABLE IF NOT EXISTS matches (
    match_id TEXT PRIMARY KEY,
    match_date TEXT,
    match_time TEXT,
    team_1_name TEXT,
    team_2_name TEXT,
    winner TEXT,
    stadium TEXT,
    deleted_at TEXT
  )`).run();
  db.prepare(`
  CREATE TABLE IF NOT EXISTS umpires (
    umpire_id TEXT PRIMARY KEY,
    umpire_name TEXT,
    country TEXT,
    no_of_matches INTEGER DEFAULT 0,
    deleted_at TEXT
  )`).run();

  // Basic indexes
  db.prepare('CREATE INDEX IF NOT EXISTS idx_players_team ON players(team_id)').run();
  db.prepare('CREATE INDEX IF NOT EXISTS idx_teams_name ON teams(team_name)').run();

  const tx = db.transaction(() => {
    // Teams
    db.prepare(`INSERT OR IGNORE INTO teams (team_id, team_name, country_name, team_rank, no_of_wins, no_of_loses, no_of_draws, deleted_at)
                VALUES (@team_id,@team_name,@country_name,@team_rank,@no_of_wins,@no_of_loses,@no_of_draws,NULL)`).run({
      team_id: 'IND', team_name: 'India', country_name: 'India', team_rank: 1, no_of_wins: 100, no_of_loses: 50, no_of_draws: 10
    });
    db.prepare(`INSERT OR IGNORE INTO teams (team_id, team_name, country_name, team_rank, no_of_wins, no_of_loses, no_of_draws, deleted_at)
                VALUES ('AUS','Australia','Australia',2,95,55,8,NULL)`).run();
    db.prepare(`INSERT OR IGNORE INTO teams (team_id, team_name, country_name, team_rank, no_of_wins, no_of_loses, no_of_draws, deleted_at)
                VALUES ('ENG','England','England',3,88,60,12,NULL)`).run();

    // Players
    const insPlayer = db.prepare(`INSERT OR IGNORE INTO players (player_id, player_name, team_id, batting_average, no_of_totalruns, no_of_wickets, type_of_bowler, no_of_sixes, economy, deleted_at)
                                  VALUES (@player_id,@player_name,@team_id,@batting_average,@no_of_totalruns,@no_of_wickets,@type_of_bowler,@no_of_sixes,@economy,NULL)`);
    insPlayer.run({ player_id:'P1', player_name:'Virat Kohli', team_id:'IND', batting_average:56.5, no_of_totalruns:13000, no_of_wickets:4, type_of_bowler:null, no_of_sixes:150, economy:null });
    insPlayer.run({ player_id:'P2', player_name:'Rohit Sharma', team_id:'IND', batting_average:48.2, no_of_totalruns:12000, no_of_wickets:8, type_of_bowler:null, no_of_sixes:250, economy:null });
    insPlayer.run({ player_id:'P3', player_name:'Pat Cummins', team_id:'AUS', batting_average:20.1, no_of_totalruns:1200, no_of_wickets:250, type_of_bowler:'Pace', no_of_sixes:40, economy:4.5 });
    insPlayer.run({ player_id:'P4', player_name:'Joe Root', team_id:'ENG', batting_average:50.1, no_of_totalruns:11000, no_of_wickets:30, type_of_bowler:'Off spin', no_of_sixes:80, economy:5.2 });

    // Matches
    const insMatch = db.prepare(`INSERT OR IGNORE INTO matches (match_id, match_date, match_time, team_1_name, team_2_name, winner, stadium, deleted_at)
                                 VALUES (@match_id,@match_date,@match_time,@team_1_name,@team_2_name,@winner,@stadium,NULL)`);
    insMatch.run({ match_id:'M1', match_date:'2024-03-10', match_time:'18:30', team_1_name:'India', team_2_name:'Australia', winner:'India', stadium:'Wankhede' });
    insMatch.run({ match_id:'M2', match_date:'2024-05-02', match_time:'19:00', team_1_name:'England', team_2_name:'Australia', winner:'Australia', stadium:'Lords' });

    // Umpires
    const insUmp = db.prepare(`INSERT OR IGNORE INTO umpires (umpire_id, umpire_name, country, no_of_matches, deleted_at)
                               VALUES (@umpire_id,@umpire_name,@country,@no_of_matches,NULL)`);
    insUmp.run({ umpire_id:'U1', umpire_name:'Aleem Dar', country:'Pakistan', no_of_matches:150 });
    insUmp.run({ umpire_id:'U2', umpire_name:'Kumar Dharmasena', country:'Sri Lanka', no_of_matches:130 });
  });
  tx();
  console.log('Seed data inserted (idempotent).');
  process.exit(0);
} catch (e) {
  console.error('Failed to seed data:', e);
  process.exit(1);
}
