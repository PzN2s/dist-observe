//! Lightweight time-series store: SQLite (bundled, no server needed).
//! Multi-node ready: every row carries a `node` id; old single-node DBs are
//! migrated automatically (node defaults to 'local').
use crate::collect::snapshot::UnifiedSnapshot;
use anyhow::Result;
use rusqlite::{params, Connection};

pub struct Store {
    conn: Connection,
}

fn has_column(conn: &Connection, col: &str) -> bool {
    let mut stmt = match conn.prepare("PRAGMA table_info(snapshots)") {
        Ok(s) => s,
        Err(_) => return false,
    };
    let names: Vec<String> = stmt
        .query_map([], |r| r.get::<_, String>(1))
        .map(|rows| rows.filter_map(|r| r.ok()).collect())
        .unwrap_or_default();
    names.iter().any(|n| n == col)
}

fn table_sql(conn: &Connection) -> String {
    conn.query_row(
        "SELECT sql FROM sqlite_master WHERE name='snapshots'",
        [],
        |r| r.get::<_, String>(0),
    )
    .unwrap_or_default()
}

/// Rebuild with composite PRIMARY KEY(node, wall_ns): the old single-node
/// schema (PK on wall_ns alone) cannot express per-node uniqueness, and
/// SQLite upsert will not bind ON CONFLICT(node, wall_ns) to a secondary
/// index while a rowid PK exists. Data is preserved.
fn rebuild_composite(conn: &Connection, has_node: bool) -> Result<()> {
    let node_expr = if has_node { "node" } else { "'local'" };
    conn.execute_batch(&format!(
        "CREATE TABLE snapshots_new(
            node TEXT NOT NULL,
            wall_ns INTEGER NOT NULL,
            mono_ns INTEGER NOT NULL,
            wall_iso TEXT NOT NULL,
            hostname TEXT NOT NULL,
            cpu_total REAL NOT NULL,
            mem_used_pct REAL NOT NULL,
            disk_used_pct REAL NOT NULL,
            json TEXT NOT NULL,
            PRIMARY KEY(node, wall_ns)
        );
        INSERT INTO snapshots_new
            (node, wall_ns, mono_ns, wall_iso, hostname, cpu_total, mem_used_pct, disk_used_pct, json)
            SELECT {node_expr}, wall_ns, mono_ns, wall_iso, hostname, cpu_total, mem_used_pct, disk_used_pct, json
            FROM snapshots;
        DROP TABLE snapshots;
        ALTER TABLE snapshots_new RENAME TO snapshots;"
    ))?;
    Ok(())
}

impl Store {
    pub fn open(path: &str) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS snapshots(
                node TEXT NOT NULL,
                wall_ns INTEGER NOT NULL,
                mono_ns INTEGER NOT NULL,
                wall_iso TEXT NOT NULL,
                hostname TEXT NOT NULL,
                cpu_total REAL NOT NULL,
                mem_used_pct REAL NOT NULL,
                disk_used_pct REAL NOT NULL,
                json TEXT NOT NULL,
                PRIMARY KEY(node, wall_ns)
            );",
        )?;
        // Migrate legacy single-node schema (PK on wall_ns alone, maybe no node col).
        if !table_sql(&conn).contains("PRIMARY KEY(node, wall_ns)") {
            rebuild_composite(&conn, has_column(&conn, "node"))?;
        }
        Ok(Self { conn })
    }

    pub fn insert(&mut self, node: &str, s: &UnifiedSnapshot) -> Result<()> {
        let json = serde_json::to_string(s)?;
        self.conn.execute(
            "INSERT INTO snapshots
             (wall_ns, mono_ns, wall_iso, hostname, cpu_total, mem_used_pct, disk_used_pct, json, node)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)
             ON CONFLICT(node, wall_ns) DO UPDATE SET
               mono_ns=excluded.mono_ns, wall_iso=excluded.wall_iso,
               hostname=excluded.hostname, cpu_total=excluded.cpu_total,
               mem_used_pct=excluded.mem_used_pct, disk_used_pct=excluded.disk_used_pct,
               json=excluded.json",
            params![
                s.ts.wall_ns as i64,
                s.ts.mono_ns as i64,
                s.ts.wall_iso,
                s.hostname,
                s.cpu.total_pct,
                s.mem.used_pct,
                s.disk.used_pct,
                json,
                node,
            ],
        )?;
        Ok(())
    }

    /// Last N points as (wall_seconds, mem_pct, disk_pct), optionally per node.
    pub fn recent_series(&mut self, limit: usize) -> Result<Vec<(f64, f64, f64)>> {
        self.series_for(None, limit)
    }

    pub fn series_for(
        &mut self,
        node: Option<&str>,
        limit: usize,
    ) -> Result<Vec<(f64, f64, f64)>> {
        let (sql, param): (String, Option<String>) = match node {
            Some(n) => (
                "SELECT wall_ns, mem_used_pct, disk_used_pct FROM snapshots
                 WHERE node = ?1 ORDER BY wall_ns DESC LIMIT ?2"
                    .into(),
                Some(n.to_string()),
            ),
            None => (
                "SELECT wall_ns, mem_used_pct, disk_used_pct FROM snapshots
                 ORDER BY wall_ns DESC LIMIT ?1"
                    .into(),
                None,
            ),
        };
        let mut stmt = self.conn.prepare(&sql)?;
        let map_row = |r: &rusqlite::Row| {
            Ok((
                r.get::<_, i64>(0)? as f64 / 1e9,
                r.get::<_, f64>(1)?,
                r.get::<_, f64>(2)?,
            ))
        };
        let mut v: Vec<(f64, f64, f64)> = match param {
            Some(n) => stmt
                .query_map(params![n, limit as i64], map_row)?
                .filter_map(|r| r.ok())
                .collect(),
            None => stmt
                .query_map(params![limit as i64], map_row)?
                .filter_map(|r| r.ok())
                .collect(),
        };
        v.reverse(); // chronological
        Ok(v)
    }

    pub fn count(&mut self) -> Result<usize> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM snapshots", [], |r| r.get(0))?;
        Ok(n as usize)
    }

    /// All snapshots in chronological order (for offline replay).
    pub fn all_snapshots(&mut self) -> Result<Vec<crate::collect::snapshot::UnifiedSnapshot>> {
        let mut stmt = self
            .conn
            .prepare("SELECT json FROM snapshots ORDER BY wall_ns")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        Ok(rows
            .filter_map(|r| r.ok())
            .filter_map(|j| serde_json::from_str(&j).ok())
            .collect())
    }

    pub fn ensure_runs_table(&self) -> Result<()> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS runs(
                input_id TEXT NOT NULL,
                worker TEXT NOT NULL,
                wall_ns INTEGER NOT NULL,
                mono_ns INTEGER NOT NULL,
                wall_iso TEXT NOT NULL,
                input_hash TEXT NOT NULL,
                output_hash TEXT NOT NULL,
                output_f64 REAL NOT NULL,
                order_desc TEXT NOT NULL,
                order_seed INTEGER NOT NULL,
                input_len INTEGER NOT NULL,
                input_abs_sum REAL NOT NULL,
                snapshot_json TEXT NOT NULL,
                PRIMARY KEY(input_id, worker, wall_ns)
            );",
        )?;
        Ok(())
    }

    pub fn insert_run(&mut self, r: &crate::nondet::WorkerRun) -> Result<()> {
        self.ensure_runs_table()?;
        self.conn.execute(
            "INSERT OR REPLACE INTO runs
             (input_id, worker, wall_ns, mono_ns, wall_iso, input_hash, output_hash,
              output_f64, order_desc, order_seed, input_len, input_abs_sum, snapshot_json)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
            params![
                r.input_id,
                r.worker,
                r.wall_ns as i64,
                r.mono_ns as i64,
                r.wall_iso,
                r.input_hash,
                r.output_hash,
                r.output_f64,
                r.order_desc,
                r.order_seed as i64,
                r.input_len as i64,
                r.input_abs_sum,
                r.snapshot_json,
            ],
        )?;
        Ok(())
    }

    pub fn runs_for_input(
        &mut self,
        input_id: &str,
    ) -> Result<Vec<crate::nondet::WorkerRun>> {
        self.ensure_runs_table()?;
        let mut stmt = self.conn.prepare(
            "SELECT input_id, worker, wall_ns, mono_ns, wall_iso, input_hash, output_hash,
                    output_f64, order_desc, order_seed, input_len, input_abs_sum, snapshot_json
             FROM runs WHERE input_id = ?1 ORDER BY wall_ns",
        )?;
        let rows = stmt.query_map(params![input_id], |r| {
            Ok(crate::nondet::WorkerRun {
                input_id: r.get(0)?,
                worker: r.get(1)?,
                wall_ns: r.get::<_, i64>(2)? as u64,
                mono_ns: r.get::<_, i64>(3)? as u64,
                wall_iso: r.get(4)?,
                input_hash: r.get(5)?,
                output_hash: r.get(6)?,
                output_f64: r.get(7)?,
                order_desc: r.get(8)?,
                order_seed: r.get::<_, i64>(9)? as u64,
                input_len: r.get::<_, i64>(10)? as usize,
                input_abs_sum: r.get(11)?,
                snapshot_json: r.get(12)?,
            })
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }
}
