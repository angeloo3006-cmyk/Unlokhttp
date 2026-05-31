use std::path::PathBuf;
use std::sync::Mutex;

use rusqlite::{params, Connection, Result as SqlResult, Row};
use serde::{Deserialize, Serialize};

// ES: Tipos serializables compartidos con Tauri. / EN: Serializable types shared with Tauri.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: i64,
    pub name: Option<String>,
    pub interface: Option<String>,
    pub started_at: Option<String>,
    pub ended_at: Option<String>,
    pub total_packets: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketRow {
    pub id: i64,
    pub session_id: i64,
    pub ts: String,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub src_port: Option<i32>,
    pub dst_port: Option<i32>,
    pub protocol: Option<String>,
    pub length: Option<i32>,
    pub ttl: Option<i32>,
    pub flags: Option<String>,
    pub payload_hex: Option<String>,
    pub raw_ascii: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PacketFilters {
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub src_port: Option<u32>,
    pub dst_port: Option<u32>,
    pub protocol: Option<String>,
    pub min_length: Option<u32>,
    pub max_length: Option<u32>,
    pub search: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolStat {
    pub protocol: String,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimePoint {
    pub bucket: String,
    pub packets: i64,
    pub bytes: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopIp {
    pub ip: String,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticRow {
    pub id: i64,
    pub session_id: Option<i64>,
    pub ts: Option<String>,
    pub metric: Option<String>,
    pub value: Option<f64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PaginatedResult<T: Serialize> {
    pub items: Vec<T>,
    pub total: i64,
    pub page: u32,
    pub page_size: u32,
    pub total_pages: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DiagnosticsData {
    pub session_id: i64,
    pub protocol_stats: Vec<ProtocolStat>,
    pub traffic_timeline: Vec<TimePoint>,
    pub top_src_ips: Vec<TopIp>,
    pub top_dst_ips: Vec<TopIp>,
    pub total_packets: i64,
    pub total_bytes: i64,
    pub avg_packet_size: f64,
    pub recent_errors: Vec<DiagnosticRow>,
}

// ES: Construye filtros SQL con parametros enlazados para evitar inyeccion.
// EN: Builds SQL filters with bound parameters to prevent injection.
struct QueryBuilder {
    clauses: Vec<String>,
    values: Vec<Box<dyn rusqlite::types::ToSql>>,
}

impl QueryBuilder {
    fn new() -> Self {
        Self {
            clauses: Vec::new(),
            values: Vec::new(),
        }
    }

    fn eq<V>(&mut self, column: &str, value: V)
    where
        V: rusqlite::types::ToSql + 'static,
    {
        self.clauses
            .push(format!("{column} = ?{}", self.values.len() + 1));
        self.values.push(Box::new(value));
    }

    fn gte<V>(&mut self, column: &str, value: V)
    where
        V: rusqlite::types::ToSql + 'static,
    {
        self.clauses
            .push(format!("{column} >= ?{}", self.values.len() + 1));
        self.values.push(Box::new(value));
    }

    fn lte<V>(&mut self, column: &str, value: V)
    where
        V: rusqlite::types::ToSql + 'static,
    {
        self.clauses
            .push(format!("{column} <= ?{}", self.values.len() + 1));
        self.values.push(Box::new(value));
    }

    fn where_clause(&self) -> String {
        if self.clauses.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", self.clauses.join(" AND "))
        }
    }

    fn params(&self) -> Vec<&dyn rusqlite::types::ToSql> {
        self.values.iter().map(|b| b.as_ref()).collect()
    }
}

fn row_to_packet(row: &Row<'_>) -> SqlResult<PacketRow> {
    Ok(PacketRow {
        id: row.get(0)?,
        session_id: row.get(1)?,
        ts: row.get(2)?,
        src_ip: row.get(3)?,
        dst_ip: row.get(4)?,
        src_port: row.get(5)?,
        dst_port: row.get(6)?,
        protocol: row.get(7)?,
        length: row.get(8)?,
        ttl: row.get(9)?,
        flags: row.get(10)?,
        payload_hex: row.get(11)?,
        raw_ascii: row.get(12)?,
    })
}

fn row_to_session(row: &Row<'_>) -> SqlResult<Session> {
    Ok(Session {
        id: row.get(0)?,
        name: row.get(1)?,
        interface: row.get(2)?,
        started_at: row.get(3)?,
        ended_at: row.get(4)?,
        total_packets: row.get(5)?,
    })
}

fn row_to_diagnostic(row: &Row<'_>) -> SqlResult<DiagnosticRow> {
    Ok(DiagnosticRow {
        id: row.get(0)?,
        session_id: row.get(1)?,
        ts: row.get(2)?,
        metric: row.get(3)?,
        value: row.get(4)?,
    })
}

// ES: Mantiene una unica conexion SQLite protegida por mutex. / EN: Holds one SQLite connection protected by a mutex.
pub struct DbManager {
    conn: Mutex<Connection>,
}

impl DbManager {
    pub fn new(app_data_dir: PathBuf) -> Result<Self, String> {
        std::fs::create_dir_all(&app_data_dir)
            .map_err(|e| format!("cannot create data dir {app_data_dir:?}: {e}"))?;

        let db_path = app_data_dir.join("netscope.db");

        let conn =
            Connection::open(&db_path).map_err(|e| format!("cannot open {db_path:?}: {e}"))?;

        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous  = NORMAL;
             PRAGMA foreign_keys = ON;
             PRAGMA cache_size   = -32000;  -- ES/EN: Cache de paginas / page cache: 32 MB
             PRAGMA temp_store   = MEMORY;",
        )
        .map_err(|e| format!("pragma setup failed: {e}"))?;

        let mgr = Self {
            conn: Mutex::new(conn),
        };
        mgr.init_schema()?;

        eprintln!("[db] opened {db_path:?}");
        Ok(mgr)
    }

    pub fn init_schema(&self) -> Result<(), String> {
        let conn = self.lock()?;
        conn.execute_batch(
            "
            -- ES/EN: Sesiones / Sessions
            CREATE TABLE IF NOT EXISTS sessions (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                name          TEXT,
                interface     TEXT,
                started_at    TEXT,
                ended_at      TEXT,
                total_packets INTEGER DEFAULT 0
            );

            -- ES/EN: Paquetes / Packets
            CREATE TABLE IF NOT EXISTS packets (
                id          INTEGER NOT NULL,
                session_id  INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
                ts          TEXT    NOT NULL,
                src_ip      TEXT,
                dst_ip      TEXT,
                src_port    INTEGER,
                dst_port    INTEGER,
                protocol    TEXT,
                length      INTEGER,
                ttl         INTEGER,
                flags       TEXT,
                payload_hex TEXT,
                raw_ascii   TEXT,
                PRIMARY KEY (session_id, id)
            );

            -- ES/EN: Diagnosticos / Diagnostics
            CREATE TABLE IF NOT EXISTS diagnostics (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER,
                ts         TEXT,
                metric     TEXT,
                value      REAL
            );

            CREATE INDEX IF NOT EXISTS idx_diag_session
                ON diagnostics(session_id);
            CREATE INDEX IF NOT EXISTS idx_diag_metric
                ON diagnostics(metric);
            ",
        )
        .map_err(|e| format!("init_schema failed: {e}"))?;

        let packet_pk_columns: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('packets') WHERE pk > 0",
                [],
                |row| row.get(0),
            )
            .map_err(|e| format!("inspect packets schema failed: {e}"))?;

        if packet_pk_columns == 1 {
            conn.execute_batch(
                "
                BEGIN IMMEDIATE;
                ALTER TABLE packets RENAME TO packets_legacy;
                CREATE TABLE packets (
                    id          INTEGER NOT NULL,
                    session_id  INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
                    ts          TEXT    NOT NULL,
                    src_ip      TEXT,
                    dst_ip      TEXT,
                    src_port    INTEGER,
                    dst_port    INTEGER,
                    protocol    TEXT,
                    length      INTEGER,
                    ttl         INTEGER,
                    flags       TEXT,
                    payload_hex TEXT,
                    raw_ascii   TEXT,
                    PRIMARY KEY (session_id, id)
                );
                INSERT OR IGNORE INTO packets
                    (id, session_id, ts, src_ip, dst_ip, src_port, dst_port,
                     protocol, length, ttl, flags, payload_hex, raw_ascii)
                SELECT id, session_id, ts, src_ip, dst_ip, src_port, dst_port,
                       protocol, length, ttl, flags, payload_hex, raw_ascii
                FROM packets_legacy
                WHERE session_id IS NOT NULL;
                DROP TABLE packets_legacy;
                COMMIT;
                ",
            )
            .map_err(|e| format!("migrate packets primary key failed: {e}"))?;
        }

        conn.execute_batch(
            "
            CREATE INDEX IF NOT EXISTS idx_packets_session
                ON packets(session_id);
            CREATE INDEX IF NOT EXISTS idx_packets_protocol
                ON packets(protocol);
            CREATE INDEX IF NOT EXISTS idx_packets_src_ip
                ON packets(src_ip);
            CREATE INDEX IF NOT EXISTS idx_packets_dst_ip
                ON packets(dst_ip);
            CREATE INDEX IF NOT EXISTS idx_packets_ts
                ON packets(ts);
            ",
        )
        .map_err(|e| format!("create packet indexes failed: {e}"))
    }

    pub fn create_session(
        &self,
        name: Option<&str>,
        interface: Option<&str>,
    ) -> Result<i64, String> {
        let conn = self.lock()?;
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

        conn.execute(
            "INSERT INTO sessions (name, interface, started_at)
             VALUES (?1, ?2, ?3)",
            params![name, interface, now],
        )
        .map_err(|e| format!("create_session insert failed: {e}"))?;

        Ok(conn.last_insert_rowid())
    }

    pub fn close_session(&self, session_id: i64, total_packets: i64) -> Result<(), String> {
        let conn = self.lock()?;
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

        conn.execute(
            "UPDATE sessions
             SET ended_at = ?1, total_packets = ?2
             WHERE id = ?3",
            params![now, total_packets, session_id],
        )
        .map_err(|e| format!("close_session update failed: {e}"))?;

        Ok(())
    }

    pub fn list_sessions(&self) -> Result<Vec<Session>, String> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT id, name, interface, started_at, ended_at, total_packets
                 FROM sessions ORDER BY id DESC",
            )
            .map_err(|e| format!("list_sessions prepare: {e}"))?;

        let rows = stmt
            .query_map([], row_to_session)
            .map_err(|e| format!("list_sessions query: {e}"))?;

        rows.collect::<SqlResult<Vec<_>>>()
            .map_err(|e| format!("list_sessions collect: {e}"))
    }

    pub fn delete_session(&self, session_id: i64) -> Result<(), String> {
        let conn = self.lock()?;
        conn.execute("DELETE FROM sessions WHERE id = ?1", params![session_id])
            .map_err(|e| format!("delete_session: {e}"))?;
        Ok(())
    }

    pub fn insert_packet(&self, session_id: i64, pkt: &PacketRow) -> Result<(), String> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT OR REPLACE INTO packets
             (id, session_id, ts, src_ip, dst_ip, src_port, dst_port,
              protocol, length, ttl, flags, payload_hex, raw_ascii)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
            params![
                pkt.id,
                session_id,
                pkt.ts,
                pkt.src_ip,
                pkt.dst_ip,
                pkt.src_port,
                pkt.dst_port,
                pkt.protocol,
                pkt.length,
                pkt.ttl,
                pkt.flags,
                pkt.payload_hex,
                pkt.raw_ascii,
            ],
        )
        .map_err(|e| format!("insert_packet failed: {e}"))?;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn insert_packets_bulk(&self, session_id: i64, pkts: &[PacketRow]) -> Result<(), String> {
        if pkts.is_empty() {
            return Ok(());
        }

        let mut conn = self.lock()?;
        let tx = conn
            .transaction()
            .map_err(|e| format!("bulk tx begin: {e}"))?;

        {
            let mut stmt = tx
                .prepare_cached(
                    "INSERT OR REPLACE INTO packets
                     (id, session_id, ts, src_ip, dst_ip, src_port, dst_port,
                      protocol, length, ttl, flags, payload_hex, raw_ascii)
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
                )
                .map_err(|e| format!("bulk stmt prepare: {e}"))?;

            for pkt in pkts {
                stmt.execute(params![
                    pkt.id,
                    session_id,
                    pkt.ts,
                    pkt.src_ip,
                    pkt.dst_ip,
                    pkt.src_port,
                    pkt.dst_port,
                    pkt.protocol,
                    pkt.length,
                    pkt.ttl,
                    pkt.flags,
                    pkt.payload_hex,
                    pkt.raw_ascii,
                ])
                .map_err(|e| format!("bulk insert row: {e}"))?;
            }
        }

        tx.commit().map_err(|e| format!("bulk tx commit: {e}"))
    }

    pub fn get_packets(
        &self,
        session_id: i64,
        filters: &PacketFilters,
    ) -> Result<Vec<PacketRow>, String> {
        let conn = self.lock()?;
        let mut qb = QueryBuilder::new();

        qb.eq("session_id", session_id);
        Self::apply_filters(&mut qb, filters);

        let sql = format!(
            "SELECT id, session_id, ts, src_ip, dst_ip, src_port, dst_port,
                    protocol, length, ttl, flags, payload_hex, raw_ascii
             FROM packets{}
             ORDER BY id ASC",
            qb.where_clause()
        );

        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| format!("get_packets prepare: {e}"))?;

        let params = qb.params();
        let rows = stmt
            .query_map(params.as_slice(), row_to_packet)
            .map_err(|e| format!("get_packets query: {e}"))?;

        rows.collect::<SqlResult<Vec<_>>>()
            .map_err(|e| format!("get_packets collect: {e}"))
    }

    pub fn get_packets_paginated(
        &self,
        session_id: i64,
        filters: &PacketFilters,
        page: u32,
        page_size: u32,
    ) -> Result<PaginatedResult<PacketRow>, String> {
        let conn = self.lock()?;
        let page = page.max(1);
        let page_size = page_size.clamp(1, 1000);
        let offset = (page - 1) * page_size;

        let mut qb = QueryBuilder::new();
        qb.eq("session_id", session_id);
        Self::apply_filters(&mut qb, filters);
        let where_sql = qb.where_clause();

        let count_sql = format!("SELECT COUNT(*) FROM packets{where_sql}");
        let mut count_stmt = conn
            .prepare(&count_sql)
            .map_err(|e| format!("count prepare: {e}"))?;
        let params_ref = qb.params();
        let total: i64 = count_stmt
            .query_row(params_ref.as_slice(), |r| r.get(0))
            .map_err(|e| format!("count query: {e}"))?;

        let mut qb2 = QueryBuilder::new();
        qb2.eq("session_id", session_id);
        Self::apply_filters(&mut qb2, filters);
        let where_sql2 = qb2.where_clause();

        let data_sql = format!(
            "SELECT id, session_id, ts, src_ip, dst_ip, src_port, dst_port,
                    protocol, length, ttl, flags, payload_hex, raw_ascii
             FROM packets{where_sql2}
             ORDER BY id DESC
             LIMIT ?{} OFFSET ?{}",
            qb2.values.len() + 1,
            qb2.values.len() + 2,
        );
        qb2.values.push(Box::new(page_size as i64));
        qb2.values.push(Box::new(offset as i64));

        let mut data_stmt = conn
            .prepare(&data_sql)
            .map_err(|e| format!("data prepare: {e}"))?;
        let params2 = qb2.params();
        let rows = data_stmt
            .query_map(params2.as_slice(), row_to_packet)
            .map_err(|e| format!("data query: {e}"))?;

        let items = rows
            .collect::<SqlResult<Vec<_>>>()
            .map_err(|e| format!("data collect: {e}"))?;

        let total_pages = ((total as u32).saturating_add(page_size - 1)) / page_size;

        Ok(PaginatedResult {
            items,
            total,
            page,
            page_size,
            total_pages,
        })
    }

    pub fn get_protocol_stats(&self, session_id: i64) -> Result<Vec<ProtocolStat>, String> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT COALESCE(protocol, 'UNKNOWN') AS proto, COUNT(*) AS cnt
                 FROM packets
                 WHERE session_id = ?1
                 GROUP BY proto
                 ORDER BY cnt DESC",
            )
            .map_err(|e| format!("protocol_stats prepare: {e}"))?;

        let rows = stmt
            .query_map(params![session_id], |row| {
                Ok(ProtocolStat {
                    protocol: row.get(0)?,
                    count: row.get(1)?,
                })
            })
            .map_err(|e| format!("protocol_stats query: {e}"))?;

        rows.collect::<SqlResult<Vec<_>>>()
            .map_err(|e| format!("protocol_stats collect: {e}"))
    }

    pub fn get_traffic_timeline(
        &self,
        session_id: i64,
        bucket_secs: u32,
    ) -> Result<Vec<TimePoint>, String> {
        let conn = self.lock()?;
        let bucket_secs = bucket_secs.clamp(1, 3600) as i64;

        let mut stmt = conn
            .prepare(
                "SELECT
                    datetime(
                        (CAST(strftime('%s', ts) AS INTEGER) / ?1) * ?1,
                        'unixepoch'
                    ) AS bucket,
                    COUNT(*)        AS packets,
                    SUM(COALESCE(length, 0)) AS bytes
                 FROM packets
                 WHERE session_id = ?2
                   AND ts IS NOT NULL
                 GROUP BY bucket
                 ORDER BY bucket ASC",
            )
            .map_err(|e| format!("timeline prepare: {e}"))?;

        let rows = stmt
            .query_map(params![bucket_secs, session_id], |row| {
                Ok(TimePoint {
                    bucket: row.get::<_, Option<String>>(0)?.unwrap_or_default(),
                    packets: row.get(1)?,
                    bytes: row.get(2)?,
                })
            })
            .map_err(|e| format!("timeline query: {e}"))?;

        rows.collect::<SqlResult<Vec<_>>>()
            .map_err(|e| format!("timeline collect: {e}"))
    }

    pub fn get_top_src_ips(&self, session_id: i64, limit: u32) -> Result<Vec<TopIp>, String> {
        self.top_ips_for_column(session_id, "src_ip", limit)
    }

    pub fn get_top_dst_ips(&self, session_id: i64, limit: u32) -> Result<Vec<TopIp>, String> {
        self.top_ips_for_column(session_id, "dst_ip", limit)
    }

    #[allow(dead_code)]
    pub fn get_top_ips(&self, session_id: i64, limit: u32) -> Result<Vec<TopIp>, String> {
        let conn = self.lock()?;
        let limit = limit.clamp(1, 500) as i64;

        let mut stmt = conn
            .prepare(
                "SELECT ip, SUM(cnt) AS total
                 FROM (
                     SELECT src_ip AS ip, COUNT(*) AS cnt
                     FROM packets
                     WHERE session_id = ?1 AND src_ip IS NOT NULL
                     GROUP BY src_ip
                     UNION ALL
                     SELECT dst_ip AS ip, COUNT(*) AS cnt
                     FROM packets
                     WHERE session_id = ?1 AND dst_ip IS NOT NULL
                     GROUP BY dst_ip
                 ) sub
                 GROUP BY ip
                 ORDER BY total DESC
                 LIMIT ?2",
            )
            .map_err(|e| format!("top_ips prepare: {e}"))?;

        let rows = stmt
            .query_map(params![session_id, limit], |row| {
                Ok(TopIp {
                    ip: row.get(0)?,
                    count: row.get(1)?,
                })
            })
            .map_err(|e| format!("top_ips query: {e}"))?;

        rows.collect::<SqlResult<Vec<_>>>()
            .map_err(|e| format!("top_ips collect: {e}"))
    }

    pub fn get_session_summary(&self, session_id: i64) -> Result<(i64, i64, f64), String> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT COUNT(*),
                        COALESCE(SUM(length), 0),
                        COALESCE(AVG(length), 0.0)
                 FROM packets
                 WHERE session_id = ?1",
            )
            .map_err(|e| format!("session_summary prepare: {e}"))?;

        stmt.query_row(params![session_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, f64>(2)?,
            ))
        })
        .map_err(|e| format!("session_summary query: {e}"))
    }

    pub fn insert_diagnostic(
        &self,
        session_id: i64,
        metric: &str,
        value: f64,
    ) -> Result<(), String> {
        let conn = self.lock()?;
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

        conn.execute(
            "INSERT INTO diagnostics (session_id, ts, metric, value)
             VALUES (?1, ?2, ?3, ?4)",
            params![session_id, now, metric, value],
        )
        .map_err(|e| format!("insert_diagnostic: {e}"))?;
        Ok(())
    }

    pub fn get_diagnostics(
        &self,
        session_id: i64,
        limit: u32,
    ) -> Result<Vec<DiagnosticRow>, String> {
        let conn = self.lock()?;
        let limit = limit.clamp(1, 10_000) as i64;

        let mut stmt = conn
            .prepare(
                "SELECT id, session_id, ts, metric, value
                 FROM diagnostics
                 WHERE session_id = ?1
                 ORDER BY id DESC
                 LIMIT ?2",
            )
            .map_err(|e| format!("get_diagnostics prepare: {e}"))?;

        let rows = stmt
            .query_map(params![session_id, limit], row_to_diagnostic)
            .map_err(|e| format!("get_diagnostics query: {e}"))?;

        rows.collect::<SqlResult<Vec<_>>>()
            .map_err(|e| format!("get_diagnostics collect: {e}"))
    }

    pub fn build_diagnostics_data(&self, session_id: i64) -> Result<DiagnosticsData, String> {
        let protocol_stats = self.get_protocol_stats(session_id)?;
        let traffic_timeline = self.get_traffic_timeline(session_id, 5)?; // ES: Bloques de 5 segundos. / EN: 5-second buckets.
        let top_src_ips = self.get_top_src_ips(session_id, 20)?;
        let top_dst_ips = self.get_top_dst_ips(session_id, 20)?;
        let (total_packets, total_bytes, avg_packet_size) = self.get_session_summary(session_id)?;
        let recent_errors = self.get_diagnostics(session_id, 50)?;

        Ok(DiagnosticsData {
            session_id,
            protocol_stats,
            traffic_timeline,
            top_src_ips,
            top_dst_ips,
            total_packets,
            total_bytes,
            avg_packet_size,
            recent_errors,
        })
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>, String> {
        self.conn
            .lock()
            .map_err(|e| format!("db mutex poisoned: {e}"))
    }

    fn top_ips_for_column(
        &self,
        session_id: i64,
        column: &str,
        limit: u32,
    ) -> Result<Vec<TopIp>, String> {
        let conn = self.lock()?;
        let limit = limit.clamp(1, 500) as i64;

        let sql = format!(
            "SELECT {column} AS ip, COUNT(*) AS cnt
             FROM packets
             WHERE session_id = ?1 AND {column} IS NOT NULL
             GROUP BY {column}
             ORDER BY cnt DESC
             LIMIT ?2"
        );

        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| format!("top_ips_for_column prepare: {e}"))?;

        let rows = stmt
            .query_map(params![session_id, limit], |row| {
                Ok(TopIp {
                    ip: row.get(0)?,
                    count: row.get(1)?,
                })
            })
            .map_err(|e| format!("top_ips_for_column query: {e}"))?;

        rows.collect::<SqlResult<Vec<_>>>()
            .map_err(|e| format!("top_ips_for_column collect: {e}"))
    }

    fn apply_filters(qb: &mut QueryBuilder, f: &PacketFilters) {
        if let Some(ref v) = f.src_ip {
            qb.eq("src_ip", v.clone());
        }
        if let Some(ref v) = f.dst_ip {
            qb.eq("dst_ip", v.clone());
        }
        if let Some(v) = f.src_port {
            qb.eq("src_port", v as i32);
        }
        if let Some(v) = f.dst_port {
            qb.eq("dst_port", v as i32);
        }
        if let Some(ref v) = f.protocol {
            qb.eq("protocol", v.clone());
        }
        if let Some(v) = f.min_length {
            qb.gte("length", v as i32);
        }
        if let Some(v) = f.max_length {
            qb.lte("length", v as i32);
        }

        if let Some(ref s) = f.search {
            let pattern = format!("%{s}%");
            let idx = qb.values.len();
            qb.clauses.push(format!(
                "(src_ip LIKE ?{} OR dst_ip LIKE ?{} OR protocol LIKE ?{})",
                idx + 1,
                idx + 2,
                idx + 3
            ));
            qb.values.push(Box::new(pattern.clone()));
            qb.values.push(Box::new(pattern.clone()));
            qb.values.push(Box::new(pattern));
        }
    }
}
