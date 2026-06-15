use std::path::Path;
use std::path::PathBuf;

use anyhow::Context;
use anyhow::Result;
use sqlx::sqlite::SqliteConnectOptions;
use sqlx::sqlite::SqliteJournalMode;
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::sqlite::SqliteSynchronous;
use sqlx::Row;
use sqlx::SqlitePool;

use crate::runbook::RunbookFinalFinding;
use crate::runbook::RunbookState;

#[derive(Clone)]
pub(crate) struct TriLaneStateStore {
    pool: SqlitePool,
}

impl TriLaneStateStore {
    pub(crate) async fn open_default() -> Result<Self> {
        let path = default_db_path();
        Self::open(path.as_path()).await
    }

    pub(crate) async fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .with_context(|| format!("create TriLane state dir {}", parent.display()))?;
        }
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal);
        let pool = SqlitePoolOptions::new()
            .max_connections(4)
            .connect_with(options)
            .await
            .with_context(|| format!("open TriLane SQLite state {}", path.display()))?;
        let store = Self { pool };
        store.migrate().await?;
        Ok(store)
    }

    pub(crate) async fn save_runbook(&self, state: &RunbookState) -> Result<bool> {
        let state_json = serde_json::to_string(state).context("serialize runbook state")?;
        let snapshot_key = state.turn_id.as_deref().unwrap_or("active");
        let revision = i64::try_from(state.revision).unwrap_or(i64::MAX);
        let mut tx = self
            .pool
            .begin()
            .await
            .context("begin runbook snapshot tx")?;
        let result = sqlx::query(
            "INSERT INTO runbook_snapshot (id, snapshot_key, revision, updated_at, turn_id, state_json)
             VALUES (1, ?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(id) DO UPDATE SET
                snapshot_key = excluded.snapshot_key,
                revision = excluded.revision,
                updated_at = excluded.updated_at,
                turn_id = excluded.turn_id,
                state_json = excluded.state_json
             WHERE excluded.revision >= runbook_snapshot.revision",
        )
        .bind(snapshot_key)
        .bind(revision)
        .bind(&state.last_updated)
        .bind(state.turn_id.as_deref())
        .bind(state_json)
        .execute(&mut *tx)
        .await
        .context("upsert runbook snapshot")?;

        if result.rows_affected() == 0 {
            tx.commit().await.context("commit skipped runbook tx")?;
            return Ok(false);
        }

        sqlx::query("DELETE FROM final_findings WHERE snapshot_key = ?1")
            .bind(snapshot_key)
            .execute(&mut *tx)
            .await
            .context("clear final findings snapshot")?;
        for (ordinal, finding) in state.final_findings.iter().enumerate() {
            let finding_json = serde_json::to_string(finding).context("serialize final finding")?;
            sqlx::query(
                "INSERT INTO final_findings
                    (snapshot_key, ordinal, finding_id, finding_json, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
            )
            .bind(snapshot_key)
            .bind(i64::try_from(ordinal).unwrap_or(i64::MAX))
            .bind(&finding.id)
            .bind(finding_json)
            .bind(&state.last_updated)
            .execute(&mut *tx)
            .await
            .context("insert final finding snapshot")?;
        }
        tx.commit().await.context("commit runbook snapshot tx")?;
        Ok(true)
    }

    pub(crate) async fn load_runbook(&self) -> Result<Option<RunbookState>> {
        let row = sqlx::query("SELECT state_json FROM runbook_snapshot WHERE id = 1")
            .fetch_optional(&self.pool)
            .await
            .context("load runbook snapshot")?;
        row.map(|row| {
            let json: String = row.get("state_json");
            serde_json::from_str(&json).context("deserialize runbook snapshot")
        })
        .transpose()
    }

    pub(crate) async fn load_final_findings(&self) -> Result<Option<Vec<RunbookFinalFinding>>> {
        let Some(snapshot) = self.load_runbook().await? else {
            return Ok(None);
        };
        if !snapshot.final_findings.is_empty() {
            return Ok(Some(snapshot.final_findings));
        }
        let snapshot_key = snapshot.turn_id.as_deref().unwrap_or("active");
        let rows = sqlx::query(
            "SELECT finding_json FROM final_findings
             WHERE snapshot_key = ?1
             ORDER BY ordinal ASC",
        )
        .bind(snapshot_key)
        .fetch_all(&self.pool)
        .await
        .context("load final finding snapshot")?;
        let findings = rows
            .into_iter()
            .map(|row| {
                let json: String = row.get("finding_json");
                serde_json::from_str(&json).context("deserialize final finding snapshot")
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Some(findings))
    }

    pub(crate) async fn clear(&self) -> Result<()> {
        let mut tx = self.pool.begin().await.context("begin clear runbook tx")?;
        sqlx::query("DELETE FROM final_findings")
            .execute(&mut *tx)
            .await
            .context("clear final findings")?;
        sqlx::query("DELETE FROM runbook_snapshot")
            .execute(&mut *tx)
            .await
            .context("clear runbook snapshot")?;
        tx.commit().await.context("commit clear runbook tx")?;
        Ok(())
    }

    async fn migrate(&self) -> Result<()> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS runbook_snapshot (
                id INTEGER PRIMARY KEY CHECK(id = 1),
                snapshot_key TEXT NOT NULL,
                revision INTEGER NOT NULL,
                updated_at TEXT NOT NULL,
                turn_id TEXT,
                state_json TEXT NOT NULL
            )",
        )
        .execute(&self.pool)
        .await
        .context("create runbook snapshot table")?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS final_findings (
                snapshot_key TEXT NOT NULL,
                ordinal INTEGER NOT NULL,
                finding_id TEXT NOT NULL,
                finding_json TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY(snapshot_key, finding_id)
            )",
        )
        .execute(&self.pool)
        .await
        .context("create final findings table")?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_final_findings_snapshot_ordinal
             ON final_findings(snapshot_key, ordinal)",
        )
        .execute(&self.pool)
        .await
        .context("create final findings ordinal index")?;
        Ok(())
    }
}

fn default_db_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
        .join(".trilane")
        .join("state.sqlite")
}

#[cfg(test)]
mod tests {
    use super::TriLaneStateStore;
    use crate::runbook::AuditMode;
    use crate::runbook::RunbookState;

    #[tokio::test]
    async fn ignores_older_runbook_snapshot_revisions() {
        let path = std::env::temp_dir().join(format!(
            "trilane-state-{}-{}.sqlite",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let store = TriLaneStateStore::open(path.as_path())
            .await
            .expect("open store");
        let mut newer = RunbookState::default();
        newer.start_turn("newer", AuditMode::Lab);
        newer.revision = 10;
        store.save_runbook(&newer).await.expect("save newer");

        let mut older = RunbookState::default();
        older.start_turn("older", AuditMode::Lab);
        older.revision = 9;
        assert!(!store.save_runbook(&older).await.expect("skip older"));

        let loaded = store
            .load_runbook()
            .await
            .expect("load runbook")
            .expect("snapshot");
        assert_eq!(loaded.objective, "newer");
        let _ = tokio::fs::remove_file(path).await;
    }
}
