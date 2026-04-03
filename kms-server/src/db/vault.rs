use sqlx::PgPool;
use uuid::Uuid;

#[derive(sqlx::Type, Debug, PartialEq)]
#[sqlx(type_name = "file_status", rename_all = "UPPERCASE")]
pub enum FileStatus {
    ACTIVE,
    REVOKED,
}

pub async fn retrieve_key(pool: &PgPool, file_id: Uuid) -> Result<Option<Vec<u8>>, String> {
    let result = sqlx::query!(
        r#"
        SELECT dek_blob, global_status AS "global_status: FileStatus"
        FROM Files_Vault
        WHERE file_id = $1
        "#,
        file_id
    )
    .fetch_optional(pool)
    .await
    .map_err(|e| format!("Database error: {}", e))?;

    match result {
        Some(row) => {
            if row.global_status == FileStatus::REVOKED {
                Err("File access has been REVOKED".to_string())
            } else {
                Ok(Some(row.dek_blob))
            }
        }
        None => Ok(None),
    }
}
