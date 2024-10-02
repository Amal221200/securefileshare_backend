use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, Type};
use uuid::Uuid;

#[derive(Debug, Clone, Deserialize, Serialize, FromRow, Type)]
pub struct User {
    pub id: Uuid,
    pub name: String,
    pub email: String,
    pub password: String,
    pub public_key: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Deserialize, Serialize, FromRow, Type)]
pub struct File {
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    pub file_name: String,
    pub file_size: i64,
    pub encrypted_aes_key: Vec<u8>,
    pub encrypted_file: Vec<u8>,
    pub iv: Vec<u8>,
    pub created_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Deserialize, Serialize, FromRow, Type)]
pub struct SharedLink {
    pub id: Uuid,
    pub file_id: Option<Uuid>,
    pub recipient_user_id: Option<Uuid>,
    pub password: String,
    pub expiration_date: Option<DateTime<Utc>>,
    pub created_at: Option<DateTime<Utc>>,
}

#[derive(FromRow)]
pub struct SentFileDetails {
    pub file_id: Uuid,
    pub file_name: String,
    pub recipient_email: String,
    pub expiration_date: Option<DateTime<Utc>>,
    pub created_at: Option<DateTime<Utc>>,
}

#[derive(FromRow)]
pub struct ReceiveFileDetails {
    pub file_id: Uuid,
    pub file_name: String,
    pub sender_email: String,
    pub expiration_date: Option<DateTime<Utc>>,
    pub created_at: Option<DateTime<Utc>>,
}
