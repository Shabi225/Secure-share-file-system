use axum::{routing::post, Router};
use sqlx::postgres::PgPoolOptions;
use std::net::SocketAddr;

mod crypto;
mod db;
mod handlers;

use crate::handlers::interrogate::handle_interrogation;

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    let database_url =
        std::env::var("DATABASE_URL").expect("DATABASE_URL environment variable must be set");

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Failed to connect to Postgres database");

    let app = Router::new()
        .route("/api/v1/interrogate/:file_id", post(handle_interrogation))
        .with_state(pool);

    let addr = SocketAddr::from(([0, 0, 0, 0], 8000));
    println!("KMS Zero-Trust Server starting on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
