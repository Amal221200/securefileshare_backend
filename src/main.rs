mod config;
mod db;
mod dtos;
mod error;
mod handler;
mod middleware;
mod models;
mod router;
mod utils;

use std::sync::Arc;

use axum::http::{
    header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE},
    HeaderValue, Method,
};
use config::Config;
use db::{DBClient, UserExt};
use dotenv::dotenv;
use router::create_router;
use sqlx::postgres::PgPoolOptions;
use tokio_cron_scheduler::{Job, JobScheduler};
use tower_http::cors::CorsLayer;
use tracing_subscriber::filter::LevelFilter;

#[derive(Debug, Clone)]
pub struct AppState {
    pub env: Config,
    pub db_client: DBClient,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(LevelFilter::DEBUG)
        .init();
    dotenv().ok();
    let config = Config::init();
    let pool = match PgPoolOptions::new()
        .max_connections(10)
        .connect(&config.database_url)
        .await
    {
        Ok(pool) => {
            println!("Connected to database");
            pool
        }
        Err(err) => {
            println!("Failed to connect to database: {:?}", err);
            std::process::exit(1);
        }
    };

    let cors = CorsLayer::new()
        .allow_origin("http://localhost:3000".parse::<HeaderValue>().unwrap())
        .allow_headers([AUTHORIZATION, ACCEPT, CONTENT_TYPE])
        .allow_credentials(true)
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE]);

    let db_client = DBClient::new(pool);
    let app_state = AppState {
        db_client: db_client.clone(),
        env: config.clone(),
    };

    let sched = JobScheduler::new().await.unwrap();
    let job = Job::new_async("0 0 * * * *", {
        move |_, _| {
            let db_client = db_client.clone();
            Box::pin(async move {
                println!("Running scheduled task to delete expired files...");
                if let Err(err) = db_client.delete_expired_files().await {
                    println!("Failed to delete expired files: {:?}", err);
                } else {
                    println!("Successfully deleted expired files");
                }
            })
        }
    })
    .unwrap();
    sched.add(job).await.unwrap();

    tokio::spawn(async move {
        sched.start().await.unwrap();
    });

    let app = create_router(Arc::new(app_state.clone())).layer(cors.clone());

    println!("Server is running on  http://localhost:{}", config.port);
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", config.port))
        .await
        .unwrap();

    axum::serve(listener, app).await.unwrap();
}
