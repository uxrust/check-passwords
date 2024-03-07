use tokio::sync::Semaphore;
use tokio::spawn;
use tokio_postgres::{NoTls, connect};
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;
use bcrypt::verify;
use std::env;
use futures::future::join_all;
use std::sync::Arc;

async fn verify_password(
    user_data: Vec<(String, String)>, // (login, hashed_password)
    password: &str,
    semaphore: Arc<Semaphore>
) -> Option<String> {
    let _permit = semaphore.acquire().await.expect("Failed to acquire semaphore permit");
    for (login, hashed_password) in user_data.iter() {
        if verify(password, hashed_password).unwrap_or(false) {
            return Some(format!("Found match - Login: {}, Password: {}", login, password));
        }
    }
    None
}

async fn check_passwords(db_uri: &str, query: &str, passwords_file_path: &Path, max_concurrent_tasks: usize) -> Result<(), Box<dyn std::error::Error>> {
    let semaphore = Arc::new(Semaphore::new(max_concurrent_tasks));
    let (client, connection) = connect(&db_uri, NoTls).await?;

    spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("connection error: {}", e);
        }
    });

    let stmt = client.prepare(&query).await?;
    let rows = client.query(&stmt, &[]).await?;

    let user_data: Vec<(String, String)> = rows.into_iter().map(|row| {
        (row.get(0), row.get(1))
    }).collect();

    let file = File::open(passwords_file_path)?;
    let reader = io::BufReader::new(file).lines();

    let futures: Vec<_> = reader.map(|line_result| {
        let line = line_result.expect("Failed to read line");
        let semaphore_clone = semaphore.clone();
        let user_data_clone = user_data.clone();
        tokio::spawn(async move {
            verify_password(user_data_clone, &line, semaphore_clone).await
        })
    }).collect();

    let results = join_all(futures).await;
    for result in results {
        if let Ok(Some(match_info)) = result {
            println!("{}", match_info);
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() {
    dotenv::from_filename(".env.local").ok();

    let db_uri = env::var("DATABASE_DSN").expect("DATABASE_DSN must be set");
    let query = env::var("QUERY").expect("QUERY must be set");
    let passwords_file_path = Path::new("passwords.txt");
    let max_concurrent_tasks = 30;

    if let Err(e) = check_passwords(&db_uri, &query, passwords_file_path, max_concurrent_tasks).await {
        eprintln!("Error checking passwords: {}", e);
    }
}
