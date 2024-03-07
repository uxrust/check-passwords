use md5::{Md5, Digest};
use tokio_postgres::{NoTls, Error};
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

async fn check_passwords(db_uri: &str, passwords_file_path: &Path) -> Result<(), Error> {
    // Подключение к базе данных
    let (client, connection) = tokio_postgres::connect(db_uri, NoTls).await?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("connection error: {}", e);
        }
    });

    // Чтение файла с паролями
    let file = File::open(passwords_file_path)?;
    let reader = io::BufReader::new(file);

    for line in reader.lines() {
        let password = line?;
        let password_md5 = format!("{:x}", Md5::digest(password.as_bytes()));

        // Запрос к базе данных для поиска совпадающего пароля
        let stmt = client.prepare("SELECT id, name FROM User WHERE password = $1").await?;
        let rows = client.query(&stmt, &[&password_md5]).await?;

        for row in rows {
            let id: i32 = row.get(0);
            let name: String = row.get(1);
            println!("Found match - ID: {}, Name: {}, Password: {}", id, name, password);
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let db_uri = "postgresql://user:password@localhost/dbname";
    let passwords_file_path = Path::new("passwords.txt");
    check_passwords(db_uri, passwords_file_path).await
}
