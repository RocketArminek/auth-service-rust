use auth_service::domain::error::Error;
use auth_service::domain::user::User;
use auth_service::infrastructure::database::create_mysql_pool;
use auth_service::infrastructure::mysql_user_repository::MysqlUserRepository;
use clap::{Parser, Subcommand};
use dotenv::dotenv;
use sqlx::sqlx_macros::migrate;
use std::env;

#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    CreateUser {
        #[arg(short, long)]
        email: String,
        #[arg(short, long)]
        password: String,
    },
    GetUserByEmail {
        #[arg(short, long)]
        email: String,
    },
    DeleteUserByEmail {
        #[arg(short, long)]
        email: String,
    },
}

#[tokio::main]
async fn main() {
    dotenv().ok();
    let cli = Cli::parse();
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = create_mysql_pool(&database_url).await.unwrap();
    migrate!("./migrations").run(&pool).await.unwrap();
    let repository = MysqlUserRepository::new(pool);

    match &cli.command {
        Commands::CreateUser { email, password } => {
            let user = User::now_with_email_and_password(email.clone(), password.clone());
            match user {
                Ok(user) => {
                    repository.add(&user).await.unwrap();

                    println!(
                        "User created: {} {} at {}",
                        user.id,
                        user.email,
                        user.created_at.format("%Y-%m-%d %H:%M:%S")
                    );
                }
                Err(error) => match error {
                    Error::InvalidEmail { email } => {
                        panic!("Invalid email: {}", email);
                    }
                },
            }
        }
        Commands::GetUserByEmail { email } => {
            let user = repository.get_by_email(email).await;

            match user {
                None => {
                    println!("User not found for {}", email);
                }
                Some(user) => {
                    println!(
                        "User found: {} {} at {}",
                        user.id,
                        user.email,
                        user.created_at.format("%Y-%m-%d %H:%M:%S")
                    );
                }
            }
        }
        Commands::DeleteUserByEmail { email } => {
            repository.delete_by_email(email).await.unwrap();

            println!("User deleted for {}", email);
        }
    }
}
