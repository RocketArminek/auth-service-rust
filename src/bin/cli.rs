use clap::{Parser, Subcommand};
use dotenv::dotenv;
use sqlx::sqlx_macros::migrate;
use auth_service::domain::error::Error;
use auth_service::domain::user::User;
use auth_service::infrastructure::database::create_mysql_pool;
use auth_service::infrastructure::sqlx_user_repository::MysqlUserRepository;

#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands
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
}

#[tokio::main]
async fn main() {
    dotenv().ok();
    let cli = Cli::parse();
    let pool = create_mysql_pool().await.unwrap();
    let repository = MysqlUserRepository::new(pool.clone());
    migrate!("./migrations").run(&pool).await.unwrap();

    match &cli.command {
        Commands::CreateUser { email, password } => {
            let user = User::now_with_email_and_password(email.clone(), password.clone());
            match user {
                Ok(user) => {
                    repository.add(&user).await.unwrap();

                    println!(
                        "User created: {} {} at {}",
                        user.id.to_string().chars().take(8).collect::<String>(),
                        user.email,
                        user.created_at.format("%Y-%m-%d %H:%M:%S")
                    );
                }
                Err(error) => {
                    match error {
                        Error::UserNotFound { id } => {
                            panic!("User not found for {}", id);
                        }
                        Error::UserAlreadyExists { email } => {
                            panic!("User already exists for {}", email);
                        }
                        Error::InvalidEmail { email } => {
                            panic!("Invalid email: {}", email);
                        }
                    }
                }
            }
        }
        Commands::GetUserByEmail { email } => {
            let user = repository.get_by_email(email).await.unwrap();

            println!(
                "User found: {} {} at {}",
                user.id.to_string().chars().take(8).collect::<String>(),
                user.email,
                user.created_at.format("%Y-%m-%d %H:%M:%S")
            );
        }
    }
}
