use clap::{Parser, Subcommand};
use auth_service::domain::error::Error;
use auth_service::domain::user::User;

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
    },
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::CreateUser { email } => {
            let user = User::now_with_email(email.clone());
            match user {
                Ok(user) => {
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
    }
}
