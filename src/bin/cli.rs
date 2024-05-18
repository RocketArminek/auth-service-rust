use auth_service::domain::crypto::{HashingScheme, SchemeAwareHasher};
use auth_service::domain::error::UserError;
use auth_service::domain::user::{PasswordHandler, User};
use auth_service::infrastructure::database::create_mysql_pool;
use auth_service::infrastructure::mysql_user_repository::MysqlUserRepository;
use clap::{Parser, Subcommand};
use dotenv::dotenv;
use sqlx::sqlx_macros::migrate;
use std::env;
use auth_service::domain::role::Role;
use auth_service::infrastructure::mysql_role_repository::MysqlRoleRepository;

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
    Login {
        #[arg(short, long)]
        email: String,
        #[arg(short, long)]
        password: String,
    },
    AssignRole {
        #[arg(short, long)]
        email: String,
        #[arg(short, long)]
        role: String,
    },
    InitRestrictedRole,
}

#[tokio::main]
async fn main() {
    dotenv().ok();
    let hashing_scheme =
        env::var("PASSWORD_HASHING_SCHEME").expect("PASSWORD_HASHING_SCHEME is not set in envs");
    let hashing_scheme = HashingScheme::from_string(hashing_scheme).unwrap();

    let cli = Cli::parse();
    let pool = create_mysql_pool().await.unwrap();
    migrate!("./migrations").run(&pool).await.unwrap();
    let user_repository = MysqlUserRepository::new(pool.clone());
    let role_repository = MysqlRoleRepository::new(pool.clone());

    match &cli.command {
        Commands::CreateUser { email, password } => {
            let user = User::now_with_email_and_password(
                email.clone(),
                password.clone()
            );

            match user {
                Ok(mut user) => {
                    user.hash_password(&SchemeAwareHasher::with_scheme(hashing_scheme));
                    user_repository
                        .add(&user)
                        .await
                        .expect("Failed to create user! Check if the email is already in use.");

                    println!(
                        "User created: {} {} at {}",
                        user.id,
                        user.email,
                        user.created_at.format("%Y-%m-%d %H:%M:%S")
                    );
                }
                Err(error) => match error {
                    UserError::InvalidEmail { email } => {
                        panic!("Invalid email: {}", email);
                    }
                    UserError::EmptyPassword => {
                        panic!("Empty password");
                    }
                    UserError::EncryptionFailed => {
                        panic!("Encryption failed");
                    }
                    UserError::InvalidPassword => {
                        panic!("Invalid password format");
                    }
                    UserError::SchemeNotSupported => {
                        panic!("Password hashing scheme not supported");
                    }
                },
            }
        }
        Commands::GetUserByEmail { email } => {
            let user = user_repository.get_by_email(email).await;

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
            user_repository.delete_by_email(email).await.unwrap();

            println!("User deleted for {}", email);
        }
        Commands::Login { email, password } => {
            let user = user_repository.get_by_email(email).await;

            match user {
                None => {
                    println!("User not found for {}", email);
                }
                Some(user) => {
                    let hasher = SchemeAwareHasher::with_scheme(hashing_scheme);

                    if user.verify_password(&hasher, password) {
                        println!(
                            "User logged in: {} {} at {}",
                            user.id,
                            user.email,
                            user.created_at.format("%Y-%m-%d %H:%M:%S")
                        );
                    } else {
                        println!("Invalid password");
                    }
                }
            }
        }
        Commands::AssignRole { email, role } => {
            let user = user_repository.get_by_email(email).await;

            match user {
                None => {
                    println!("User not found for {}", email);
                }
                Some(user) => {
                    let r = role_repository.get_by_name(role).await;

                    match r {
                        None => {
                            println!("Role not found for {}", role);
                        }
                        Some(role) => {
                            user_repository
                                .add_role(user.id, role.id)
                                .await
                                .expect("Failed to assign role");

                            println!("Role assigned: {} to {}", role.name, user.email);
                        }
                    }
                }
            }
        }
        Commands::InitRestrictedRole => {
            let restricted_role_prefix = env::var("RESTRICTED_ROLE_PREFIX")
                .unwrap_or("ADMIN".to_string());
            let role = role_repository.get_by_name(&restricted_role_prefix).await;

            match role {
                None => {
                    let role = Role::now(restricted_role_prefix).unwrap();
                    role_repository
                        .add(&role)
                        .await
                        .expect("Failed to init auth owner role!");

                    println!(
                        "Created initial restricted role base on pattern: {}, {}, {}",
                        role.id,
                        role.name,
                        role.created_at.format("%Y-%m-%d %H:%M:%S")
                    );
                }
                Some(_) => {
                    println!("Role already exists");
                }
            }
        }
    }
}
