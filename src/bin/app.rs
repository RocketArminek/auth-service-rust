use auth_service::domain::crypto::{HashingScheme, SchemeAwareHasher};
use auth_service::domain::error::UserError;
use auth_service::domain::user::{PasswordHandler, User};
use auth_service::infrastructure::database::create_mysql_pool;
use auth_service::infrastructure::mysql_user_repository::MysqlUserRepository;
use clap::{Parser, Subcommand};
use dotenv::dotenv;
use sqlx::sqlx_macros::migrate;
use std::env;
use std::sync::Arc;
use regex::{Error, Regex};
use tokio::signal;
use tokio::sync::Mutex;
use auth_service::api::routes::routes;
use auth_service::api::server_state::{parse_restricted_pattern, ServerState};
use auth_service::domain::role::Role;
use auth_service::infrastructure::mysql_role_repository::MysqlRoleRepository;

#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    #[command(about = "Start the server")]
    Start,
    CreateUser {
        #[arg(short, long)]
        email: String,
        #[arg(short, long)]
        password: String,
        #[arg(short, long)]
        role: Option<String>,
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
    CreateRole {
        #[arg(short, long)]
        name: String,
    },
    DeleteRole {
        #[arg(short, long)]
        name: String,
    },
    InitRestrictedRole,
}

#[tokio::main(flavor = "multi_thread", worker_threads=4)]
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
        Some(Commands::Start) | None => {
            tracing_subscriber::fmt()
                .with_max_level(tracing::Level::DEBUG)
                .init();

            let secret = env::var("SECRET").expect("SECRET is not set in envs");

            let hashing_scheme =
                env::var("PASSWORD_HASHING_SCHEME").expect("PASSWORD_HASHING_SCHEME is not set in envs");
            let hashing_scheme = HashingScheme::from_string(hashing_scheme).unwrap();

            let port = "8080";
            let addr = &format!("0.0.0.0:{}", port);
            let listener = tokio::net::TcpListener::bind(addr).await;

            tracing::info!("Configured hashing scheme: {}", hashing_scheme.to_string());

            let pool = create_mysql_pool().await.expect("Failed to connect & create db pool");
            let migration_result = migrate!("./migrations").run(&pool).await;
            match migration_result {
                Ok(_) => {
                    tracing::info!("Database migration completed successfully");
                }
                Err(e) => {
                    tracing::error!("Failed to migrate database: {}", e);
                    panic!("Failed to migrate database");
                }
            }

            let user_repository = Arc::new(
                Mutex::new(MysqlUserRepository::new(pool.clone()))
            );
            let role_repository = Arc::new(
                Mutex::new(MysqlRoleRepository::new(pool.clone()))
            );

            let restricted_role_pattern = init_roles(&role_repository).await.unwrap();

            let state = ServerState {
                secret,
                hashing_scheme,
                restricted_role_pattern,
                user_repository,
                role_repository,
            };

            match listener {
                Ok(listener) => {
                    tracing::info!("Server started at {}", addr);
                    axum::serve(listener, routes(state))
                        .with_graceful_shutdown(shutdown_signal())
                        .await
                        .expect("Failed to start server");
                }
                Err(e) => {
                    tracing::error!("Failed to bind to port {}: {}", port, e);
                }
            }
        }
        Some(Commands::CreateUser { email, password, role }) => {
            let user = User::now_with_email_and_password(
                email.clone(),
                password.clone()
            );

            match user {
                Ok(mut user) => {
                    let role = role.to_owned().unwrap_or("USER".to_string());
                    let existing_role = role_repository
                        .get_by_name(&role)
                        .await
                        .expect(&format!("Failed to get role {}", role));
                    user.hash_password(&SchemeAwareHasher::with_scheme(hashing_scheme));
                    user.add_role(existing_role.clone());
                    user_repository
                        .add_with_role(&user, existing_role.id)
                        .await
                        .expect("Failed to create user! Check if the email is already in use.");

                    println!(
                        "User created: {} {} at {} with roles ({})",
                        user.id,
                        user.email,
                        user.created_at.format("%Y-%m-%d %H:%M:%S"),
                        user.roles.iter().map(|r| r.name.clone()).collect::<Vec<String>>().join(", ")
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
                    UserError::InvalidPassword { reason} => {
                        panic!("Invalid password format reason: {}", reason.unwrap_or("unknown".to_string()));
                    }
                    UserError::SchemeNotSupported => {
                        panic!("Password hashing scheme not supported");
                    }
                },
            }
        }
        Some(Commands::GetUserByEmail { email }) => {
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
        Some(Commands::DeleteUserByEmail { email }) => {
            user_repository.delete_by_email(email).await.unwrap();

            println!("User deleted for {}", email);
        }
        Some(Commands::Login { email, password }) => {
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
        Some(Commands::AssignRole { email, role }) => {
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
        Some(Commands::InitRestrictedRole) => {
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
        Some(Commands::CreateRole { name }) => {
            let role = Role::now(name.to_owned()).unwrap();
            role_repository
                .add(&role)
                .await
                .expect(&format!("Failed to create {} role!", name));

            println!(
                "Created role: {}, {}, {}",
                role.id,
                role.name,
                role.created_at.format("%Y-%m-%d %H:%M:%S")
            );
        }
        Some(Commands::DeleteRole { name }) => {
            role_repository.delete_by_name(name).await.unwrap();

            println!("Role deleted for {}", name);
        }
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install CTRL+C signal handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM signal handler")
            .recv()
            .await;
    };

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}


async fn init_roles(role_repository: &Arc<Mutex<MysqlRoleRepository>>) -> Result<Regex, Error> {
    let regular_role_prefix = env::var("REGULAR_ROLE_PREFIX")
        .unwrap_or("USER".to_string());
    tracing::info!("Configured regular role prefix: {}", regular_role_prefix);

    let existing_regular_role = role_repository.lock()
        .await.get_by_name(&regular_role_prefix)
        .await;

    if existing_regular_role.is_some() {
        let existing_regular_role = existing_regular_role.clone().unwrap();
        tracing::info!(
            "Found existing regular role: {}, {}, {}",
            existing_regular_role.id,
            existing_regular_role.name,
            existing_regular_role.created_at.format("%Y-%m-%d %H:%M:%S")
        );
    } else {
        let regular_role = Role::now("USER".to_string())
            .expect("Failed to create regular role");

        role_repository.lock()
            .await.add(&regular_role)
            .await.expect("Failed to create regular role");

        tracing::info!(
            "Created initial regular role: {}, {}, {}",
            regular_role.id,
            regular_role.name,
            regular_role.created_at.format("%Y-%m-%d %H:%M:%S")
        );
    }

    let restricted_role_prefix = env::var("RESTRICTED_ROLE_PREFIX")
        .unwrap_or("ADMIN".to_string());
    tracing::info!("Configured restricted role prefix: {}", restricted_role_prefix);

    let existing_init_role = role_repository.lock()
        .await.get_by_name(&restricted_role_prefix)
        .await;

    if existing_init_role.is_some() {
        let existing_init_role = existing_init_role.clone().unwrap();
        tracing::info!(
            "Found existing restricted role base on pattern: {}, {}, {}",
            existing_init_role.id,
            existing_init_role.name,
            existing_init_role.created_at.format("%Y-%m-%d %H:%M:%S")
        );
    } else {
        let restricted_init_role = Role::now(restricted_role_prefix.clone())
            .expect("Failed to create restricted role");

        role_repository.lock()
            .await.add(&restricted_init_role)
            .await.expect("Failed to create restricted role");

        tracing::info!(
            "Created initial restricted role base on pattern: {}, {}, {}",
            restricted_init_role.id,
            restricted_init_role.name,
            restricted_init_role.created_at.format("%Y-%m-%d %H:%M:%S")
        );
    }

    parse_restricted_pattern(restricted_role_prefix.as_str())
}
