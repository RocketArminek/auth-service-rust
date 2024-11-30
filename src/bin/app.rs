use auth_service::api::routes::routes;
use auth_service::api::server_state::{parse_restricted_pattern, ServerState};
use auth_service::domain::crypto::{HashingScheme, SchemeAwareHasher};
use auth_service::domain::error::UserError;
use auth_service::domain::event::UserEvents;
use auth_service::domain::role::Role;
use auth_service::domain::user::{PasswordHandler, User};
use auth_service::infrastructure::database::create_mysql_pool;
use auth_service::infrastructure::message_publisher::create_message_publisher;
use auth_service::infrastructure::mysql_role_repository::MysqlRoleRepository;
use auth_service::infrastructure::mysql_user_repository::MysqlUserRepository;
use auth_service::infrastructure::rabbitmq_message_publisher::create_rabbitmq_connection;
use clap::{Parser, Subcommand};
use dotenv::{dotenv, from_filename};
use futures_lite::StreamExt;
use lapin::options::{BasicAckOptions, BasicConsumeOptions, QueueBindOptions, QueueDeclareOptions};
use lapin::types::FieldTable;
use regex::{Error, Regex};
use sqlx::sqlx_macros::migrate;
use std::env;
use std::sync::Arc;
use tokio::signal;
use tokio::sync::Mutex;

#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    #[command(about = "🚀 Start the server")]
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
    CheckPassword {
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
    GetRole {
        #[arg(short, long)]
        name: String,
    },
    InitRestrictedRole,
    CheckRabbitmqConnection,
    ConsumeRabbitmqMessages {
        #[arg(short, long)]
        exchange_name: String,
        #[arg(short, long)]
        dry_run: Option<bool>,
    },
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    let cli = Cli::parse();
    from_filename(".env.local").or(dotenv()).ok();
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    let hashing_scheme =
        env::var("PASSWORD_HASHING_SCHEME").expect("PASSWORD_HASHING_SCHEME is not set in envs");
    let hashing_scheme = HashingScheme::from_string(hashing_scheme).unwrap();
    tracing::info!("Configured hashing scheme: {}", hashing_scheme.to_string());

    let at_duration_in_seconds = env::var("AT_DURATION_IN_SECONDS")
        .unwrap_or("300".to_string())
        .parse::<i64>()
        .unwrap();

    tracing::info!(
        "Configured access token duration in seconds: {} ({} m)",
        &at_duration_in_seconds,
        &at_duration_in_seconds / 60
    );

    let rt_duration_in_seconds = env::var("RT_DURATION_IN_SECONDS")
        .unwrap_or("2592000".to_string())
        .parse::<i64>()
        .unwrap();

    tracing::info!(
        "Configured refresh token duration in seconds: {} ({} d)",
        &rt_duration_in_seconds,
        &rt_duration_in_seconds / 60 / 60 / 24
    );

    let verification_required = env::var("VERIFICATION_REQUIRED")
        .unwrap_or("true".to_string())
        .parse::<bool>()
        .unwrap();

    let secret = env::var("SECRET").expect("SECRET is not set in envs");
    let pool = create_mysql_pool().await.unwrap();
    migrate_db(&pool).await;

    let user_repository = Arc::new(Mutex::new(MysqlUserRepository::new(pool.clone())));
    let role_repository = Arc::new(Mutex::new(MysqlRoleRepository::new(pool.clone())));

    let message_publisher = create_message_publisher().await;

    let restricted_role_pattern = init_roles(&role_repository).await.unwrap();

    match &cli.command {
        Some(Commands::Start) | None => {
            let port = "8080";
            let addr = &format!("0.0.0.0:{}", port);
            let listener = tokio::net::TcpListener::bind(addr).await;

            let state = ServerState {
                secret,
                hashing_scheme,
                restricted_role_pattern,
                at_duration_in_seconds,
                rt_duration_in_seconds,
                verification_required,
                user_repository,
                role_repository,
                message_publisher,
            };

            match listener {
                Ok(listener) => {
                    tracing::info!("Server started at {}", addr);
                    axum::serve(listener, routes(state))
                        .with_graceful_shutdown(shutdown_signal())
                        .await
                        .unwrap();
                }
                Err(e) => {
                    tracing::error!("Failed to bind to port {}: {}", port, e);
                }
            }
        }
        Some(Commands::CreateUser {
            email,
            password,
            role,
        }) => {
            let user =
                User::now_with_email_and_password(email.clone(), password.clone(), None, None);

            match user {
                Ok(mut user) => {
                    let role = role.to_owned().unwrap_or("USER".to_string());
                    let existing_role = role_repository
                        .lock()
                        .await
                        .get_by_name(&role)
                        .await
                        .unwrap();
                    user.hash_password(&SchemeAwareHasher::with_scheme(hashing_scheme));
                    user.add_role(existing_role.clone());
                    user_repository
                        .lock()
                        .await
                        .add_with_role(&user, existing_role.id)
                        .await
                        .unwrap();

                    println!(
                        "User created: {} {} at {} with roles ({})",
                        user.id,
                        user.email,
                        user.created_at.format("%Y-%m-%d %H:%M:%S"),
                        user.roles
                            .iter()
                            .map(|r| r.name.clone())
                            .collect::<Vec<String>>()
                            .join(", ")
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
                    UserError::InvalidPassword { reason } => {
                        panic!(
                            "Invalid password format reason: {}",
                            reason.unwrap_or("unknown".to_string())
                        );
                    }
                    UserError::SchemeNotSupported => {
                        panic!("Password hashing scheme not supported");
                    }
                },
            }
        }
        Some(Commands::GetUserByEmail { email }) => {
            let user = user_repository.lock().await.get_by_email(email).await;

            match user {
                None => {
                    println!("User not found for {}", email);
                }
                Some(user) => {
                    println!("User found: {:?}", user);
                }
            }
        }
        Some(Commands::DeleteUserByEmail { email }) => {
            user_repository
                .lock()
                .await
                .delete_by_email(email)
                .await
                .unwrap();

            println!("User deleted for {}", email);
        }
        Some(Commands::CheckPassword { email, password }) => {
            let user = user_repository.lock().await.get_by_email(email).await;

            match user {
                None => {
                    println!("User not found for {}", email);
                }
                Some(user) => {
                    let hasher = SchemeAwareHasher::with_scheme(hashing_scheme);

                    if user.verify_password(&hasher, password) {
                        println!(
                            "User: {} {} at {} password is correct",
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
            let user = user_repository.lock().await.get_by_email(email).await;

            match user {
                None => {
                    println!("User not found for {}", email);
                }
                Some(user) => {
                    let r = role_repository.lock().await.get_by_name(role).await;

                    match r {
                        None => {
                            println!("Role not found for {}", role);
                        }
                        Some(role) => {
                            user_repository
                                .lock()
                                .await
                                .add_role(user.id, role.id)
                                .await
                                .unwrap();

                            println!("Role assigned: {} to {}", role.name, user.email);
                        }
                    }
                }
            }
        }
        Some(Commands::InitRestrictedRole) => {
            let restricted_role_prefix =
                env::var("RESTRICTED_ROLE_PREFIX").unwrap_or("ADMIN".to_string());
            let role = role_repository
                .lock()
                .await
                .get_by_name(&restricted_role_prefix)
                .await;

            match role {
                None => {
                    let role = Role::now(restricted_role_prefix).unwrap();
                    role_repository.lock().await.add(&role).await.unwrap();

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
            role_repository.lock().await.add(&role).await.unwrap();

            println!(
                "Created role: {}, {}, {}",
                role.id,
                role.name,
                role.created_at.format("%Y-%m-%d %H:%M:%S")
            );
        }
        Some(Commands::GetRole { name }) => {
            let role = role_repository.lock().await.get_by_name(name).await;
            match role {
                None => {
                    panic!("Role not found for {}", name);
                }
                Some(role) => {
                    println!("Get role: {}", role.name);
                }
            }
        }
        Some(Commands::DeleteRole { name }) => {
            role_repository
                .lock()
                .await
                .delete_by_name(name)
                .await
                .unwrap();

            println!("Role deleted for {}", name);
        }
        Some(Commands::CheckRabbitmqConnection) => {
            create_rabbitmq_connection().await;
        }
        Some(Commands::ConsumeRabbitmqMessages {
            exchange_name,
            dry_run,
        }) => {
            let conn = create_rabbitmq_connection().await;
            let exchange_name = exchange_name.to_owned();
            let channel = conn
                .create_channel()
                .await
                .expect("Failed to create channel");
            let dry_run = dry_run.unwrap_or(false);

            let queue = channel
                .queue_declare(
                    "",
                    QueueDeclareOptions {
                        exclusive: true,
                        auto_delete: true,
                        ..QueueDeclareOptions::default()
                    },
                    FieldTable::default(),
                )
                .await
                .expect("Failed to declare queue");

            let queue_name = queue.name().to_string();

            let r = channel
                .queue_bind(
                    &queue_name,
                    &exchange_name,
                    "",
                    QueueBindOptions::default(),
                    FieldTable::default(),
                )
                .await;

            if r.is_err() {
                println!("Could not bind queue");
                return;
            }

            let mut consumer = channel
                .basic_consume(
                    &queue_name,
                    "test_consumer",
                    BasicConsumeOptions::default(),
                    FieldTable::default(),
                )
                .await
                .expect("Failed to create consumer");

            if dry_run {
                println!("Just a dry run");
                return;
            }

            while let Some(delivery) = consumer.next().await {
                match delivery {
                    Ok(delivery) => {
                        if let Ok(event) = serde_json::from_slice::<UserEvents>(&delivery.data) {
                            println!("Received event: {:?}", event);
                        } else {
                            println!("Cannot deserialize event: {:?}", delivery);
                        }

                        delivery
                            .ack(BasicAckOptions::default())
                            .await
                            .expect("Failed to ack message");
                    }
                    Err(e) => {
                        println!("Error receiving message: {:?}", e);
                    }
                }
            }
        }
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c().await.unwrap();
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .unwrap()
            .recv()
            .await;
    };

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

async fn init_roles(role_repository: &Arc<Mutex<MysqlRoleRepository>>) -> Result<Regex, Error> {
    init_role(
        &"REGULAR_ROLE_PREFIX".to_string(),
        "USER".to_string(),
        role_repository,
    )
    .await;
    let restricted_role = init_role(
        &"RESTRICTED_ROLE_PREFIX".to_string(),
        "ADMIN".to_string(),
        role_repository,
    )
    .await;

    parse_restricted_pattern(restricted_role.name.as_str())
}

async fn init_role(
    role_env_var: &String,
    default: String,
    role_repository: &Arc<Mutex<MysqlRoleRepository>>,
) -> Role {
    let role_prefix = env::var(role_env_var).unwrap_or(default);

    tracing::info!("Configured {} with: {}", role_env_var, role_prefix);
    let existing_role = role_repository.lock().await.get_by_name(&role_prefix).await;

    if existing_role.is_some() {
        let existing_role = existing_role.clone().unwrap();
        tracing::info!(
            "Found existing role: {}, {}, {}",
            existing_role.id,
            existing_role.name,
            existing_role.created_at.format("%Y-%m-%d %H:%M:%S")
        );

        return existing_role;
    }

    let role = Role::now(role_prefix.to_string()).unwrap();

    role_repository.lock().await.add(&role).await.unwrap();

    tracing::info!(
        "Created role: {}, {}, {}",
        role.id,
        role.name,
        role.created_at.format("%Y-%m-%d %H:%M:%S")
    );

    role
}

async fn migrate_db(pool: &sqlx::MySqlPool) {
    let migration_result = migrate!("./migrations").run(pool).await;
    match migration_result {
        Ok(_) => {
            tracing::info!("Database migration completed successfully");
        }
        Err(e) => {
            tracing::error!("Failed to migrate database: {}", e);
            panic!("Failed to migrate database");
        }
    }
}
