use auth_service::api::routes::routes;
use auth_service::api::server_state::ServerState;
use auth_service::application::app_configuration::{AppConfiguration, EnvNames as AppEnvNames};
use auth_service::application::configuration::Configuration;
use auth_service::application::message_publisher_configuration::MessagePublisherConfiguration;
use auth_service::domain::crypto::SchemeAwareHasher;
use auth_service::domain::error::UserError;
use auth_service::domain::event::UserEvents;
use auth_service::domain::repositories::{RoleRepository, UserRepository};
use auth_service::domain::role::Role;
use auth_service::domain::user::{PasswordHandler, User};
use auth_service::infrastructure::database::create_pool;
use auth_service::infrastructure::message_publisher::create_message_publisher;
use auth_service::infrastructure::rabbitmq_message_publisher::create_rabbitmq_connection;
use auth_service::infrastructure::repository::{
    create_role_repository, create_user_repository, RepositoryError,
};
use clap::{Parser, Subcommand};
use futures_lite::StreamExt;
use lapin::options::{BasicAckOptions, BasicConsumeOptions, QueueBindOptions, QueueDeclareOptions};
use lapin::types::FieldTable;
use std::env;
use std::sync::Arc;
use tokio::signal;
use auth_service::application::auth_service::create_auth_service;

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
    HealthCheck,
    ConsumeRabbitmqMessages {
        #[arg(short, long)]
        exchange_name: String,
        #[arg(short, long)]
        dry_run: Option<bool>,
    },
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    let config = Configuration::default();
    let cli = Cli::parse();

    setup_logging(&config);

    debug_config(&config);

    let db_pool = create_pool(config.db()).await.unwrap();
    db_pool.migrate().await;

    let user_repository = create_user_repository(db_pool.clone());
    let role_repository = create_role_repository(db_pool.clone());

    let message_publisher = create_message_publisher(config.publisher()).await;

    let auth_service = create_auth_service(
        config.app(),
        user_repository.clone(),
    );

    load_fixtures(config.app(), &user_repository, &role_repository).await;
    let hashing_scheme = config.app().password_hashing_scheme();

    match &cli.command {
        Some(Commands::Start) | None => {
            let port = config.app().port();
            let host = config.app().host();
            let addr = format!("{}:{}", host, port);
            let listener = tokio::net::TcpListener::bind(&addr).await;
            let config = config.app().clone();

            let state = ServerState::new(
                config,
                user_repository,
                role_repository,
                message_publisher,
                auth_service,
            );

            match listener {
                Ok(listener) => {
                    tracing::info!("Server started at {}", &addr);
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
            let user = User::now_with_email_and_password(
                email.clone(),
                password.clone(),
                None,
                None,
                Some(true),
            );

            match user {
                Ok(mut user) => {
                    let role = role.to_owned().unwrap_or("USER".to_string());
                    let existing_role = role_repository.get_by_name(&role).await.unwrap();
                    if let Err(e) =
                        user.hash_password(&SchemeAwareHasher::with_scheme(hashing_scheme))
                    {
                        println!("Failed to hash user's password: {:?}", e);

                        return;
                    }
                    user.add_role(existing_role.clone());
                    user_repository.save(&user).await.unwrap();

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
            let user = user_repository.get_by_email(email).await;

            match user {
                Err(e) => {
                    println!("Error {:?}", e);
                }
                Ok(user) => {
                    println!("User found: {:?}", user);
                }
            }
        }
        Some(Commands::DeleteUserByEmail { email }) => {
            user_repository.delete_by_email(email).await.unwrap();

            println!("User deleted for {}", email);
        }
        Some(Commands::CheckPassword { email, password }) => {
            let user = user_repository.get_by_email(email).await;

            match user {
                Err(e) => {
                    println!("Error {:?}", e);
                }
                Ok(user) => {
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
            let user = user_repository.get_by_email(email).await;

            match user {
                Err(e) => {
                    println!("Error {:?}", e);
                }
                Ok(mut user) => {
                    let r = role_repository.get_by_name(role).await;

                    match r {
                        Err(e) => {
                            println!("{}", e.to_string());
                        }
                        Ok(role) => {
                            user.add_role(role.clone());
                            user_repository.save(&user).await.unwrap();

                            println!("Role assigned: {} to {}", role.name, user.email);
                        }
                    }
                }
            }
        }
        Some(Commands::InitRestrictedRole) => {
            let restricted_role_prefix =
                env::var("RESTRICTED_ROLE_PREFIX").unwrap_or("ADMIN".to_string());
            let role = role_repository.get_by_name(&restricted_role_prefix).await;

            match role {
                Err(_) => {
                    let role = Role::now(restricted_role_prefix).unwrap();
                    role_repository.save(&role).await.unwrap();

                    println!(
                        "Created initial restricted role base on pattern: {}, {}, {}",
                        role.id,
                        role.name,
                        role.created_at.format("%Y-%m-%d %H:%M:%S")
                    );
                }
                Ok(_) => {
                    println!("Role already exists");
                }
            }
        }
        Some(Commands::CreateRole { name }) => {
            let role = Role::now(name.to_owned()).unwrap();
            role_repository.save(&role).await.unwrap();

            println!(
                "Created role: {}, {}, {}",
                role.id,
                role.name,
                role.created_at.format("%Y-%m-%d %H:%M:%S")
            );
        }
        Some(Commands::GetRole { name }) => {
            let role = role_repository.get_by_name(name).await;
            match role {
                Err(e) => {
                    panic!("Error {:?}", e);
                }
                Ok(role) => {
                    println!("Get role: {}", role.name);
                }
            }
        }
        Some(Commands::DeleteRole { name }) => {
            role_repository.delete_by_name(name).await.unwrap();

            println!("Role deleted for {}", name);
        }
        Some(Commands::HealthCheck) => {}
        Some(Commands::ConsumeRabbitmqMessages {
            exchange_name,
            dry_run,
        }) => match config.publisher() {
            MessagePublisherConfiguration::Rabbitmq(config) => {
                let conn = create_rabbitmq_connection(config).await;
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
                            if let Ok(event) = serde_json::from_slice::<UserEvents>(&delivery.data)
                            {
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
            MessagePublisherConfiguration::None => {
                println!("No message publishing enabled");
            }
        },
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c().await.unwrap();
        tracing::info!("Received Ctrl+C, starting graceful shutdown");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .unwrap()
            .recv()
            .await;
        tracing::info!("Received terminate signal, starting graceful shutdown");
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

async fn load_fixtures(
    config: &AppConfiguration,
    user_repository: &Arc<dyn UserRepository>,
    role_repository: &Arc<dyn RoleRepository>,
) {
    init_role(config.regular_role_name(), &role_repository)
        .await
        .unwrap();
    let restricted_role = init_role(config.restricted_role_name(), &role_repository)
        .await
        .unwrap();
    init_user(config, &user_repository, restricted_role)
        .await
        .unwrap();
}

async fn init_user(
    config: &AppConfiguration,
    user_repository: &Arc<dyn UserRepository>,
    role: Role,
) -> Result<User, RepositoryError> {
    let email = config.super_admin_email().to_string();

    let existing_user = user_repository.get_by_email(&email).await;

    if let Ok(existing_user) = existing_user {
        tracing::info!(
            "Found existing super admin: {}, {}, {}",
            &existing_user.id,
            &existing_user.email,
            &existing_user.created_at.format("%Y-%m-%d %H:%M:%S")
        );

        return Ok(existing_user);
    }

    let password = config.super_admin_password().to_string();

    let mut user = User::now_with_email_and_password(email, password, None, None, Some(true))
        .unwrap()
        .with_roles(vec![role]);
    user.hash_password(&SchemeAwareHasher::with_scheme(
        config.password_hashing_scheme(),
    ))
    .unwrap();

    let r = user_repository.save(&user).await;
    if let Err(e) = r {
        tracing::error!("Error saving user: {}", e);

        return Err(e);
    }

    tracing::info!(
        "Super admin created: {}, {}, {}",
        &user.id,
        &user.email,
        &user.created_at.format("%Y-%m-%d %H:%M:%S")
    );

    Ok(user)
}

async fn init_role(
    role_name: &str,
    role_repository: &Arc<dyn RoleRepository>,
) -> Result<Role, RepositoryError> {
    let existing_role = role_repository.get_by_name(role_name).await;

    if let Ok(existing_role) = existing_role {
        tracing::info!(
            "Found existing role: {}, {}, {}",
            &existing_role.id,
            &existing_role.name,
            &existing_role.created_at.format("%Y-%m-%d %H:%M:%S")
        );

        return Ok(existing_role);
    }

    let role = Role::now(role_name.to_string()).unwrap();

    let r = role_repository.save(&role).await;

    if let Err(e) = r {
        tracing::error!(
            "Failed to add role: {} during init role due to: {:?}",
            role_name,
            e
        );

        return Err(e);
    }

    tracing::info!(
        "Created role: {}, {}, {}",
        role.id,
        role.name,
        role.created_at.format("%Y-%m-%d %H:%M:%S")
    );

    Ok(role)
}

fn setup_logging(config: &Configuration) {
    tracing_subscriber::fmt()
        .with_target(true)
        .with_thread_ids(true)
        .with_thread_names(true)
        .with_max_level(config.app().log_level())
        .json()
        .init();

    tracing::info!(version = env!("CARGO_PKG_VERSION"), "Starting auth service");
}

fn debug_config(config: &Configuration) {
    let message = "Configuration loaded successfully";
    for (name, value) in config.envs() {
        match name.as_str() {
            AppEnvNames::ADMIN_PASSWORD => {
                tracing::debug!(message, env = name, value = "****");
            }
            AppEnvNames::SECRET => {
                tracing::debug!(message, env = name, value = "****");
            }
            _ => {
                tracing::debug!(message, env = name, value = %value);
            }
        }
    }
}
