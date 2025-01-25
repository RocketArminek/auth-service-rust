use crate::application::configuration::dto::{DurationInSeconds, HiddenString};
use crate::application::service::auth_service::AuthStrategy;
use crate::domain::crypto::HashingScheme;
use lazy_regex::Regex;
use std::collections::HashMap;
use std::env;
use std::str::FromStr;
use tracing::Level;

pub struct AppConfigurationBuilder {
    pub secret: Option<HiddenString>,
    pub super_admin_email: Option<String>,
    pub super_admin_password: Option<HiddenString>,
    pub regular_role_name: Option<String>,
    pub restricted_role_name: Option<String>,
    pub restricted_role_pattern: Option<Regex>,
    pub password_hashing_scheme: Option<HashingScheme>,
    pub at_duration_in_seconds: Option<DurationInSeconds>,
    pub rt_duration_in_seconds: Option<DurationInSeconds>,
    pub verification_required: Option<bool>,
    pub vr_duration_in_seconds: Option<DurationInSeconds>,
    pub rp_duration_in_seconds: Option<DurationInSeconds>,
    pub cleanup_interval_in_minutes: Option<u64>,
    pub port: Option<String>,
    pub host: Option<String>,
    pub log_level: Option<Level>,
    pub auth_strategy: Option<AuthStrategy>,
}

impl AppConfigurationBuilder {
    pub fn new() -> Self {
        AppConfigurationBuilder {
            secret: None,
            super_admin_email: None,
            super_admin_password: None,
            regular_role_name: None,
            restricted_role_name: None,
            restricted_role_pattern: None,
            password_hashing_scheme: None,
            at_duration_in_seconds: None,
            rt_duration_in_seconds: None,
            verification_required: None,
            vr_duration_in_seconds: None,
            rp_duration_in_seconds: None,
            cleanup_interval_in_minutes: None,
            port: None,
            host: None,
            log_level: None,
            auth_strategy: None,
        }
    }

    pub fn super_admin_email(&mut self, value: String) -> &mut Self {
        self.super_admin_email = Some(value);
        self
    }

    pub fn super_admin_password(&mut self, value: HiddenString) -> &mut Self {
        self.super_admin_password = Some(value);
        self
    }

    pub fn regular_role_name(&mut self, value: String) -> &mut Self {
        self.regular_role_name = Some(value);
        self
    }

    pub fn restricted_role_name(&mut self, value: String) -> &mut Self {
        self.restricted_role_name = Some(value.clone());
        self.restricted_role_pattern =
            Some(Regex::new(format!("(?i)^{}.*", value).as_str()).unwrap());
        self
    }

    pub fn password_hashing_scheme(&mut self, value: HashingScheme) -> &mut Self {
        self.password_hashing_scheme = Some(value);
        self
    }

    pub fn at_duration_in_seconds(&mut self, value: DurationInSeconds) -> &mut Self {
        self.at_duration_in_seconds = Some(value);
        self
    }

    pub fn rt_duration_in_seconds(&mut self, value: DurationInSeconds) -> &mut Self {
        self.rt_duration_in_seconds = Some(value);
        self
    }

    pub fn verification_required(&mut self, value: bool) -> &mut Self {
        self.verification_required = Some(value);
        self
    }

    pub fn vr_duration_in_seconds(&mut self, value: DurationInSeconds) -> &mut Self {
        self.vr_duration_in_seconds = Some(value);
        self
    }

    pub fn rp_duration_in_seconds(&mut self, value: DurationInSeconds) -> &mut Self {
        self.rp_duration_in_seconds = Some(value);
        self
    }

    pub fn cleanup_interval_in_minutes(&mut self, value: u64) -> &mut Self {
        self.cleanup_interval_in_minutes = Some(value);
        self
    }

    pub fn secret(&mut self, value: HiddenString) -> &mut Self {
        self.secret = Some(value);
        self
    }

    pub fn port(&mut self, value: String) -> &mut Self {
        self.port = Some(value);
        self
    }

    pub fn host(&mut self, value: String) -> &mut Self {
        self.host = Some(value);
        self
    }

    pub fn log_level(&mut self, value: Level) -> &mut Self {
        self.log_level = Some(value);
        self
    }

    pub fn auth_strategy(&mut self, value: AuthStrategy) -> &mut Self {
        self.auth_strategy = Some(value);
        self
    }

    pub fn load_env(&mut self) -> &mut Self {
        self.super_admin_email = env::var(EnvNames::ADMIN_EMAIL).ok();
        self.super_admin_password = env::var(EnvNames::ADMIN_PASSWORD)
            .map(HiddenString)
            .ok();
        self.regular_role_name = env::var(EnvNames::REGULAR_ROLE_NAME).ok();
        self.restricted_role_name = env::var(EnvNames::RESTRICTED_ROLE_NAME).ok();
        self.restricted_role_pattern = self.restricted_role_name.as_ref()
            .map(|name| Regex::new(format!("(?i)^{}.*", name).as_str()).unwrap());
        self.password_hashing_scheme = env::var(EnvNames::PASSWORD_HASHING_SCHEME)
            .map(|v| HashingScheme::from_string(v).unwrap())
            .ok();

        self.at_duration_in_seconds = env::var(EnvNames::AT_DURATION_IN_SECONDS)
            .map(|v| DurationInSeconds::try_from(v).unwrap())
            .ok();
        self.rt_duration_in_seconds = env::var(EnvNames::RT_DURATION_IN_SECONDS)
            .map(|v| DurationInSeconds::try_from(v).unwrap())
            .ok();
        self.verification_required = env::var(EnvNames::VERIFICATION_REQUIRED)
            .map(|v| v.parse::<bool>().unwrap())
            .ok();
        self.vr_duration_in_seconds = env::var(EnvNames::VR_DURATION_IN_SECONDS)
            .map(|v| DurationInSeconds::try_from(v).unwrap())
            .ok();
        self.rp_duration_in_seconds = env::var(EnvNames::RP_DURATION_IN_SECONDS)
            .map(|v| DurationInSeconds::try_from(v).unwrap())
            .ok();
        self.cleanup_interval_in_minutes = env::var(EnvNames::CLEANUP_INTERVAL_IN_MINUTES)
            .map(|v| v.parse::<u64>().unwrap())
            .ok();
        self.secret = env::var(EnvNames::SECRET)
            .map(HiddenString)
            .ok();
        self.port = env::var(EnvNames::PORT).ok();
        self.host = env::var(EnvNames::HOST).ok();
        self.log_level = env::var(EnvNames::LOG_LEVEL)
            .map(|v| Level::from_str(v.as_str()).unwrap())
            .ok();
        self.auth_strategy = env::var(EnvNames::AUTH_STRATEGY)
            .map(|v| AuthStrategy::try_from(v).unwrap())
            .ok();

        self
    }

    pub fn build(&self) -> AppConfiguration {
        AppConfiguration::new(
            self.super_admin_email
                .clone()
                .unwrap_or("admin@example.com".to_string()),
            self.super_admin_password
                .clone()
                .unwrap_or("Admin#123*".to_string().into()),
            self.regular_role_name.clone().unwrap_or("USER".to_string()),
            self.restricted_role_name
                .clone()
                .unwrap_or("ADMIN".to_string()),
            self.restricted_role_pattern
                .clone()
                .unwrap_or(Regex::new(format!("(?i)^{}.*", "ADMIN").as_str()).unwrap()),
            self.password_hashing_scheme
                .unwrap_or(HashingScheme::BcryptLow),
            self.at_duration_in_seconds
                .clone()
                .unwrap_or(DurationInSeconds(300)),
            self.rt_duration_in_seconds
                .clone()
                .unwrap_or(DurationInSeconds(2592000)),
            self.verification_required.clone().unwrap_or(true),
            self.vr_duration_in_seconds
                .clone()
                .unwrap_or(DurationInSeconds(2592000)),
            self.rp_duration_in_seconds
                .clone()
                .unwrap_or(DurationInSeconds(2592000)),
            self.cleanup_interval_in_minutes.unwrap_or(5),
            self.secret.clone().unwrap_or("secret".to_string().into()),
            self.port.clone().unwrap_or("8080".to_string()),
            self.host.clone().unwrap_or("0.0.0.0".to_string()),
            self.log_level.unwrap_or(Level::INFO),
            self.auth_strategy.clone().unwrap_or_default(),
        )
    }
}

impl Default for AppConfigurationBuilder {
    fn default() -> Self {
        AppConfigurationBuilder::new()
    }
}

#[derive(Debug, Clone)]
pub struct AppConfiguration {
    super_admin_email: String,
    super_admin_password: HiddenString,
    regular_role_name: String,
    restricted_role_name: String,
    restricted_role_pattern: Regex,
    password_hashing_scheme: HashingScheme,
    at_duration_in_seconds: DurationInSeconds,
    rt_duration_in_seconds: DurationInSeconds,
    verification_required: bool,
    vr_duration_in_seconds: DurationInSeconds,
    rp_duration_in_seconds: DurationInSeconds,
    cleanup_interval_in_minutes: u64,
    secret: HiddenString,
    port: String,
    host: String,
    log_level: Level,
    auth_strategy: AuthStrategy,
}

impl AppConfiguration {
    pub fn new(
        super_admin_email: String,
        super_admin_password: HiddenString,
        regular_role_name: String,
        restricted_role_name: String,
        restricted_role_pattern: Regex,
        password_hashing_scheme: HashingScheme,
        at_duration_in_seconds: DurationInSeconds,
        rt_duration_in_seconds: DurationInSeconds,
        verification_required: bool,
        vr_duration_in_seconds: DurationInSeconds,
        rp_duration_in_seconds: DurationInSeconds,
        cleanup_interval_in_minutes: u64,
        secret: HiddenString,
        port: String,
        host: String,
        log_level: Level,
        auth_strategy: AuthStrategy,
    ) -> Self {
        AppConfiguration {
            super_admin_email,
            super_admin_password,
            regular_role_name,
            restricted_role_name,
            restricted_role_pattern,
            password_hashing_scheme,
            at_duration_in_seconds,
            rt_duration_in_seconds,
            verification_required,
            vr_duration_in_seconds,
            rp_duration_in_seconds,
            cleanup_interval_in_minutes,
            secret,
            port,
            host,
            log_level,
            auth_strategy,
        }
    }

    pub fn super_admin_email(&self) -> &str {
        &self.super_admin_email
    }

    pub fn super_admin_password(&self) -> HiddenString {
        self.super_admin_password.clone()
    }

    pub fn regular_role_name(&self) -> &str {
        &self.regular_role_name
    }

    pub fn restricted_role_name(&self) -> &str {
        &self.restricted_role_name
    }

    pub fn password_hashing_scheme(&self) -> HashingScheme {
        self.password_hashing_scheme.clone()
    }

    pub fn at_duration_in_seconds(&self) -> DurationInSeconds {
        self.at_duration_in_seconds.clone()
    }

    pub fn rt_duration_in_seconds(&self) -> DurationInSeconds {
        self.rt_duration_in_seconds.clone()
    }

    pub fn verification_required(&self) -> bool {
        self.verification_required.clone()
    }

    pub fn vr_duration_in_seconds(&self) -> DurationInSeconds {
        self.vr_duration_in_seconds.clone()
    }

    pub fn cleanup_interval_in_minutes(&self) -> u64 {
        self.cleanup_interval_in_minutes
    }

    pub fn secret(&self) -> HiddenString {
        self.secret.clone()
    }

    pub fn restricted_role_pattern(&self) -> Regex {
        self.restricted_role_pattern.clone()
    }

    pub fn port(&self) -> &str {
        &self.port
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn log_level(&self) -> Level {
        self.log_level
    }

    pub fn rp_duration_in_seconds(&self) -> DurationInSeconds {
        self.rp_duration_in_seconds.clone()
    }

    pub fn auth_strategy(&self) -> AuthStrategy {
        self.auth_strategy.clone()
    }

    pub fn envs(&self) -> HashMap<String, String> {
        let mut envs = HashMap::new();

        envs.insert(
            EnvNames::ADMIN_EMAIL.to_owned(),
            self.super_admin_email.clone(),
        );
        envs.insert(
            EnvNames::ADMIN_PASSWORD.to_owned(),
            self.super_admin_password.0.clone(),
        );
        envs.insert(
            EnvNames::REGULAR_ROLE_NAME.to_owned(),
            self.regular_role_name.clone(),
        );
        envs.insert(
            EnvNames::RESTRICTED_ROLE_NAME.to_owned(),
            self.restricted_role_name.clone(),
        );
        envs.insert(
            EnvNames::PASSWORD_HASHING_SCHEME.to_owned(),
            self.password_hashing_scheme.to_string(),
        );
        envs.insert(
            EnvNames::AT_DURATION_IN_SECONDS.to_owned(),
            self.at_duration_in_seconds.0.to_string(),
        );
        envs.insert(
            EnvNames::RT_DURATION_IN_SECONDS.to_owned(),
            self.rt_duration_in_seconds.0.to_string(),
        );
        envs.insert(
            EnvNames::VERIFICATION_REQUIRED.to_owned(),
            self.verification_required.to_string(),
        );
        envs.insert(
            EnvNames::VR_DURATION_IN_SECONDS.to_owned(),
            self.vr_duration_in_seconds.0.to_string(),
        );
        envs.insert(
            EnvNames::RP_DURATION_IN_SECONDS.to_owned(),
            self.rp_duration_in_seconds.0.to_string(),
        );
        envs.insert(
            EnvNames::CLEANUP_INTERVAL_IN_MINUTES.to_owned(),
            self.cleanup_interval_in_minutes.to_string(),
        );
        envs.insert(EnvNames::SECRET.to_owned(), self.secret.0.clone());
        envs.insert(EnvNames::PORT.to_owned(), self.port.to_owned());
        envs.insert(EnvNames::HOST.to_owned(), self.host.to_owned());
        envs.insert(EnvNames::LOG_LEVEL.to_owned(), self.log_level.to_string());
        envs.insert(
            EnvNames::AUTH_STRATEGY.to_owned(),
            self.auth_strategy.to_string(),
        );

        envs
    }
}

pub struct EnvNames;

impl EnvNames {
    pub const ADMIN_EMAIL: &'static str = "ADMIN_EMAIL";
    pub const ADMIN_PASSWORD: &'static str = "ADMIN_PASSWORD";
    pub const REGULAR_ROLE_NAME: &'static str = "REGULAR_ROLE_NAME";
    pub const RESTRICTED_ROLE_NAME: &'static str = "RESTRICTED_ROLE_NAME";
    pub const PASSWORD_HASHING_SCHEME: &'static str = "PASSWORD_HASHING_SCHEME";
    pub const AT_DURATION_IN_SECONDS: &'static str = "AT_DURATION_IN_SECONDS";
    pub const RT_DURATION_IN_SECONDS: &'static str = "RT_DURATION_IN_SECONDS";
    pub const VERIFICATION_REQUIRED: &'static str = "VERIFICATION_REQUIRED";
    pub const VR_DURATION_IN_SECONDS: &'static str = "VR_DURATION_IN_SECONDS";
    pub const RP_DURATION_IN_SECONDS: &'static str = "RP_DURATION_IN_SECONDS";
    pub const CLEANUP_INTERVAL_IN_MINUTES: &'static str = "CLEANUP_INTERVAL_IN_MINUTES";
    pub const SECRET: &'static str = "SECRET";
    pub const PORT: &'static str = "PORT";
    pub const HOST: &'static str = "HOST";
    pub const LOG_LEVEL: &'static str = "LOG_LEVEL";
    pub const AUTH_STRATEGY: &'static str = "AUTH_STRATEGY";
}
