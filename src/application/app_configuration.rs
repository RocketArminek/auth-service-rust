use std::env;
use regex::Regex;
use crate::application::configuration_types::{DurationInSeconds, HiddenString};
use crate::domain::crypto::HashingScheme;

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
        self.restricted_role_pattern = Some(
            Regex::new(format!("(?i)^{}.*", value).as_str()).unwrap()
        );
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

    pub fn secret(&mut self, value: HiddenString) -> &mut Self {
        self.secret = Some(value);
        self
    }

    pub fn load_env(&mut self) -> &mut Self {
        self.super_admin_email = env::var("ADMIN_EMAIL").ok();
        self.super_admin_password = env::var("ADMIN_PASSWORD")
            .and_then(|v| Ok(HiddenString(v))).ok();
        self.regular_role_name = env::var("REGULAR_ROLE_NAME").ok();
        self.restricted_role_name = env::var("RESTRICTED_ROLE_NAME").ok();
        self.restricted_role_pattern = match &self.restricted_role_name {
            None => None,
            Some(name) => Some(Regex::new(format!("(?i)^{}.*", name).as_str()).unwrap())
        };
        self.password_hashing_scheme = env::var("ADMIN_PASSWORD")
            .and_then(|v| Ok(HashingScheme::from_string(v).unwrap())).ok();

        self.at_duration_in_seconds = env::var("AT_DURATION_IN_SECONDS")
            .and_then(|v| Ok(DurationInSeconds::try_from(v).unwrap())).ok();
        self.rt_duration_in_seconds = env::var("RT_DURATION_IN_SECONDS")
            .and_then(|v| Ok(DurationInSeconds::try_from(v).unwrap())).ok();
        self.verification_required = env::var("VERIFICATION_REQUIRED").and_then(|v| Ok(v.parse::<bool>().unwrap())).ok();
        self.vr_duration_in_seconds = env::var("VR_DURATION_IN_SECONDS")
            .and_then(|v| Ok(DurationInSeconds::try_from(v).unwrap())).ok();
        self.secret = env::var("SECRET").and_then(|v| Ok(HiddenString(v))).ok();

        self
    }

    pub fn build(&self) -> AppConfiguration {
        AppConfiguration::new(
            self.super_admin_email.clone().unwrap_or("admin@example.com".to_string()),
            self.super_admin_password.clone().unwrap_or("Admin#123*".to_string().into()),
            self.regular_role_name.clone().unwrap_or("USER".to_string()),
            self.restricted_role_name.clone().unwrap_or("ADMIN".to_string()),
            self.restricted_role_pattern.clone()
                .unwrap_or(Regex::new(format!("(?i)^{}.*", "ADMIN").as_str()).unwrap()),
            self.password_hashing_scheme.clone().unwrap_or(HashingScheme::BcryptLow),
            self.at_duration_in_seconds.clone().unwrap_or(DurationInSeconds(300)),
            self.rt_duration_in_seconds.clone().unwrap_or(DurationInSeconds(2592000)),
            self.verification_required.clone().unwrap_or(true),
            self.vr_duration_in_seconds.clone().unwrap_or(DurationInSeconds(2592000)),
            self.secret.clone().unwrap_or("secret".to_string().into())
        )
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
    secret: HiddenString,
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
        secret: HiddenString,
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
            secret,
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

    pub fn secret(&self) -> HiddenString {
        self.secret.clone()
    }

    pub fn restricted_role_pattern(&self) -> Regex {
        self.restricted_role_pattern.clone()
    }
}
