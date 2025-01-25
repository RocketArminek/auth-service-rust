use assert_cmd::cargo::{CargoError, CommandCargoExt};
use auth_service::application::configuration::composed::Configuration;
use std::collections::HashMap;
use std::process::Command;

pub struct CommandFactory {
    envs: HashMap<String, String>,
}

impl CommandFactory {
    pub fn new(config: &Configuration) -> CommandFactory {
        let envs = config.envs();

        CommandFactory { envs }
    }

    pub fn create(&self, bin_name: &str) -> Result<Command, CargoError> {
        let mut cmd = Command::cargo_bin(bin_name)?;
        cmd.envs(self.envs.clone());
        Ok(cmd)
    }
}
