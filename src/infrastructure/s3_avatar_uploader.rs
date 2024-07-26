use aws_sdk_s3::{Client, Config};
use uuid::Uuid;
use std::env;
use std::error::Error;
use aws_sdk_s3::config::{Credentials, Region};
use aws_sdk_s3::primitives::ByteStream;

pub struct S3AvatarUploader {
    client: Client,
    bucket: String,
    region: String,
}

impl S3AvatarUploader {
    pub fn new() -> Result<Self, Box<dyn Error>> {
        let access_key = env::var("AWS_ACCESS_KEY").expect("AWS_ACCESS_KEY is not set");
        let secret_key = env::var("AWS_SECRET_ACCESS_KEY").expect("AWS_SECRET_ACCESS_KEY is not set");
        let bucket = env::var("AWS_BUCKET").expect("AWS_BUCKET is not set");
        let region = env::var("AWS_REGION").expect("AWS_REGION is not set");

        let credentials = Credentials::new(access_key, secret_key, None, None, "example");
        let config = Config::builder()
            .region(Region::new(region.clone()))
            .credentials_provider(credentials)
            .build();
        let client = Client::from_conf(config);

        Ok(Self {
            client,
            bucket,
            region,
        })
    }
}

impl S3AvatarUploader {
    pub async fn upload(&self, user_id: Uuid, file_name: &str, file_content: Vec<u8>) -> Result<String, Box<dyn Error + Send + Sync>> {
        let key = format!("{}/{}", user_id, file_name);

        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(&key)
            .body(ByteStream::from(file_content))
            .send()
            .await?;

        let avatar_url = format!(
            "https://{}.s3.{}.amazonaws.com/{}",
            self.bucket,
            self.region,
            key
        );

        Ok(avatar_url)
    }
}

pub struct InMemoryAvatarUploader;

impl InMemoryAvatarUploader {
    pub fn new() -> Self {
        Self {}
    }
}

impl InMemoryAvatarUploader {
    pub fn upload(&self, _user_id: Uuid, file_name: &str, _file_content: Vec<u8>) -> Result<String, Box<dyn Error + Send + Sync>> {
        Ok(format!("in-memory://{}", file_name))
    }
}
