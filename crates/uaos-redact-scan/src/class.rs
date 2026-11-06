// SPDX-License-Identifier: Apache-2.0

//! The high-risk data classes detector set v1 claims.

use std::fmt;

/// A class of high-risk secret. Declaration order is merge priority: when two detections
/// overlap, the merged span takes the class declared first (the more specific format).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum DataClass {
    /// PEM private key block (RSA, EC, DSA, OpenSSH, PKCS#8, encrypted, PGP).
    PrivateKey,
    /// Signed JSON Web Token (bearer credential).
    Jwt,
    /// Anthropic API or admin key (`sk-ant-…`).
    AnthropicApiKey,
    /// `OpenAI` API key (project, service account, admin, legacy).
    OpenaiApiKey,
    /// GitHub token (classic `gh?_…` or fine-grained `github_pat_…`).
    GithubToken,
    /// GitLab personal, runner or deploy token.
    GitlabToken,
    /// Slack token (`xox?-…`) or incoming-webhook path.
    SlackToken,
    /// Stripe secret or restricted key.
    StripeKey,
    /// Google API key (`AIza…`).
    GoogleApiKey,
    /// AWS access key id.
    AwsAccessKeyId,
    /// Password in a URL's userinfo (`scheme://user:password@host`).
    UrlCredentials,
}

impl DataClass {
    /// Every class, in priority order.
    pub const ALL: [Self; 11] = [
        Self::PrivateKey,
        Self::Jwt,
        Self::AnthropicApiKey,
        Self::OpenaiApiKey,
        Self::GithubToken,
        Self::GitlabToken,
        Self::SlackToken,
        Self::StripeKey,
        Self::GoogleApiKey,
        Self::AwsAccessKeyId,
        Self::UrlCredentials,
    ];

    /// Stable wire name, used in placeholders, policy context (`data_classes`) and events.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PrivateKey => "private_key",
            Self::Jwt => "jwt",
            Self::AnthropicApiKey => "anthropic_api_key",
            Self::OpenaiApiKey => "openai_api_key",
            Self::GithubToken => "github_token",
            Self::GitlabToken => "gitlab_token",
            Self::SlackToken => "slack_token",
            Self::StripeKey => "stripe_key",
            Self::GoogleApiKey => "google_api_key",
            Self::AwsAccessKeyId => "aws_access_key_id",
            Self::UrlCredentials => "url_credentials",
        }
    }
}

impl fmt::Display for DataClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
