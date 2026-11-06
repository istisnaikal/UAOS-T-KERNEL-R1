// SPDX-License-Identifier: Apache-2.0

//! Name resolution. The door resolves names itself and classifies every answer before it
//! connects, so a DNS answer can never steer it to an address it would refuse (rebinding).

use std::fmt;
use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;

use crate::host::HostName;

/// The addresses a name resolves to, or the resolver's failure.
pub type Resolution<'a> = Pin<Box<dyn Future<Output = io::Result<Vec<IpAddr>>> + Send + 'a>>;

/// Resolves host names. The system resolver in production; a fixed table in tests.
pub trait Resolve: Send + Sync + fmt::Debug {
    /// The addresses `host` resolves to, in the resolver's order.
    fn resolve<'a>(&'a self, host: &'a HostName, port: u16) -> Resolution<'a>;
}

/// The operating system's resolver (`getaddrinfo` and its platform equivalents).
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemResolver;

impl Resolve for SystemResolver {
    fn resolve<'a>(&'a self, host: &'a HostName, port: u16) -> Resolution<'a> {
        Box::pin(async move {
            #[allow(
                clippy::disallowed_methods,
                reason = "uaos-egress owns name resolution: the one place outbound DNS happens"
            )]
            let found = tokio::net::lookup_host((host.as_str(), port)).await?;
            Ok(found.map(|addr| addr.ip()).collect())
        })
    }
}
