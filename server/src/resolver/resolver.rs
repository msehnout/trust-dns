//! Module for `Resolver`

use std::io;
use server::{Request, RequestHandler, ResponseHandler};
use trust_dns_proto::DnsHandle;
use trust_dns_proto::xfer::DnsRequestOptions;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::name_server_pool::{NameServerPool, ConnectionProvider, StandardConnection};
use trust_dns_resolver::resolver_future::BasicResolverHandle;

/// Resolver struct
/// It takes a DNS query as and input and returns a DNS response as opposed
/// to the resolver_future which takes a domain name.
/// TODO: maybe this should go to the Resolver crate and only the RequestHandler
/// trait implementation would stay here.
pub struct Resolver<C, P>
where C: DnsHandle + 'static, P: ConnectionProvider<ConnHandle = C> + 'static
{
    // Well, this does not feel as the right component to use, but it seems to
    // be the most appropriate one. Why?
    ns_pool: NameServerPool<C, P>,
}

impl Resolver<BasicResolverHandle, StandardConnection>
{
    /// Return a new resolver. Right now, it is just a forwarder to the
    /// Cloudflare public DNS servers.
    pub fn new() -> Self {
        let config = ResolverConfig::cloudflare();
        let opts = ResolverOpts::default();
        Resolver {
            ns_pool: NameServerPool::<_, StandardConnection>::from_config(&config, &opts)
        }
    }
}

impl RequestHandler for Resolver<BasicResolverHandle, StandardConnection>
{
    fn handle_request<'q, 'a, R: ResponseHandler + 'static>(
        &'a self,
        request: &'q Request,
        response_handle: R,
    ) -> io::Result<()> {
        // Extract the query from the DNS message
        let queries = request.message.queries();
        let query = queries[0].original().clone();
        let opts = DnsRequestOptions{
            expects_multiple_responses: false,
        };
        // Run a lookup procedure using the NameServerPool
        // TODO: How to wait for this? This is not a future, I cannot return now
        let mut owned_pool = self.ns_pool.clone();
        owned_pool.lookup(query, opts);
        // TODO: Call the response handler
        Ok(())
    }
}