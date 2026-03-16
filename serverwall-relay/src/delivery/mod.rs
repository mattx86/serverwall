pub mod mx_resolver;
pub mod sender;
pub mod tls;

pub use mx_resolver::MxResolver;
pub use sender::{DeliveryResult, SmtpSender};
pub use tls::OutboundTls;

use std::sync::Arc;

use anyhow::Result;
use tokio::sync::Semaphore;

use crate::bounce::BounceGenerator;
use crate::queue::message::QueueStatus;
use crate::queue::scheduler::RetryScheduler;
use crate::queue::spool::FilesystemSpool;

/// Background delivery manager.
///
/// Periodically scans the spool for messages due for delivery, resolves MX
/// records, and attempts to send each message.  On success the message is
/// removed; on temporary failure it is re-scheduled; on permanent failure
/// (or max-retry expiry) a bounce is generated.
pub struct DeliveryManager {
    spool: Arc<FilesystemSpool>,
    scheduler: Arc<RetryScheduler>,
    resolver: Arc<MxResolver>,
    sender: Arc<SmtpSender>,
    bounce_gen: Arc<BounceGenerator>,
    concurrency: Arc<Semaphore>,
}

impl DeliveryManager {
    pub fn new(
        spool: Arc<FilesystemSpool>,
        scheduler: Arc<RetryScheduler>,
        resolver: Arc<MxResolver>,
        sender: Arc<SmtpSender>,
        bounce_gen: Arc<BounceGenerator>,
        delivery_threads: usize,
    ) -> Self {
        Self {
            spool,
            scheduler,
            resolver,
            sender,
            bounce_gen,
            concurrency: Arc::new(Semaphore::new(delivery_threads)),
        }
    }

    /// Run the delivery loop.  This should be spawned as a background task.
    pub async fn run(&self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        tracing::info!("delivery manager started");

        loop {
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {
                    if let Err(e) = self.process_queue().await {
                        tracing::error!(error = %e, "delivery processing error");
                    }
                }
                _ = shutdown.changed() => {
                    tracing::info!("delivery manager shutting down");
                    return;
                }
            }
        }
    }

    /// Scan the queue once and attempt delivery for all due messages.
    async fn process_queue(&self) -> Result<()> {
        let messages = self.spool.list()?;
        let now = chrono::Utc::now();

        for msg in messages {
            // Only process pending/deferred messages whose next_retry is past
            match msg.metadata.status {
                QueueStatus::Pending | QueueStatus::Deferred => {}
                _ => continue,
            }
            if msg.metadata.next_retry > now {
                continue;
            }

            let spool = self.spool.clone();
            let scheduler = self.scheduler.clone();
            let resolver = self.resolver.clone();
            let sender = self.sender.clone();
            let bounce_gen = self.bounce_gen.clone();
            let permit = self.concurrency.clone().acquire_owned().await;

            if permit.is_err() {
                break; // semaphore closed
            }
            let _permit = permit.unwrap();

            let queue_id = msg.id.clone();
            tokio::spawn(async move {
                if let Err(e) = deliver_message(
                    &queue_id, &spool, &scheduler, &resolver, &sender, &bounce_gen,
                ).await {
                    tracing::error!(queue_id = %queue_id, error = %e, "delivery task failed");
                }
                drop(_permit);
            });
        }

        Ok(())
    }
}

/// Attempt delivery of a single queued message.
async fn deliver_message(
    queue_id: &str,
    spool: &FilesystemSpool,
    scheduler: &RetryScheduler,
    resolver: &MxResolver,
    sender: &SmtpSender,
    bounce_gen: &BounceGenerator,
) -> Result<()> {
    let (mut queued, msg_bytes) = spool.dequeue(queue_id)?;

    // Mark active
    queued.metadata.status = QueueStatus::Active;
    queued.metadata.attempts += 1;
    spool.update_metadata(queue_id, &queued.metadata)?;

    // Extract recipient domain from first RCPT TO
    let domain = queued
        .envelope
        .rcpt_to
        .first()
        .and_then(|r| r.rsplit('@').next())
        .unwrap_or("localhost");

    // Resolve MX
    let mx_hosts = match resolver.resolve(domain).await {
        Ok(hosts) => hosts,
        Err(e) => {
            tracing::warn!(queue_id = %queue_id, domain = %domain, error = %e, "MX resolution failed");
            return handle_temp_fail(queue_id, &e.to_string(), &mut queued, spool, scheduler, bounce_gen);
        }
    };

    // Try each MX host in priority order
    for mx_host in &mx_hosts {
        for &addr in &mx_host.addresses {
            let sock_addr = std::net::SocketAddr::new(addr, 25);
            let result = sender
                .send(
                    sock_addr,
                    &mx_host.hostname,
                    &queued.envelope.mail_from,
                    &queued.envelope.rcpt_to,
                    &msg_bytes,
                )
                .await;

            match result {
                DeliveryResult::Success(resp) => {
                    tracing::info!(queue_id = %queue_id, response = %resp, "message delivered");
                    spool.remove(queue_id)?;
                    return Ok(());
                }
                DeliveryResult::PermFail(err) => {
                    tracing::warn!(queue_id = %queue_id, error = %err, "permanent delivery failure");
                    // Generate bounce and remove
                    if let Some((bounce_env, bounce_msg)) =
                        bounce_gen.generate(&queued.envelope, &err, &msg_bytes)
                    {
                        let _ = spool.enqueue(bounce_env, bounce_msg);
                    }
                    spool.remove(queue_id)?;
                    return Ok(());
                }
                DeliveryResult::TempFail(err) => {
                    tracing::debug!(
                        queue_id = %queue_id,
                        mx = %mx_host.hostname,
                        addr = %addr,
                        error = %err,
                        "temporary failure, trying next host"
                    );
                    queued.metadata.last_error = Some(err);
                    // Continue to next address / MX host
                }
            }
        }
    }

    // All MX hosts failed with temp errors
    let last_err = queued.metadata.last_error.clone().unwrap_or_default();
    handle_temp_fail(queue_id, &last_err, &mut queued, spool, scheduler, bounce_gen)
}

fn handle_temp_fail(
    queue_id: &str,
    error: &str,
    queued: &mut crate::queue::QueuedMessage,
    spool: &FilesystemSpool,
    scheduler: &RetryScheduler,
    bounce_gen: &BounceGenerator,
) -> Result<()> {
    // Check if expired
    if scheduler.is_expired(queued.metadata.created) {
        tracing::warn!(queue_id = %queue_id, "message expired, generating bounce");
        if let Some((bounce_env, bounce_msg)) =
            bounce_gen.generate(&queued.envelope, error, &[])
        {
            let _ = spool.enqueue(bounce_env, bounce_msg);
        }
        spool.remove(queue_id)?;
        return Ok(());
    }

    // Schedule retry
    match scheduler.next_retry_time(queued.metadata.attempts) {
        Some(next) => {
            queued.metadata.next_retry = next;
            queued.metadata.status = QueueStatus::Deferred;
            queued.metadata.last_error = Some(error.to_string());
            spool.update_metadata(queue_id, &queued.metadata)?;
            tracing::info!(
                queue_id = %queue_id,
                next_retry = %next,
                "message deferred"
            );
        }
        None => {
            tracing::warn!(queue_id = %queue_id, "max attempts exceeded, generating bounce");
            if let Some((bounce_env, bounce_msg)) =
                bounce_gen.generate(&queued.envelope, error, &[])
            {
                let _ = spool.enqueue(bounce_env, bounce_msg);
            }
            spool.remove(queue_id)?;
        }
    }

    Ok(())
}
