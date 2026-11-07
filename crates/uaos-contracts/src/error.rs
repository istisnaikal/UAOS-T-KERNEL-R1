// SPDX-License-Identifier: Apache-2.0

//! Unified error taxonomy, `uaos.error/1`.
//!
//! Every error UAOS itself originates has a registered code `UAOS-<DOMAIN>-<NNNN>`, a class,
//! a severity, a retry hint, a localizable message key, and a remediation pointer. The
//! registry below is the single source; reference documentation is generated from it.
//!
//! Two rules.
//! * **Upstream provider errors are never rewritten.** Clients' recovery logic matches on the
//!   provider's wording; UAOS adds `x-uaos-*` headers only.
//! * **UAOS-originated errors use the client dialect's own error shape**, carrying this
//!   contract in a `uaos` extension object.

use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::id::{CorrelationId, EventId};

/// Subsystem that originates an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorDomain {
    /// Journal and storage.
    Journal,
    /// Encrypted content store and its keys.
    Store,
    /// Authorization policy.
    Policy,
    /// Budget ledger.
    Budget,
    /// Secret detection and redaction.
    Redact,
    /// Operation runtime.
    Runtime,
    /// Client-facing ingress.
    Ingress,
    /// Outbound network path.
    Egress,
    /// Configuration.
    Config,
    /// Credentials and keys.
    Identity,
    /// The `uaos` command line.
    Cli,
}

impl ErrorDomain {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Journal => "JOURNAL",
            Self::Store => "STORE",
            Self::Policy => "POLICY",
            Self::Budget => "BUDGET",
            Self::Redact => "REDACT",
            Self::Runtime => "RUNTIME",
            Self::Ingress => "INGRESS",
            Self::Egress => "EGRESS",
            Self::Config => "CONFIG",
            Self::Identity => "IDENTITY",
            Self::Cli => "CLI",
        }
    }
}

/// Who or what is at the root of the error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ErrorClass {
    /// The request itself is invalid.
    User,
    /// Configuration is invalid or inconsistent.
    Config,
    /// A policy decision refused the action.
    Policy,
    /// A budget rule refused the action.
    Budget,
    /// The upstream provider failed.
    Provider,
    /// A tool failed.
    Tool,
    /// A defect or resource failure inside UAOS.
    Internal,
    /// A security control acted.
    Security,
}

/// Incident severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Secret leak, RCE, data loss, budget runaway.
    S1,
    /// Durability, crash, provider cascade.
    S2,
    /// UX or performance degradation.
    S3,
    /// Expected, user-actionable condition (for example a policy denial).
    Info,
}

/// A registered error code such as `UAOS-BUDGET-0001`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ErrorCode {
    domain: ErrorDomain,
    number: u16,
}

impl ErrorCode {
    /// Creates a code. Only codes present in [`REGISTRY`] are meaningful.
    #[must_use]
    pub const fn new(domain: ErrorDomain, number: u16) -> Self {
        Self { domain, number }
    }

    /// The originating domain.
    #[must_use]
    pub const fn domain(self) -> ErrorDomain {
        self.domain
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UAOS-{}-{:04}", self.domain.as_str(), self.number)
    }
}

/// Static description of a registered error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErrorSpec {
    /// The code.
    pub code: ErrorCode,
    /// Root-cause class.
    pub class: ErrorClass,
    /// Severity.
    pub severity: Severity,
    /// Whether retrying the same request can succeed without any change.
    pub retryable: bool,
    /// Whether the condition implies a possible secret exposure.
    pub secret_leak_risk: bool,
    /// Localization key for the user-facing message (Fluent catalogs, TR/EN).
    pub message_key: &'static str,
    /// English summary used in generated reference documentation.
    pub summary: &'static str,
    /// What to do about it.
    pub remediation: &'static str,
}

macro_rules! registry {
    ($( $const_name:ident = $domain:ident $num:literal, $class:ident, $sev:ident,
        retryable: $retry:literal, leak: $leak:literal, $key:literal, $summary:literal, $fix:literal; )*) => {
        /// Registered error codes, one constant per code.
        pub mod codes {
            use super::{ErrorCode, ErrorDomain};
            $(
                #[doc = $summary]
                pub const $const_name: ErrorCode = ErrorCode::new(ErrorDomain::$domain, $num);
            )*
        }

        /// The error registry: the single source of truth for codes and their meaning.
        pub const REGISTRY: &[ErrorSpec] = &[
            $(ErrorSpec {
                code: codes::$const_name,
                class: ErrorClass::$class,
                severity: Severity::$sev,
                retryable: $retry,
                secret_leak_risk: $leak,
                message_key: $key,
                summary: $summary,
                remediation: $fix,
            },)*
        ];
    };
}

registry! {
    JOURNAL_WRITE_FAILED = Journal 1, Internal, S2, retryable: false, leak: false,
        "error-journal-write-failed", "A critical journal record could not be handed to the OS; the operation was not started.",
        "Run `uaos doctor`; check disk health and permissions of the data directory.";
    JOURNAL_DISK_FULL = Journal 2, Internal, S2, retryable: false, leak: false,
        "error-journal-disk-full", "The data directory is out of space; operations that need a critical record fail closed.",
        "Free disk space; no data was corrupted. See the disk-full runbook.";
    JOURNAL_FSYNC_FAILED = Journal 3, Internal, S2, retryable: false, leak: false,
        "error-journal-fsync-failed", "Flushing the journal to stable storage failed; the writer stopped and unflushed records are rewritten to a new segment.",
        "Check storage health; run `uaos journal verify`.";
    JOURNAL_CHAIN_BROKEN = Journal 4, Security, S1, retryable: false, leak: false,
        "error-journal-chain-broken", "The journal hash chain does not verify; records were altered or lost outside UAOS.",
        "Stop and preserve the data directory; run `uaos journal verify --report`.";
    JOURNAL_INSTANCE_LOCKED = Journal 5, Config, Info, retryable: false, leak: false,
        "error-journal-instance-locked", "Another UAOS daemon already owns this data directory.",
        "Use `uaos status` to find it; `uaos run` attaches to it automatically.";
    JOURNAL_READER_TOO_OLD = Journal 6, Config, S3, retryable: false, leak: false,
        "error-journal-reader-too-old", "This binary is older than the journal's minimum reader version; it refuses to run instead of risking corruption.",
        "Upgrade, or restore the matching data-directory backup before downgrading.";
    JOURNAL_PAYLOAD_NOT_STORED = Journal 7, Internal, S2, retryable: false, leak: false,
        "error-journal-payload-not-stored", "UAOS tried to record a reference to content it had not stored; nothing was recorded.",
        "Report this with `uaos trace`; it indicates a defect, not a problem with your data.";
    STORE_CHUNK_UNAVAILABLE = Store 1, User, Info, retryable: false, leak: false,
        "error-store-chunk-unavailable", "The content is not available: it was never stored here, or it was deliberately shredded.",
        "Check `uaos trace` for a chunk.shredded event; shredded content cannot be recovered by design.";
    STORE_CHUNK_CORRUPT = Store 2, Security, S1, retryable: false, leak: false,
        "error-store-chunk-corrupt", "Stored content failed authentication: it was altered or damaged outside UAOS.",
        "Preserve the data directory and run `uaos doctor`; report the trace.";
    STORE_KEYRING_UNAVAILABLE = Store 3, Internal, S2, retryable: true, leak: false,
        "error-store-keyring-unavailable", "The encryption keys for this pocket could not be loaded, so its content cannot be read or written.",
        "Run `uaos doctor` to check keychain access.";
    STORE_PAYLOAD_LOST = Store 4, Internal, S2, retryable: false, leak: false,
        "error-store-payload-lost", "Content a journal record refers to could not be read back after a crash or a failed flush. The record is kept and the loss is recorded as chunk.lost.",
        "The content cannot be restored. Check disk health with `uaos doctor`; the damaged files are kept in the pocket's quarantine folder.";
    STORE_PAYLOAD_FLUSH_FAILED = Store 5, Internal, S2, retryable: false, leak: false,
        "error-store-payload-flush-failed", "Making stored content durable failed. New records are refused until recovery has read the content back and recorded anything lost.",
        "Free space or fix the disk, then let UAOS recover; `uaos doctor` shows the cause.";
    POLICY_DENIED = Policy 1, Policy, Info, retryable: false, leak: false,
        "error-policy-denied", "Policy denied the operation.",
        "Run `uaos policy explain <operation>` to see the matching rules.";
    POLICY_APPROVAL_REQUIRED = Policy 2, Policy, Info, retryable: true, leak: false,
        "error-policy-approval-required", "A human must approve this operation; retry after approving.",
        "Approve with `uaos approvals` (requires user presence), then retry.";
    POLICY_EVALUATION_ERROR = Policy 3, Security, S2, retryable: false, leak: false,
        "error-policy-evaluation-error", "A policy failed to evaluate; UAOS treats evaluation errors as denial.",
        "Run `uaos policy check` to find the failing policy.";
    BUDGET_HARD_STOP = Budget 1, Budget, Info, retryable: false, leak: false,
        "error-budget-hard-stop", "The budget pool reached its hard cap; the request was stopped before being sent.",
        "Run `uaos budget explain`; raise the cap or wait for the next period.";
    BUDGET_INSUFFICIENT = Budget 2, Budget, Info, retryable: false, leak: false,
        "error-budget-insufficient", "Remaining budget cannot cover even the smallest useful response for this request.",
        "Run `uaos budget explain`; shorten the context or raise the cap.";
    BUDGET_UNKNOWN_PRICING = Budget 3, Config, S3, retryable: false, leak: false,
        "error-budget-unknown-pricing", "The model or a billing dimension has no known price, so the hard cap cannot be guaranteed.",
        "Update pricing with `uaos pricing update`, or declare a price with `uaos pricing set`.";
    BUDGET_SETTLEMENT_OVERRUN = Budget 4, Internal, S1, retryable: false, leak: false,
        "error-budget-settlement-overrun", "Actual cost exceeded the reservation; the estimator was recalibrated.",
        "Review `uaos budget explain`; report the trace if it repeats.";
    BUDGET_KEY_CONFLICT = Budget 5, User, Info, retryable: false, leak: false,
        "error-budget-key-conflict", "An idempotency key was reused for a different budget operation, or uses a reserved form.",
        "Use a fresh idempotency key; keys starting with `rsv_` or ending in `:in`, `:return`, `:reserve`, `:release`, `:settle`, `:overrun` or a `:repair_` form of the last three are reserved.";
    BUDGET_LEDGER_INCONSISTENT = Budget 6, Internal, S2, retryable: false, leak: false,
        "error-budget-ledger-inconsistent", "A budget entry does not fit the ledger's state.",
        "Run `uaos journal verify` and `uaos budget explain`; report the trace.";
    BUDGET_RECOVERY_REQUIRED = Budget 7, Internal, S3, retryable: true, leak: false,
        "error-budget-recovery-required", "The budget ledger was rebuilt and must close what the previous run left open before it accepts new work.",
        "Wait for startup recovery to finish; if it persists, run `uaos doctor`.";
    BUDGET_STREAM_OVERRUN = Budget 8, Internal, S1, retryable: false, leak: false,
        "error-budget-stream-overrun", "A response's reported usage passed its reservation mid-stream; UAOS cut the stream and stopped the kernel. The provider may have billed tokens it generated before the cut.",
        "Run `uaos budget explain` and correct the price or the clamp, then resume the kernel with `uaos resume`.";
    BUDGET_ENTRIES_UNREADABLE = Budget 9, Internal, S2, retryable: false, leak: false,
        "error-budget-entries-unreadable", "The journal holds budget entries in a record this version of UAOS cannot read.",
        "Run the newest `uaos`; do not delete or edit the journal.";
    REDACT_BLOCKED = Redact 1, Security, Info, retryable: false, leak: true,
        "error-redact-blocked", "A high-risk secret was detected in outbound content and the request was blocked.",
        "Run `uaos redact test` on the content; remove the secret or start a fresh session.";
    REDACT_DETECTOR_FAILURE = Redact 2, Security, S2, retryable: true, leak: true,
        "error-redact-detector-failure", "A detector failed; UAOS blocks rather than sending unscanned content.",
        "Retry; if it persists run `uaos doctor` and report the trace.";
    REDACT_EXPOSED_SECRET = Redact 3, Security, S2, retryable: false, leak: true,
        "error-redact-exposed-secret", "A secret was found in content that had already been sent before; it cannot be unsent.",
        "Rotate the secret now. UAOS will not retro-edit history (it would break provider signatures).";
    RUNTIME_OVERLOAD = Runtime 1, Internal, S3, retryable: true, leak: false,
        "error-runtime-overload", "UAOS is at capacity and did not admit the request; in-flight work continues.",
        "Retry after the indicated delay.";
    RUNTIME_DEADLINE = Runtime 2, Internal, S3, retryable: true, leak: false,
        "error-runtime-deadline", "The operation exceeded its deadline and was cancelled.",
        "Retry; check `uaos trace` for the slow stage.";
    RUNTIME_STOPPED = Runtime 3, Internal, S2, retryable: true, leak: false,
        "error-runtime-stopped", "The kernel is stopped: nothing new is admitted, and live streams were cut.",
        "Run `uaos status` for the reason; a human resumes the kernel with `uaos resume`.";
    RUNTIME_BOOT_RECORDS_STALE = Runtime 4, Internal, S2, retryable: false, leak: false,
        "error-runtime-boot-records-stale", "Boot was given journal records that are not the whole journal, from its first record to its head; nothing was written.",
        "Restart UAOS so boot reads the journal afresh; report the trace if it repeats.";
    RUNTIME_DRAINING = Runtime 5, Internal, S2, retryable: true, leak: false,
        "error-runtime-draining", "UAOS is shutting down cleanly and admits no new work; open work is finishing.",
        "Retry after the indicated delay, once UAOS has restarted.";
    RUNTIME_EDIT_REFUSED = Runtime 6, Internal, S2, retryable: false, leak: false,
        "error-runtime-edit-refused", "A module's planned edit of the request was refused, because it would have changed content UAOS never edits (signed, opaque, provider-produced or system content, or content redaction masked) or broken the request; nothing was sent.",
        "Report it with `uaos trace`; it indicates a module or codec defect, not a problem with your request.";
    INGRESS_UNAUTHENTICATED = Ingress 1, User, Info, retryable: false, leak: false,
        "error-ingress-unauthenticated", "The request did not carry a valid UAOS credential.",
        "Use the key printed by `uaos init`, or run the agent under `uaos run --`.";
    INGRESS_TOO_LARGE = Ingress 2, User, Info, retryable: false, leak: false,
        "error-ingress-too-large", "The request exceeds a limit: its size, nesting depth or number of values, which are configured, or the length of a key, which is fixed at 65,535 bytes. Redaction can push a request past the size or key limit, because a placeholder can be longer than the secret it replaces.",
        "Reduce the request (fewer or smaller values, shorter keys, less nesting), or raise the size, depth or value limit in the profile.";
    INGRESS_UNSUPPORTED = Ingress 3, User, Info, retryable: false, leak: false,
        "error-ingress-unsupported", "The request uses a feature the selected route cannot carry; UAOS refuses instead of silently dropping it.",
        "Choose a route that supports the feature, or remove it from the request.";
    INGRESS_MALFORMED = Ingress 4, User, Info, retryable: false, leak: false,
        "error-ingress-malformed", "The request is not JSON UAOS can read unambiguously (for example a duplicate key, trailing data or a byte-order mark), or redacting a secret inside a key would have made two keys equal, so it was not sent.",
        "Send the body as plain, well-formed JSON with each key once, and keep secrets out of object keys.";
    EGRESS_BLOCKED = Egress 1, Security, S2, retryable: false, leak: false,
        "error-egress-blocked", "The destination resolved only to private or special-purpose addresses, so UAOS did not connect.",
        "If this is a server on your own machine or network that you trust, declare it as a private upstream in the profile.";
    EGRESS_UNREACHABLE = Egress 2, Provider, S3, retryable: true, leak: false,
        "error-egress-unreachable", "The provider could not be reached: name resolution, connection or TLS failed, and nothing was sent.",
        "Check the network, then run `uaos doctor --online` and retry.";
    EGRESS_TIMEOUT = Egress 3, Provider, S3, retryable: true, leak: false,
        "error-egress-timeout", "Reaching the provider timed out (name resolution, the TLS handshake, or no connection ready in time), and nothing was sent.",
        "Retry; if it persists check the network and the provider's status page.";
    EGRESS_CIRCUIT_OPEN = Egress 4, Provider, S3, retryable: true, leak: false,
        "error-egress-circuit-open", "Recent attempts to this provider failed, so UAOS paused new attempts for a short time.",
        "Retry after the indicated delay.";
    EGRESS_REFUSED = Egress 5, Internal, S2, retryable: false, leak: false,
        "error-egress-refused", "UAOS refused to send a request that broke the egress door's rules; nothing was sent.",
        "Report this with `uaos trace`; it indicates a defect, not a problem with your request.";
    EGRESS_INTERRUPTED = Egress 6, Provider, S3, retryable: false, leak: false,
        "error-egress-interrupted", "The connection to the provider failed, or no answer came in time, after the request was sent: the provider may have received it and billed it.",
        "Check the Operation with `uaos trace` before retrying; a retry sends the request again.";
    EGRESS_UNUSABLE_RESPONSE = Egress 7, Provider, S3, retryable: false, leak: false,
        "error-egress-unusable-response", "The provider answered in a form UAOS does not pass on or could not parse (an unrequested protocol switch, a transfer coding, a malformed answer); it may have processed and billed the request.",
        "Report this with `uaos trace`; a retry sends the request again.";
    CONFIG_INVALID = Config 1, Config, S3, retryable: false, leak: false,
        "error-config-invalid", "The configuration failed validation and was not applied.",
        "The message names the key and what it expects; fix the file, then check it with `uaos config show`.";
    CONFIG_DRIFT = Config 2, Security, S3, retryable: false, leak: false,
        "error-config-drift", "The configuration file changed outside UAOS; it will not load without approval.",
        "Review the diff with `uaos profile diff` and approve it.";
    CONFIG_HOLDS_SECRET = Config 3, Config, S2, retryable: false, leak: false,
        "error-config-holds-secret", "The configuration holds what looks like a secret, so it was not loaded.",
        "Remove it, keep the key in the OS keychain (`uaos key add`), and refer to it by name.";
    CLI_USAGE = Cli 1, User, Info, retryable: false, leak: false,
        "error-cli-usage", "The command line could not be read: an unknown command or option, or a missing value.",
        "Run `uaos --help` for the commands and options.";
    CLI_DATA_DIR = Cli 2, Config, S3, retryable: false, leak: false,
        "error-cli-data-dir", "The data directory could not be found, created or read.",
        "Check the path and its permissions, or choose one with `--data-dir`.";
    CLI_DOCTOR_FAILED = Cli 3, Config, S3, retryable: false, leak: false,
        "error-cli-doctor-failed", "One or more health checks failed.",
        "Each failed check says what to fix; run `uaos doctor` again afterwards.";
    CLI_KEYCHAIN_UNAVAILABLE = Cli 4, Config, S2, retryable: false, leak: false,
        "error-cli-keychain-unavailable", "The OS keychain is not available, so UAOS cannot keep its keys.",
        "Start or unlock the system keychain (a Secret Service such as GNOME Keyring or KeePassXC on Linux, the login keychain on macOS, Credential Manager on Windows) and allow UAOS to use it, then run the command again; `uaos doctor` shows the reason.";
    CLI_KEYCHAIN_FAILED = Cli 5, Internal, S2, retryable: false, leak: false,
        "error-cli-keychain-failed", "The OS keychain returned an error UAOS did not expect.",
        "Run `uaos doctor`; if the error stays, report it with this code.";
    IDENTITY_REVOKED = Identity 1, Security, Info, retryable: false, leak: false,
        "error-identity-revoked", "The credential has been revoked.",
        "Issue a new scoped key with `uaos key issue`.";
    IDENTITY_SCOPE_EXCEEDS_PARENT = Identity 2, Security, Info, retryable: false, leak: false,
        "error-identity-scope-exceeds-parent", "A child key cannot have more scope than its parent.",
        "Narrow the requested scope.";
    IDENTITY_UNKNOWN = Identity 3, Security, Info, retryable: false, leak: true,
        "error-identity-unknown", "The presented credential is not recognised.",
        "Check the key the agent was given; issue a new one with `uaos key issue`.";
    IDENTITY_EXPIRED = Identity 4, Security, Info, retryable: false, leak: false,
        "error-identity-expired", "The credential, or one of its ancestors, has expired.",
        "Issue a new scoped key with `uaos key issue`.";
    IDENTITY_STALE_DATA_DIR = Identity 5, Security, S2, retryable: false, leak: false,
        "error-identity-stale-data-dir", "The data directory is older than the latest revocation; agent credentials are refused.",
        "A backup was probably restored. Re-issue agent keys to continue.";
    IDENTITY_DEPTH_EXCEEDED = Identity 6, User, Info, retryable: false, leak: false,
        "error-identity-depth-exceeded", "The credential hierarchy would exceed its maximum depth.",
        "Issue the key from a credential closer to the master.";
    IDENTITY_MALFORMED = Identity 7, User, Info, retryable: false, leak: true,
        "error-identity-malformed", "The presented credential is not a well-formed UAOS key.",
        "Use the key exactly as `uaos key issue` printed it.";
    IDENTITY_RECORD_TOO_LARGE = Identity 8, User, Info, retryable: false, leak: false,
        "error-identity-record-too-large", "The requested scope is too broad for one credential record.",
        "List fewer members per scope dimension; express fine-grained rules in policy instead.";
    IDENTITY_KEYS_UNAVAILABLE = Identity 9, Internal, S2, retryable: true, leak: false,
        "error-identity-keys-unavailable", "The identity key could not be read from the OS keychain.",
        "Run `uaos doctor`; unlock or grant access to the OS keychain.";
    IDENTITY_UNAVAILABLE = Identity 10, Internal, S2, retryable: false, leak: false,
        "error-identity-unavailable", "Recording an identity change failed; credentials are refused until the state is rebuilt from the journal.",
        "Restart the daemon; if it persists, run `uaos doctor` and `uaos journal verify`.";
    IDENTITY_KEY_LOST = Identity 11, Security, S2, retryable: false, leak: false,
        "error-identity-key-lost", "The identity key is missing or malformed in the OS keychain while credentials exist; every credential is refused.",
        "Restore the keychain entry if you can; otherwise re-issue every key with `uaos key issue`.";
    IDENTITY_COUNTER_INCONSISTENT = Identity 12, Security, S1, retryable: false, leak: false,
        "error-identity-counter-inconsistent", "The revocation counter in the OS keychain is behind the journal or implausible; credentials are refused.",
        "The keychain entry was deleted or altered. Run `uaos doctor`; repairing it requires an approved reset.";
    IDENTITY_INVALID_REQUEST = Identity 13, User, Info, retryable: false, leak: false,
        "error-identity-invalid-request", "The credential request is invalid.",
        "Check the parent, scope and expiry; see `uaos key --help`.";
    IDENTITY_LIMIT_REACHED = Identity 14, User, Info, retryable: false, leak: false,
        "error-identity-limit-reached", "Too many live credentials, overall or under one parent.",
        "Revoke credentials you no longer use.";
}

/// Looks up the registered specification for a code.
#[must_use]
pub fn spec(code: ErrorCode) -> Option<&'static ErrorSpec> {
    REGISTRY.iter().find(|s| s.code == code)
}

/// Schema tag of the error contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum ErrorSchema {
    /// Version 1.
    #[serde(rename = "uaos.error/1")]
    V1,
}

/// A UAOS-originated error as carried on the wire (inside the client dialect's error shape).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[schemars(
    title = "uaos.error/1",
    description = "A UAOS-originated error. Never used to rewrite upstream provider errors."
)]
pub struct UaosError {
    /// Schema tag, always `uaos.error/1`.
    pub schema: ErrorSchema,
    /// Registered code, e.g. `UAOS-BUDGET-0001`.
    pub code: String,
    /// Root-cause class.
    pub class: ErrorClass,
    /// Severity.
    pub severity: Severity,
    /// Whether retrying the same request can succeed.
    pub retryable: bool,
    /// Localization key of the user-facing message.
    pub message_key: String,
    /// Sanitized, actionable message for the agent. Never contains secrets or local paths.
    pub agent_message: String,
    /// What to do about it.
    pub remediation: String,
    /// Whether the condition implies a possible secret exposure.
    pub secret_leak_risk: bool,
    /// Correlation identifier for `uaos trace`.
    pub correlation_id: CorrelationId,
    /// Journal event that records this error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_id: Option<EventId>,
}

impl UaosError {
    /// Builds the wire error for a registered code.
    #[must_use]
    pub fn from_spec(spec: &ErrorSpec, correlation_id: CorrelationId, audit_id: Option<EventId>) -> Self {
        Self {
            schema: ErrorSchema::V1,
            code: spec.code.to_string(),
            class: spec.class,
            severity: spec.severity,
            retryable: spec.retryable,
            message_key: spec.message_key.to_owned(),
            agent_message: spec.summary.to_owned(),
            remediation: spec.remediation.to_owned(),
            secret_leak_risk: spec.secret_leak_risk,
            correlation_id,
            audit_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn codes_are_unique_and_well_formed() {
        let mut seen = BTreeSet::new();
        for s in REGISTRY {
            assert!(seen.insert(s.code), "duplicate code {}", s.code);
            let text = s.code.to_string();
            assert!(text.starts_with("UAOS-") && text.len() >= "UAOS-X-0000".len(), "{text}");
            assert!(s.message_key.starts_with("error-"), "{text}: message key");
            assert!(
                s.message_key.bytes().all(|b| b.is_ascii_lowercase() || b == b'-'),
                "{text}: message key must be a Fluent identifier"
            );
            assert!(!s.summary.is_empty() && !s.remediation.is_empty(), "{text}");
        }
    }

    #[test]
    fn numbers_are_dense_per_domain() {
        // Gaps usually mean a code was deleted; codes are retired, never reused.
        let mut by_domain: std::collections::BTreeMap<ErrorDomain, Vec<u16>> = std::collections::BTreeMap::new();
        for s in REGISTRY {
            by_domain.entry(s.code.domain).or_default().push(s.code.number);
        }
        for (domain, mut numbers) in by_domain {
            numbers.sort_unstable();
            let expected: Vec<u16> = (1..).take(numbers.len()).collect();
            assert_eq!(numbers, expected, "{domain:?}");
        }
    }

    #[test]
    fn display_format() {
        assert_eq!(codes::BUDGET_HARD_STOP.to_string(), "UAOS-BUDGET-0001");
        assert_eq!(
            spec(codes::JOURNAL_CHAIN_BROKEN).map(|s| s.severity),
            Some(Severity::S1)
        );
    }
}
