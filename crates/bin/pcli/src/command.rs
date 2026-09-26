pub use debug::DebugCmd;
pub use init::InitCmd;
pub use migrate::MigrateCmd;
pub use query::QueryCmd;
pub use threshold::ThresholdCmd;
pub use tx::TxCmd;
pub use validator::ValidatorCmd;
pub use view::ViewCmd;

use self::tx::TxCmdWithOptions;

mod debug;
mod init;
mod migrate;
mod query;
mod threshold;
mod tx;
mod utils;
mod validator;
mod view;

// Note on display_order:
//
// The value is between 0 and 999 (the default).  Sorting of subcommands is done
// by display_order first, and then alphabetically.  We should not try to order
// every set of subcommands -- for instance, it doesn't make sense to try to
// impose a non-alphabetical ordering on the query subcommands -- but we can use
// the order to group related commands.
//
// Setting spaced numbers is future-proofing, letting us insert other commands
// without noisy renumberings.
//
// https://docs.rs/clap/latest/clap/builder/struct.App.html#method.display_order
#[derive(Debug, clap::Subcommand)]
#[allow(clippy::large_enum_variant)]
pub enum Command {
    /// Initialize `pcli` with a new wallet, or reset it.
    ///
    /// This command requires selecting a custody backend.  The `SoftKMS`
    /// backend is a good default choice.  More backends (e.g., threshold
    /// custody, hardware wallets) may be added in the future.
    #[clap(display_order = 100)]
    Init(InitCmd),
    /// Query the public chain state, like the validator set.
    ///
    /// This command has two modes: it can be used to query raw bytes of
    /// arbitrary keys with the `key` subcommand, or it can be used to query
    /// typed data with a subcommand for a particular component.
    #[clap(subcommand, display_order = 200, visible_alias = "q")]
    Query(QueryCmd),
    /// View your private chain state, like account balances.
    #[clap(subcommand, display_order = 300, visible_alias = "v")]
    View(ViewCmd),
    /// Create and broadcast a transaction.
    #[clap(display_order = 400, visible_alias = "tx")]
    Transaction(TxCmdWithOptions),
    /// Follow the threshold signing protocol.
    #[clap(subcommand, display_order = 500)]
    Threshold(ThresholdCmd),
    /// Migrate your balance to another wallet.
    #[clap(subcommand, display_order = 600)]
    Migrate(MigrateCmd),
    /// Manage a validator.
    #[clap(subcommand, display_order = 900)]
    Validator(ValidatorCmd),
    /// Display information related to diagnosing problems running Penumbra
    #[clap(subcommand, display_order = 999)]
    Debug(DebugCmd),
}

impl Command {
    /// The command as a caller would type it, for diagnostics.
    pub fn path(&self) -> &'static str {
        match self {
            Command::Init(_) => "init",
            Command::Query(QueryCmd::Tx(_)) => "q tx",
            Command::Query(_) => "q <subcommand>",
            Command::View(v) => match v {
                ViewCmd::Address(_) => "v address",
                ViewCmd::Balance(_) => "v balance",
                ViewCmd::Auction(_) => "v auction",
                ViewCmd::WalletId(_) => "v wallet-id",
                ViewCmd::Tx(_) => "v tx",
                ViewCmd::ListTransactionHashes(_) => "v transaction-hashes",
                ViewCmd::Sync => "v sync",
                ViewCmd::Reset(_) => "v reset",
                ViewCmd::NobleAddress(_) => "v noble-address",
                ViewCmd::Staked(_) => "v staked",
                ViewCmd::LiquidityPositions(_) => "v lps",
            },
            Command::Transaction(_) => "tx",
            Command::Threshold(_) => "threshold",
            Command::Migrate(_) => "migrate",
            Command::Validator(_) => "validator",
            Command::Debug(_) => "debug",
        }
    }

    /// Reject an output format this command cannot honour.
    ///
    /// Deny by default, and check it before any work happens. A `--output
    /// json` that quietly prints the human table is worse than an error: the
    /// caller parses prose believing it is JSON — and gets amounts carrying
    /// display-unit suffixes (`1.727mpenumbra`) where it expected integers.
    /// A command is listed here when it actually writes the format.
    ///
    /// `v sync`, `v reset` and the `tx` subcommands that only print a plan or
    /// a prompt have no JSON form yet, and say so instead of pretending.
    pub fn check_output(&self, fmt: Option<crate::opt::OutputFormat>) -> anyhow::Result<()> {
        let Some(fmt) = fmt else { return Ok(()) };
        let supported = matches!(
            (self, fmt),
            (
                Command::Query(QueryCmd::Tx(_)),
                crate::opt::OutputFormat::Json | crate::opt::OutputFormat::Base64
            ) | (
                Command::View(
                    ViewCmd::Balance(_)
                        | ViewCmd::Address(_)
                        | ViewCmd::Auction(_)
                        | ViewCmd::WalletId(_)
                        | ViewCmd::Tx(_)
                        | ViewCmd::ListTransactionHashes(_)
                        | ViewCmd::NobleAddress(_)
                        | ViewCmd::Staked(_)
                        | ViewCmd::LiquidityPositions(_)
                ),
                crate::opt::OutputFormat::Json
            ) | (Command::Transaction(_), crate::opt::OutputFormat::Json)
        );
        if supported {
            return Ok(());
        }
        anyhow::bail!(
            "pcli {} does not support --output {}",
            self.path(),
            match fmt {
                crate::opt::OutputFormat::Text => "text",
                crate::opt::OutputFormat::Json => "json",
                crate::opt::OutputFormat::Base64 => "base64",
            }
        )
    }

    /// Determine if this command can run in "offline" mode.
    pub fn offline(&self) -> bool {
        match self {
            Command::Init(_) => true,
            Command::Transaction(cmd) => cmd.offline(),
            Command::View(cmd) => cmd.offline(),
            Command::Validator(cmd) => cmd.offline(),
            Command::Query(cmd) => cmd.offline(),
            Command::Debug(cmd) => cmd.offline(),
            Command::Threshold(cmd) => cmd.offline(),
            Command::Migrate(_) => false,
        }
    }
}
