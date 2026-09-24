use anyhow::Result;

use crate::context::TestContext;

mod address;
mod analysis;
mod batch;
mod bridge;
mod comment;
mod data_type;
mod decompilation;
mod function;
mod global_variable;
mod help;
mod listing;
mod memory;
mod program;
mod protocol;
mod reference;
mod setup;
mod symbol;

pub use bridge::shutdown;

pub type CaseFn = fn(&mut TestContext) -> Result<()>;

/// One named test case.
pub struct Case {
    pub name: &'static str,
    /// Setup cases collect facts that later cases use. They always run.
    pub setup: bool,
    pub run: CaseFn,
}

impl Case {
    pub const fn new(name: &'static str, run: CaseFn) -> Self {
        Self {
            name,
            setup: false,
            run,
        }
    }

    pub const fn setup(name: &'static str, run: CaseFn) -> Self {
        Self {
            name,
            setup: true,
            run,
        }
    }
}

/// Returns every case in run order: setup, read-only checks, mutations, then save.
///
/// The `ghidra.bridge shutdown` case is not in this list. The runner calls it last.
pub fn all() -> Vec<Case> {
    [
        setup::cases(),
        protocol::cases(),
        help::cases(),
        bridge::cases(),
        program::cases(),
        address::cases(),
        memory::cases(),
        listing::cases(),
        global_variable::cases(),
        function::cases(),
        decompilation::cases(),
        symbol::cases(),
        reference::cases(),
        comment::cases(),
        data_type::cases(),
        batch::cases(),
        analysis::cases(),
        program::save_cases(),
    ]
    .into_iter()
    .flatten()
    .collect()
}
