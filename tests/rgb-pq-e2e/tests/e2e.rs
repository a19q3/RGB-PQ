//! The local end-to-end test. Runs offline by default; runs live when a BTQ
//! node is configured via the environment.

use rgb_pq_e2e::*;

#[test]
fn local_e2e_flow() {
    let cfg = read_live_config();
    let (mode, steps) = match try_connect(&cfg) {
        Some(mut client) => {
            // Live mode: run the real chain-level close (fund P2MR, insert
            // OP_RETURN commitment, sign via node, broadcast, mine, verify on
            // chain + inclusion proof) AND the offline guarantees.
            let live_steps = run_live_flow(&mut client);
            let offline_steps = run_offline_flow();
            ("live", live_steps + offline_steps)
        }
        None => {
            println!("[e2e] no reachable BTQ node; running deterministic offline flow");
            let steps = run_offline_flow();
            ("offline", steps)
        }
    };
    assert!(
        steps >= 5,
        "expected at least 5 verified steps, got {steps}"
    );
    print_summary(mode, steps);
}

/// Dedicated live-path test. Skips cleanly when no node is reachable. When a
/// node is present (e.g. via scripts/e2e-local.sh) it asserts the full close
/// ordering produces a chain-confirmed commitment.
#[test]
fn live_close_with_opret_commitment() {
    let cfg = read_live_config();
    let Some(mut client) = try_connect(&cfg) else {
        eprintln!("[e2e-live] skipping live close test (no BTQ node)");
        return;
    };
    let steps = run_live_flow(&mut client);
    assert!(steps >= 6, "expected >=6 live steps, got {steps}");
    println!("[e2e-live] full live close verified ({steps} steps)");
}
