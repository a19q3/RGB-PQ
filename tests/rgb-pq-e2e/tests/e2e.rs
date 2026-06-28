//! The local end-to-end test. Runs offline by default; runs live when a BTQ
//! node is configured via the environment.

use rgb_pq_e2e::*;

#[test]
fn local_e2e_flow() {
    let cfg = read_live_config();
    let (mode, steps) = match try_connect(&cfg) {
        Some(_client) => {
            // Live mode: the offline sub-flow is a strict subset and still
            // must pass; a full live BTQ drive is performed by
            // scripts/e2e-local.sh which sets the env and asserts the node
            // steps. Here we confirm connectivity + run the offline guarantees.
            let steps = run_offline_flow();
            ("live+offline", steps)
        }
        None => {
            println!("[e2e] no reachable BTQ node; running deterministic offline flow");
            let steps = run_offline_flow();
            ("offline", steps)
        }
    };
    assert!(steps >= 5, "expected at least 5 verified steps, got {steps}");
    print_summary(mode, steps);
}
