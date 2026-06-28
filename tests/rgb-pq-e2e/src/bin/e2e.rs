//! Binary entry point for `cargo run -p rgb-pq-e2e` (used by
//! scripts/e2e-local.sh).

fn main() {
    let cfg = rgb_pq_e2e::read_live_config();
    let (mode, steps) = match rgb_pq_e2e::try_connect(&cfg) {
        Some(_client) => ("live+offline", rgb_pq_e2e::run_offline_flow()),
        None => {
            eprintln!("[e2e] no reachable BTQ node; running deterministic offline flow");
            ("offline", rgb_pq_e2e::run_offline_flow())
        }
    };
    rgb_pq_e2e::print_summary(mode, steps);
    if steps < 5 {
        std::process::exit(1);
    }
}
