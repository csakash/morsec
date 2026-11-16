//! Fuzz the swap planner and rewriter on raw request heads (`ms_proxy::fuzzing::head`, which
//! panics when the value lands anywhere but the bound location). Seeds: corpus/proxy-heads and
//! corpus/proxy-tunnel.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    ms_proxy::fuzzing::head(data);
});
