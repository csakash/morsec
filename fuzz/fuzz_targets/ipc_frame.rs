//! Fuzz IPC framing: `read_frame` over arbitrary bytes never panics and agrees with the framing
//! rules (4-byte big-endian length, 1..=1 MiB, no truncation). Seeds: corpus/ipc-frames.
#![no_main]

use libfuzzer_sys::fuzz_target;
use ms_ipc::MAX_FRAME;
use ms_ipc::frame::read_frame;

fuzz_target!(|data: &[u8]| {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    rt.block_on(async {
        let mut r = data;
        let mut rest = data;
        loop {
            let got = read_frame(&mut r).await;
            if rest.is_empty() {
                assert!(matches!(got, Ok(None)));
                return;
            }
            let ok = rest.len() >= 4 && {
                let len = u32::from_be_bytes(rest[..4].try_into().unwrap()) as usize;
                len != 0 && len <= MAX_FRAME && rest.len() - 4 >= len
            };
            if !ok {
                assert!(got.is_err());
                return;
            }
            let len = u32::from_be_bytes(rest[..4].try_into().unwrap()) as usize;
            assert_eq!(got.unwrap().unwrap(), &rest[4..4 + len]);
            rest = &rest[4 + len..];
        }
    });
});
