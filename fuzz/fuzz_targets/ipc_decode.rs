//! Fuzz IPC message decoding: `decode` never panics, and whatever it accepts re-encodes to a
//! message that decodes to the same thing. Seeds: corpus/ipc-messages.
#![no_main]

use libfuzzer_sys::fuzz_target;
use ms_ipc::protocol::{decode, encode};
use ms_ipc::{RequestBody, ResponseBody};

fuzz_target!(|data: &[u8]| {
    if let Ok(env) = decode::<RequestBody>(data) {
        let again = encode(env.id, &env.body).unwrap();
        assert_eq!(decode::<RequestBody>(&again).unwrap(), env);
    }
    if let Ok(env) = decode::<ResponseBody>(data) {
        let again = encode(env.id, &env.body).unwrap();
        assert_eq!(decode::<ResponseBody>(&again).unwrap(), env);
    }
});
