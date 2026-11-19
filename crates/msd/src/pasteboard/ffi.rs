//! The macOS pasteboard through the Objective-C runtime (L33 SPEC D-20). FFI only: the logic
//! (markers, the 30 s clear) is in `pasteboard.rs`. `NSPasteboard` is looked up by class name
//! with AppKit linked here, so no new crate: `objc2` 0.6 and `objc2-foundation` 0.3 are already
//! locked (through ms-approve's Touch ID).
#![allow(unsafe_code)]

use objc2::msg_send;
use objc2::rc::{Retained, autoreleasepool};
use objc2::runtime::{AnyClass, AnyObject};
use objc2_foundation::NSString;

use super::PasteboardApi;

#[link(name = "AppKit", kind = "framework")]
unsafe extern "C" {}

/// `NSPasteboardContentsCurrentHostOnly`: the contents stay on this Mac (no Universal
/// Clipboard).
const CURRENT_HOST_ONLY: usize = 1;

/// `+[NSPasteboard generalPasteboard]`.
#[derive(Debug, Default, Clone, Copy)]
pub struct General;

fn general() -> Result<Retained<AnyObject>, String> {
    let Some(cls) = AnyClass::get(c"NSPasteboard") else {
        return Err("AppKit's NSPasteboard is not available".into());
    };
    // SAFETY: `generalPasteboard` is a class method with no arguments that returns the shared
    // pasteboard (or nil without a pasteboard server); objc2 retains the autoreleased result.
    let pb: Option<Retained<AnyObject>> = unsafe { msg_send![cls, generalPasteboard] };
    pb.ok_or_else(|| "no pasteboard (msd has no GUI session)".into())
}

fn ns(s: &str) -> Retained<NSString> {
    NSString::from_str(s)
}

impl PasteboardApi for General {
    fn prepare_current_host_only(&self) -> Result<(), String> {
        autoreleasepool(|_| {
            let pb = general()?;
            // SAFETY: `prepareForNewContentsWithOptions:` (macOS 10.12+) takes an NSUInteger
            // option mask and returns the new change count; `pb` is a live NSPasteboard.
            let _: isize =
                unsafe { msg_send![&*pb, prepareForNewContentsWithOptions: CURRENT_HOST_ONLY] };
            Ok(())
        })
    }

    fn clear_contents(&self) -> Result<(), String> {
        autoreleasepool(|_| {
            let pb = general()?;
            // SAFETY: `clearContents` takes no arguments and returns the new change count.
            let _: isize = unsafe { msg_send![&*pb, clearContents] };
            Ok(())
        })
    }

    fn set_string(&self, value: &str, kind: &str) -> Result<(), String> {
        autoreleasepool(|_| {
            let pb = general()?;
            let (v, t) = (ns(value), ns(kind));
            // SAFETY: `setString:forType:` takes two live NSStrings and returns BOOL. The
            // NSString holding the value is released when `v` drops, right after.
            let ok: bool = unsafe { msg_send![&*pb, setString: &*v, forType: &*t] };
            drop(v);
            if ok {
                Ok(())
            } else {
                Err("the pasteboard refused the text".into())
            }
        })
    }

    fn set_empty_data(&self, kind: &str) -> Result<(), String> {
        autoreleasepool(|_| {
            let pb = general()?;
            let Some(cls) = AnyClass::get(c"NSData") else {
                return Err("NSData is not available".into());
            };
            // SAFETY: `+[NSData data]` returns an empty, autoreleased NSData; objc2 retains it.
            let data: Option<Retained<AnyObject>> = unsafe { msg_send![cls, data] };
            let data = data.ok_or("no NSData")?;
            let t = ns(kind);
            // SAFETY: `setData:forType:` takes a live NSData and NSString and returns BOOL.
            let ok: bool = unsafe { msg_send![&*pb, setData: &*data, forType: &*t] };
            if ok {
                Ok(())
            } else {
                Err(format!("the pasteboard refused the {kind} marker"))
            }
        })
    }

    fn change_count(&self) -> Result<i64, String> {
        autoreleasepool(|_| {
            let pb = general()?;
            // SAFETY: `changeCount` takes no arguments and returns an NSInteger.
            let n: isize = unsafe { msg_send![&*pb, changeCount] };
            Ok(n as i64)
        })
    }
}
