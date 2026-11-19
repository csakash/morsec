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

// SAFETY: an empty extern block declares no symbols; it only links AppKit so that
// `NSPasteboard` and `NSPasteboardItem` exist for the class lookups below.
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

    fn write_item(&self, value: &str, kind: &str, markers: &[&str]) -> Result<(), String> {
        autoreleasepool(|_| {
            let pb = general()?;
            let (Some(item_cls), Some(data_cls), Some(array_cls)) = (
                AnyClass::get(c"NSPasteboardItem"),
                AnyClass::get(c"NSData"),
                AnyClass::get(c"NSArray"),
            ) else {
                return Err("AppKit's NSPasteboardItem is not available".into());
            };
            // SAFETY: `+new` on NSPasteboardItem returns an owned, empty item.
            let item: Option<Retained<AnyObject>> = unsafe { msg_send![item_cls, new] };
            let item = item.ok_or("no NSPasteboardItem")?;
            // SAFETY: `+[NSData data]` returns an empty, autoreleased NSData; objc2 retains it.
            let empty: Option<Retained<AnyObject>> = unsafe { msg_send![data_cls, data] };
            let empty = empty.ok_or("no NSData")?;
            // Every type is on the item before it reaches the pasteboard, so the text is never
            // there without its markers (review N1).
            for m in markers {
                let t = ns(m);
                // SAFETY: `setData:forType:` on a live item with a live NSData and NSString;
                // returns BOOL.
                let ok: bool = unsafe { msg_send![&*item, setData: &*empty, forType: &*t] };
                if !ok {
                    return Err(format!("the pasteboard item refused the {m} marker"));
                }
            }
            let (v, t) = (ns(value), ns(kind));
            // SAFETY: `setString:forType:` on a live item with two live NSStrings; returns BOOL.
            // The NSString holding the value is released when `v` drops, right after.
            let ok: bool = unsafe { msg_send![&*item, setString: &*v, forType: &*t] };
            drop(v);
            if !ok {
                return Err("the pasteboard item refused the text".into());
            }
            // SAFETY: `+arrayWithObject:` with a live object returns an autoreleased NSArray;
            // objc2 retains it.
            let arr: Option<Retained<AnyObject>> =
                unsafe { msg_send![array_cls, arrayWithObject: &*item] };
            let arr = arr.ok_or("no NSArray")?;
            // SAFETY: `writeObjects:` on the live pasteboard with an array of one
            // NSPasteboardItem (it conforms to NSPasteboardWriting); returns BOOL.
            let ok: bool = unsafe { msg_send![&*pb, writeObjects: &*arr] };
            if ok {
                Ok(())
            } else {
                Err("the pasteboard refused the item".into())
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
