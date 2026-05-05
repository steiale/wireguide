#import <AppKit/AppKit.h>
#import <objc/runtime.h>

// setStatusItemFixedWidth locks our app's NSStatusItem to a fixed pixel width
// so it never auto-resizes when the label text changes. Must be called on
// the main thread after the status item is created.
//
// There is no public API to enumerate NSStatusItems. We walk all NSWindows,
// find the NSStatusBarWindow(s) (each status item has a backing window), and
// resolve the owning NSStatusItem via the window's button view ivars. This
// avoids the unrecognised-selector crash from `[NSStatusBar statusItems]`
// (a compiler-known but runtime-unimplemented selector on this macOS).
void setStatusItemFixedWidth(double width) {
    Class statusBarWindowClass = NSClassFromString(@"NSStatusBarWindow");
    if (!statusBarWindowClass) return;

    for (NSWindow *win in [NSApp windows]) {
        if (![win isKindOfClass:statusBarWindowClass]) continue;
        // The window's contentView is the NSStatusBarButton. Walk up via the
        // button's `target` (which is the NSStatusItem) when available.
        NSView *content = [win contentView];
        if (!content) continue;
        // NSStatusBarButton has a -statusItem accessor on most recent macOS
        // versions; fall back to KVC if it doesn't respond.
        SEL sel = NSSelectorFromString(@"statusItem");
        id item = nil;
        if ([content respondsToSelector:sel]) {
            IMP imp = [content methodForSelector:sel];
            id (*fn)(id, SEL) = (id (*)(id, SEL))imp;
            item = fn(content, sel);
        } else {
            @try { item = [content valueForKey:@"statusItem"]; }
            @catch (__unused NSException *e) { item = nil; }
        }
        if (!item) continue;
        if (![item isKindOfClass:[NSStatusItem class]]) continue;
        NSStatusItem *statusItem = (NSStatusItem *)item;
        statusItem.length = width;
    }
}
