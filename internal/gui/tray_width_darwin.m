#import <AppKit/AppKit.h>
#import <objc/runtime.h>

// Walk NSStatusBarWindows to find our NSStatusItem.
static NSStatusItem *findStatusItem(void) {
    Class cls = NSClassFromString(@"NSStatusBarWindow");
    if (!cls) return nil;
    for (NSWindow *win in [NSApp windows]) {
        if (![win isKindOfClass:cls]) continue;
        NSView *content = [win contentView];
        if (!content) continue;
        SEL sel = NSSelectorFromString(@"statusItem");
        id item = nil;
        if ([content respondsToSelector:sel]) {
            IMP imp = [content methodForSelector:sel];
            id (*fn)(id, SEL) = (id (*)(id, SEL))imp;
            item = fn(content, sel);
        } else {
            @try { item = [content valueForKey:@"statusItem"]; }
            @catch (__unused NSException *e) {}
        }
        if (item && [item isKindOfClass:[NSStatusItem class]])
            return (NSStatusItem *)item;
    }
    return nil;
}

// setStatusItemFixedWidth locks the NSStatusItem to a fixed pixel width so it
// never auto-resizes when the label text changes.
void setStatusItemFixedWidth(double width) {
    NSStatusItem *item = findStatusItem();
    if (item) item.length = width;
}
