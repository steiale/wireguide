//go:build darwin

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <stdlib.h>
#import <string.h>

// errSecParam (-50): "one or more parameters passed to the function were
// not valid" — a stable, public Security.framework constant, reused here
// as this file's own "bad input" return code (e.g. non-UTF8 input, alloc
// failure) so callers get a real OSStatus-shaped value instead of a crash.
static const int kBadParam = -50;

// defaultKeychainSearchList returns an array containing just the caller's
// default keychain (normally login.keychain for a GUI-process caller), or
// nil if it can't be resolved. Used as kSecMatchSearchList on read/delete
// queries so a stale item elsewhere in the keychain search list — e.g. one a
// ROOT process's SecItemAdd once defaulted into the admin-managed System
// keychain, before credential writes moved to run as the regular user (see
// keychainStoreGenericPassword's doc comment) — is treated as simply not
// present instead of requiring an OS administrator-authorization prompt just
// to notice it exists. A caller falling back to an unrestricted search on
// nil is safer than failing outright; it just means that one call reverts
// to the old (correct, just not migration-silent) behavior.
//
// SecKeychainCopyDefault is deprecated (macOS 10.10+) in favor of the
// data-protection keychain APIs — expected and left as-is here, same as
// kSecUseDataProtectionKeychain being deliberately unset above: this whole
// file targets the legacy file-based keychain on purpose, for compatibility
// with items `security`-CLI-based code already created there.
static NSArray *defaultKeychainSearchList(void) {
	SecKeychainRef defaultKeychain = NULL;
	OSStatus status = SecKeychainCopyDefault(&defaultKeychain);
	if (status != errSecSuccess || defaultKeychain == NULL) {
		return nil;
	}
	NSArray *list = @[(__bridge id)defaultKeychain];
	// NSArray's literal syntax retains its elements independent of this
	// file's ARC setting, so releasing our own Create-Rule reference here is
	// safe — the array already holds its own.
	CFRelease(defaultKeychain);
	return list;
}

// keychainStoreGenericPassword adds or updates a generic-password Keychain
// item. Returns 0 on success, or an OSStatus error code on failure.
//
// NOTE on kSecAttrAccessible below: it is only enforced on the data-
// protection keychain (opted into via kSecUseDataProtectionKeychain, which
// this code deliberately does NOT set — doing so would move reads/writes to
// a separate store from the one `security`-CLI-created items already live
// in, silently orphaning every existing user's saved credentials on
// upgrade). On the legacy file-based keychain used here, this attribute is
// accepted but not actually enforced by the OS — it does NOT deliver
// "unusable while locked" or "excluded from iCloud Keychain sync" on this
// code path. It's left in place as a declared intent / no-op-if-ignored
// rather than removed, in case a future macOS revision changes this, but
// don't rely on it for an actual security guarantee today. The real,
// delivered improvement of this rewrite over the previous `security` CLI
// subprocess approach is that the secret never appears as a subprocess
// argument (visible to `ps`/`/proc` for that process's lifetime).
int keychainStoreGenericPassword(const char *service, const char *account, const unsigned char *secret, int secretLen) {
	@autoreleasepool {
		NSString *svc = [NSString stringWithUTF8String:service];
		NSString *acct = [NSString stringWithUTF8String:account];
		if (svc == nil || acct == nil) {
			// stringWithUTF8String: returns nil on invalid UTF-8; a nil
			// value in an @{} literal below throws
			// NSInvalidArgumentException instead of returning an error —
			// a crash in a root daemon. Fail cleanly instead.
			return kBadParam;
		}
		NSData *data = [NSData dataWithBytes:secret length:(NSUInteger)secretLen];

		NSDictionary *query = @{
			(__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
			(__bridge id)kSecAttrService: svc,
			(__bridge id)kSecAttrAccount: acct,
		};

		// Delete any existing item in the DEFAULT keychain BEFORE adding,
		// rather than updating one in place if found. SecItemUpdate modifies
		// an item wherever it already lives and never relocates it — for
		// years this code (and the root helper process that used to be the
		// sole writer) could leave an item stuck in a keychain the CURRENT
		// caller doesn't actually have standing access to (e.g. an item a
		// root process's SecItemAdd defaulted into the admin-managed System
		// keychain), so every subsequent save just kept re-authorizing into
		// and updating that same wrong keychain forever instead of ever
		// migrating it. Delete (harmless no-op via errSecItemNotFound when
		// nothing exists there) + fresh Add always lands the item in the
		// CALLER's own default keychain, self-healing that kind of stale
		// placement on the very next save.
		//
		// Restricted to the default keychain (not the full search list) so
		// this never touches — and never needs to re-authorize into — a
		// stale copy sitting in the System keychain from before credential
		// writes moved to run as the regular user: that old item is simply
		// left behind as an orphan (it's already unreachable via the read
		// path below, which has the same restriction) rather than costing
		// the user one more admin prompt to migrate away.
		NSMutableDictionary *deleteQuery = [query mutableCopy];
		NSArray *searchList = defaultKeychainSearchList();
		if (searchList != nil) {
			deleteQuery[(__bridge id)kSecMatchSearchList] = searchList;
		}
		OSStatus status = SecItemDelete((__bridge CFDictionaryRef)deleteQuery);
		[deleteQuery release];
		if (status != errSecSuccess && status != errSecItemNotFound) {
			return (int)status;
		}

		NSMutableDictionary *addQuery = [query mutableCopy];
		addQuery[(__bridge id)kSecValueData] = data;
		addQuery[(__bridge id)kSecAttrAccessible] = (__bridge id)kSecAttrAccessibleWhenUnlockedThisDeviceOnly;
		status = SecItemAdd((__bridge CFDictionaryRef)addQuery, NULL);
		if (status == errSecDuplicateItem) {
			// TOCTOU: another call (or the unscoped-search-list fallback
			// above, if SecKeychainCopyDefault failed) recreated/left a
			// matching item between our delete and this add. Overwrite it in
			// place rather than surfacing a spurious "duplicate item" error.
			status = SecItemUpdate((__bridge CFDictionaryRef)query, (__bridge CFDictionaryRef)@{
				(__bridge id)kSecValueData: data,
			});
		}
		[addQuery release];
		return (int)status;
	}
}

// keychainLoadGenericPassword looks up a generic-password item. On success
// (return 0), *outData is malloc'd (caller must free() it) and *outLen is
// its length. On failure, returns an OSStatus error code without touching
// *outData/*outLen — errSecItemNotFound (-25300) means "no such item".
int keychainLoadGenericPassword(const char *service, const char *account, unsigned char **outData, int *outLen) {
	@autoreleasepool {
		NSString *svc = [NSString stringWithUTF8String:service];
		NSString *acct = [NSString stringWithUTF8String:account];
		if (svc == nil || acct == nil) {
			return kBadParam;
		}

		NSMutableDictionary *query = [@{
			(__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
			(__bridge id)kSecAttrService: svc,
			(__bridge id)kSecAttrAccount: acct,
			(__bridge id)kSecReturnData: @YES,
			(__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitOne,
		} mutableCopy];
		// Restricted to the default keychain — see
		// defaultKeychainSearchList's doc comment. Without this, a stale
		// item left in the System keychain (from before credential writes
		// moved to run as the regular user) makes EVERY connect attempt
		// trigger an OS administrator-authorization prompt just to read a
		// value this call doesn't even need to succeed at (the caller
		// treats "not found" as "show an empty field", not an error).
		NSArray *searchList = defaultKeychainSearchList();
		if (searchList != nil) {
			query[(__bridge id)kSecMatchSearchList] = searchList;
		}

		CFTypeRef result = NULL;
		OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
		[query release];
		if (status != errSecSuccess) {
			return (int)status;
		}
		// This file is compiled WITHOUT ARC (no -fobjc-arc in this cgo
		// build's flags), so __bridge_transfer would silently do nothing —
		// it only transfers ownership under ARC. SecItemCopyMatching
		// follows the Core Foundation "Create Rule": the caller owns a +1
		// reference on `result` and must release it explicitly.
		NSData *data = (__bridge NSData *)result;
		NSUInteger len = data.length;
		unsigned char *buf = malloc(len > 0 ? len : 1);
		if (buf == NULL) {
			CFRelease(result);
			return kBadParam;
		}
		if (len > 0) {
			memcpy(buf, data.bytes, len);
		}
		CFRelease(result);
		*outData = buf;
		*outLen = (int)len;
		return 0;
	}
}

// keychainDeleteGenericPassword removes a generic-password item. Returns 0
// on success, INCLUDING when the item didn't exist (matches the previous
// `security delete-generic-password` based implementation's semantics,
// which callers rely on for "delete unconditionally on tunnel removal").
int keychainDeleteGenericPassword(const char *service, const char *account) {
	@autoreleasepool {
		NSString *svc = [NSString stringWithUTF8String:service];
		NSString *acct = [NSString stringWithUTF8String:account];
		if (svc == nil || acct == nil) {
			return kBadParam;
		}
		NSMutableDictionary *query = [@{
			(__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
			(__bridge id)kSecAttrService: svc,
			(__bridge id)kSecAttrAccount: acct,
		} mutableCopy];
		// Same default-keychain restriction as the read/store paths — a
		// plain tunnel deletion or rename shouldn't cost the user an OS
		// administrator prompt just to clean up a credential that (from
		// this caller's perspective, running as the regular user) may not
		// even be reachable without one.
		NSArray *searchList = defaultKeychainSearchList();
		if (searchList != nil) {
			query[(__bridge id)kSecMatchSearchList] = searchList;
		}
		OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);
		[query release];
		if (status == errSecItemNotFound) {
			return 0;
		}
		return (int)status;
	}
}
