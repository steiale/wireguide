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

		NSDictionary *attributesToUpdate = @{
			(__bridge id)kSecValueData: data,
		};

		OSStatus status = SecItemUpdate((__bridge CFDictionaryRef)query, (__bridge CFDictionaryRef)attributesToUpdate);
		if (status == errSecItemNotFound) {
			// mutableCopy follows the Copy Rule (+1 owned reference), unlike
			// the @{} literals and factory methods above — this file is
			// compiled without ARC, so it needs an explicit release or it
			// leaks one NSMutableDictionary per first-time credential save.
			NSMutableDictionary *addQuery = [query mutableCopy];
			addQuery[(__bridge id)kSecValueData] = data;
			addQuery[(__bridge id)kSecAttrAccessible] = (__bridge id)kSecAttrAccessibleWhenUnlockedThisDeviceOnly;
			status = SecItemAdd((__bridge CFDictionaryRef)addQuery, NULL);
			if (status == errSecDuplicateItem) {
				// TOCTOU: another call created the item between our
				// SecItemUpdate (not-found) and this SecItemAdd. Retry as
				// an update now that it genuinely exists instead of
				// surfacing a spurious "duplicate item" error.
				status = SecItemUpdate((__bridge CFDictionaryRef)query, (__bridge CFDictionaryRef)attributesToUpdate);
			}
			[addQuery release];
		}
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

		NSDictionary *query = @{
			(__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
			(__bridge id)kSecAttrService: svc,
			(__bridge id)kSecAttrAccount: acct,
			(__bridge id)kSecReturnData: @YES,
			(__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitOne,
		};

		CFTypeRef result = NULL;
		OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
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
		NSDictionary *query = @{
			(__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
			(__bridge id)kSecAttrService: svc,
			(__bridge id)kSecAttrAccount: acct,
		};
		OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);
		if (status == errSecItemNotFound) {
			return 0;
		}
		return (int)status;
	}
}
