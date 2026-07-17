import { writable, derived, get } from 'svelte/store';
import en from './en.json';
import de from './de.json';
import ko from './ko.json';
import ja from './ja.json';

const translations = { en, de, ko, ja };

// `locale` is the current UI language. Components don't usually touch it
// directly — they subscribe to the `t` derived store below via `$t(...)`.
export const locale = writable('en');

export function detectLanguage() {
  const nav = navigator.language || 'en';
  const short = nav.split('-')[0];
  if (translations[short]) return short;
  return 'en';
}

export function setLanguage(lang) {
  if (translations[lang]) {
    locale.set(lang);
  }
}

export function getLanguage() {
  return get(locale);
}

// lookup walks a dotted key path through a single language's tree, returning
// the string value or undefined if any segment along the way is missing.
function lookup(tree, keys) {
  let value = tree;
  for (const k of keys) {
    if (value && typeof value === 'object') {
      value = value[k];
    } else {
      return undefined;
    }
  }
  return typeof value === 'string' ? value : undefined;
}

function translate(lang, key, params = {}) {
  const keys = key.split('.');
  // Previously a missing key in the CURRENT language returned the raw key
  // string immediately (e.g. a ko/ja user seeing "history.today" rendered
  // literally) — the app only ever fell back to English when the whole
  // language object was missing, not per-key. Falling back to English per
  // key means a future translation gap degrades to readable English instead
  // of an internal key name, matching how en.json itself is the source of
  // truth every other language is diffed against.
  const value = lookup(translations[lang] || translations.en, keys) ?? lookup(translations.en, keys) ?? key;
  return value.replace(/\{(\w+)\}/g, (_, name) => params[name] ?? `{${name}}`);
}

// `t` is a Svelte derived store that yields a translator function bound
// to the current locale. Components use it as `$t('some.key')` inside
// templates — the `$` auto-subscribes, and because the store emits a new
// closure whenever the locale changes, every `$t(...)` call re-evaluates
// automatically. This is the idiomatic Svelte i18n pattern (same as
// `svelte-i18n`), conceptually equivalent to Swift's `L.tr("key")`.
export const t = derived(locale, ($locale) => (key, params) => translate($locale, key, params));

// Non-reactive translator for plain-JS call sites (notifications, log
// formatting, etc.) that aren't tied to the Svelte render tree. Reads
// the current locale once per call. Do NOT use this inside `.svelte`
// templates — use `$t(...)` there so re-renders happen on language change.
export function tPlain(key, params = {}) {
  return translate(get(locale), key, params);
}

// Initialize with detected language
locale.set(detectLanguage());
