import { writable, get } from 'svelte/store';
import { Events } from '@wailsio/runtime';

export const tunnels = writable([]);
export const selectedTunnel = writable(null);
export const connectionStatus = writable({ state: 'disconnected' });

const _stored = parseInt(localStorage.getItem('wg_connect_count') || '0');
export const connectCount = writable(_stored);
export const kofiDismissed = writable(localStorage.getItem('wg_kofi_dismissed') === '1');

export function dismissKofi() {
  localStorage.setItem('wg_kofi_dismissed', '1');
  kofiDismissed.set(true);
}

let statusUnsub = null;
let _prevActiveCount = 0;

// Subscribe to backend status events. The tunnel list is not event-driven
// on the backend side — it's refreshed manually via `refreshTunnels()` after
// each mutating operation (connect/disconnect/create/delete/rename).
//
// Returns true on success, false if the subscription couldn't be registered
// (e.g. the Wails runtime hasn't finished bootstrapping). The caller can
// retry; without this, a thrown error from Events.On would silently leave
// statusUnsub = null and the UI would never receive any status updates.
export function subscribeToEvents() {
  unsubscribe();

  try {
    statusUnsub = Events.On('status', (event) => {
      const status = event.data;
      connectionStatus.set(status);

      const activeCount = (status?.active_tunnels || []).length;
      if (activeCount > _prevActiveCount) {
        const next = parseInt(localStorage.getItem('wg_connect_count') || '0') + (activeCount - _prevActiveCount);
        localStorage.setItem('wg_connect_count', String(next));
        connectCount.set(next);
      }
      _prevActiveCount = activeCount;

      // Sync is_connected flag on tunnel objects. The backend now sends
      // active_tunnels (array of connected tunnel names) to support
      // multiple simultaneous tunnels.
      const activeSet = new Set(status?.active_tunnels || []);
      // Fallback for single-tunnel backward compat
      if (activeSet.size === 0 && status?.state === 'connected' && status?.tunnel_name) {
        activeSet.add(status.tunnel_name);
      }

      tunnels.update((list) => {
        let changed = false;
        const next = list.map((t) => {
          const conn = activeSet.has(t.name);
          if (t.is_connected === conn) return t;
          changed = true;
          return { ...t, is_connected: conn };
        });
        return changed ? next : list;
      });

      selectedTunnel.update((sel) => {
        if (!sel) return sel;
        const nowConnected = activeSet.has(sel.name);
        if (sel.is_connected === nowConnected) return sel;
        return { ...sel, is_connected: nowConnected };
      });
    });
    return true;
  } catch (e) {
    console.error('subscribeToEvents failed — UI will not receive live status updates:', e);
    statusUnsub = null;
    return false;
  }
}

export function unsubscribe() {
  if (statusUnsub) {
    statusUnsub();
    statusUnsub = null;
  }
}

// Initial load — one-time fetch to populate before first event arrives
export async function initialLoad(TunnelService) {
  try {
    const list = (await TunnelService.ListTunnels()) || [];
    tunnels.set(list);
    TunnelService.ResizeToFit(list.length).catch(() => {});
  } catch (e) {
    console.error('initial load failed:', e);
  }
}

// Manual refresh (after create/delete/import actions)
export async function refreshTunnels(TunnelService) {
  try {
    const list = (await TunnelService.ListTunnels()) || [];
    tunnels.set(list);
    const sel = get(selectedTunnel);
    if (sel) {
      const updated = list.find((t) => t.name === sel.name);
      if (updated) selectedTunnel.set(updated);
    }
    TunnelService.ResizeToFit(list.length).catch(() => {});
  } catch (e) {
    console.error('refresh error:', e);
  }
}

// Immediate status fetch (after Connect/Disconnect)
export async function refreshStatus(TunnelService) {
  try {
    const status = await TunnelService.GetStatus();
    if (status) connectionStatus.set(status);
  } catch (e) {
    console.error('status error:', e);
  }
}
