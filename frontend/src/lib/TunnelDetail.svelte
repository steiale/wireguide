<script>
  import { selectedTunnel, connectionStatus, refreshTunnels, refreshStatus } from '../stores/tunnels.js';
  import { t } from '../i18n/index.js';
  import { errText } from './errors.js';
  import { createEventDispatcher, tick, onMount, onDestroy } from 'svelte';

  export let TunnelService;
  const dispatch = createEventDispatcher();

  let detail = null;
  let loading = false;
  let error = '';
  let autoReconnect = false;

  $: if ($selectedTunnel) loadDetail($selectedTunnel.name);

  // Load per-tunnel metadata (auto-reconnect flag) whenever the selection changes.
  $: if ($selectedTunnel?.name) {
    TunnelService.GetTunnelMeta($selectedTunnel.name)
      .then(m => { autoReconnect = m?.auto_reconnect ?? false; })
      .catch(() => { autoReconnect = false; });
  }

  async function toggleAutoReconnect() {
    if (!$selectedTunnel?.name) return;
    autoReconnect = !autoReconnect;
    try {
      await TunnelService.SaveTunnelMeta($selectedTunnel.name, { auto_reconnect: autoReconnect });
    } catch (e) {
      // Roll back the optimistic toggle so the UI reflects what's on disk.
      autoReconnect = !autoReconnect;
      error = errText(e);
    }
  }

  // Single source of truth for "is this tunnel currently active?" —
  // combine the selected-tunnel flag with the live connection status so the
  // UI can't show a stale "connected" chip briefly after disconnect.
  $: isConnected = $selectedTunnel?.is_connected
    && ($connectionStatus?.active_tunnels || []).includes($selectedTunnel?.name);
  $: isConnecting = !isConnected
    && $connectionStatus?.state === 'connecting'
    && $connectionStatus?.tunnel_name === $selectedTunnel?.name;
  // Prefer the explicit boolean from the backend (`has_handshake`); fall
  // back to truthiness of the `last_handshake` string for older helper
  // versions that don't yet emit the field.
  $: noHandshake = isConnected && (!(status?.has_handshake || status?.last_handshake));
  // Use the primary status if it matches the selected tunnel (has full stats).
  // Otherwise fall back to the lightweight per-tunnel info from the tunnels array
  // (name + state + handshake only, no rx/tx/duration).
  $: status = (() => {
    if ($connectionStatus?.tunnel_name === $selectedTunnel?.name) {
      return $connectionStatus;
    }
    const tunnels = $connectionStatus?.tunnels || [];
    const match = tunnels.find(t => t.tunnel_name === $selectedTunnel?.name);
    return match || $connectionStatus;
  })();

  async function loadDetail(name) {
    try {
      detail = await TunnelService.GetTunnelDetail(name);
    } catch (e) {
      detail = null;
    }
  }

  function connect() {
    dispatch('connect', {
      name: $selectedTunnel.name
    });
  }

  async function disconnect() {
    error = '';
    loading = true;
    try {
      await TunnelService.DisconnectTunnel($selectedTunnel.name);
      // Don't wait for event stream — refresh immediately.
      await refreshTunnels(TunnelService);
      await refreshStatus(TunnelService);
    } catch (e) {
      error = errText(e);
    }
    loading = false;
  }

  let showDeleteConfirm = false;
  let deleteConfirmBtn = null;

  async function askDelete() {
    if (isConnected) {
      error = $t('confirm.disconnect_first');
      return;
    }
    showDeleteConfirm = true;
    // Auto-focus the confirm button so Enter confirms, Escape cancels,
    // and a stray Space press doesn't accidentally trigger the No button.
    await tick();
    deleteConfirmBtn?.focus();
  }

  async function confirmDelete() {
    showDeleteConfirm = false;
    try {
      await TunnelService.DeleteTunnel($selectedTunnel.name);
      selectedTunnel.set(null);
      dispatch('refresh');
    } catch (e) {
      error = errText(e);
    }
  }

  function cancelDelete() {
    showDeleteConfirm = false;
  }

  // Global ESC handler — closes whichever modal is open.
  // Attached inside onMount so the listener lifetime is bound to the
  // component instance. The previous module-scope attachment leaked
  // across hot reloads in dev and registered duplicates when the
  // component remounted.
  function handleKeydown(e) {
    if (e.key !== 'Escape') return;
    if (showDeleteConfirm) cancelDelete();
    else if (renaming) cancelRename();
  }
  onMount(() => {
    window.addEventListener('keydown', handleKeydown);
  });
  onDestroy(() => {
    window.removeEventListener('keydown', handleKeydown);
  });

  function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  }

  let renaming = false;
  let renameValue = '';

  function startRename() {
    if (isConnected) {
      error = $t('confirm.disconnect_first');
      return;
    }
    renameValue = $selectedTunnel.name;
    renaming = true;
  }

  async function commitRename() {
    const oldName = $selectedTunnel.name;
    const newName = renameValue.trim();
    renaming = false;
    if (!newName || newName === oldName) return;
    try {
      await TunnelService.RenameTunnel(oldName, newName);
      selectedTunnel.set({ ...$selectedTunnel, name: newName });
      dispatch('refresh');
    } catch (e) {
      error = errText(e);
    }
  }

  function cancelRename() {
    renaming = false;
  }
</script>

<div class="detail-panel">
  {#if !$selectedTunnel}
    <div class="no-selection">
      <p>{$t('tunnel.no_tunnels')}</p>
    </div>
  {:else}
    <div class="detail-header" class:connected={isConnected}>
      {#if renaming}
        <input
          class="rename-input"
          type="text"
          bind:value={renameValue}
          on:blur={commitRename}
          on:keydown={(e) => {
            if (e.key === 'Enter') commitRename();
            if (e.key === 'Escape') cancelRename();
          }}
          autofocus
        />
      {:else}
        <h2 on:dblclick={startRename} title={$t('tunnel.rename_hint')}>{$selectedTunnel.name}</h2>
        <button class="btn-rename" on:click={startRename} title="Rename">✎</button>
      {/if}
      <span class="state-badge" class:on={isConnected && !noHandshake} class:warning={noHandshake} class:connecting={isConnecting}>
        {#if isConnected && noHandshake}
          {$t('app.no_handshake')}
        {:else if isConnected}
          {$t('app.connected')}
        {:else if isConnecting}
          {$t('app.connecting')}
        {:else}
          {$t('app.disconnected')}
        {/if}
      </span>
    </div>

    {#if isConnected && status.state === 'connected'}
      <div class="stats-grid">
        <div class="stat stat-rx">
          <span class="stat-label">↓ {$t('tunnel.rx')}</span>
          <span class="stat-value down">{formatBytes(status.rx_bytes || 0)}</span>
        </div>
        <div class="stat stat-tx">
          <span class="stat-label">↑ {$t('tunnel.tx')}</span>
          <span class="stat-value up">{formatBytes(status.tx_bytes || 0)}</span>
        </div>
        <div class="stat">
          <span class="stat-label">{$t('tunnel.handshake')}</span>
          <span class="stat-value">{status.last_handshake || '-'}</span>
        </div>
        <div class="stat">
          <span class="stat-label">{$t('tunnel.duration')}</span>
          <span class="stat-value">{status.duration || '-'}</span>
        </div>
      </div>
    {/if}

    <div class="detail-info">
      {#if detail?.interface?.address?.length}
        <div class="info-row">
          <span class="label">{$t('tunnel.address')}</span>
          <span class="value">{detail.interface.address.join(', ')}</span>
        </div>
      {/if}
      {#if detail?.interface?.dns?.length}
        <div class="info-row">
          <span class="label">DNS</span>
          <span class="value">{detail.interface.dns.join(', ')}</span>
        </div>
      {/if}
      {#if detail}
        {#each detail.peers || [] as peer, i}
          {#if peer.endpoint}
            <div class="info-row">
              <span class="label">{$t('tunnel.endpoint')}{(detail.peers.length > 1) ? ` ${i + 1}` : ''}</span>
              <span class="value">{peer.endpoint}</span>
            </div>
          {/if}
          {#if (peer.allowed_ips || []).length}
            <div class="info-row">
              <span class="label">{$t('tunnel.allowed_ips')}</span>
              <span class="value">{peer.allowed_ips.join(', ')}</span>
            </div>
          {/if}
          {#if peer.public_key}
            <div class="info-row">
              <span class="label">{$t('tunnel.public_key')}</span>
              <span class="value mono" title={peer.public_key}>{peer.public_key.substring(0, 20)}…</span>
            </div>
          {/if}
        {/each}
      {:else if $selectedTunnel.endpoint}
        <div class="info-row">
          <span class="label">{$t('tunnel.endpoint')}</span>
          <span class="value">{$selectedTunnel.endpoint}</span>
        </div>
      {/if}
      <div class="info-row">
        <span class="label">Auto-reconnect</span>
        <label class="toggle-wrap">
          <input
            type="checkbox"
            class="toggle-input"
            checked={autoReconnect}
            on:change={toggleAutoReconnect}
          />
          <span class="toggle-track">
            <span class="toggle-thumb"></span>
          </span>
          <span class="toggle-hint">{autoReconnect ? 'On wake & network change' : 'Off'}</span>
        </label>
      </div>
    </div>

    {#if error}
      <div class="error-msg">{error}</div>
    {/if}

    <div class="actions">
      {#if isConnected}
        <button class="btn btn-disconnect" on:click={disconnect} disabled={loading}>
          {$t('tunnel.disconnect')}
        </button>
      {:else}
        <button class="btn btn-connect" on:click={connect} disabled={loading}>
          {loading ? $t('app.connecting') : $t('tunnel.connect')}
        </button>
      {/if}
      <button class="btn btn-secondary" on:click={() => dispatch('edit', $selectedTunnel.name)}>
        {$t('tunnel.edit')}
      </button>
      <button class="btn btn-secondary" on:click={() => dispatch('export', $selectedTunnel.name)}>
        {$t('tunnel.export')}
      </button>
      <button class="btn btn-danger" on:click={askDelete}>
        {$t('tunnel.delete')}
      </button>
    </div>
  {/if}
</div>

{#if showDeleteConfirm}
  <div class="confirm-backdrop" on:click={cancelDelete}>
    <div class="confirm-dialog" on:click|stopPropagation>
      <h3>{$t('confirm.delete_title')}</h3>
      <p>{$t('confirm.delete_message', { name: $selectedTunnel.name })}</p>
      <div class="confirm-footer">
        <button class="btn btn-disconnect" bind:this={deleteConfirmBtn} on:click={confirmDelete}>{$t('confirm.yes')}</button>
        <button class="btn btn-secondary" on:click={cancelDelete}>{$t('confirm.no')}</button>
      </div>
    </div>
  </div>
{/if}

<style>
  /* ---------- Layout ---------- */
  .detail-panel {
    flex: 1;
    padding: var(--space-6) var(--space-6);
    padding-top: 52px; /* clears the macOS traffic-light inset */
    overflow-y: auto;
  }
  .no-selection {
    display: flex;
    align-items: center;
    justify-content: center;
    height: 100%;
    color: var(--text-muted);
    font: var(--text-body);
  }

  /* ---------- Header: title + rename + state badge ---------- */
  .detail-header {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    margin-bottom: var(--space-5);
    padding-bottom: var(--space-4);
    border-bottom: 0.5px solid var(--border);
  }
  .detail-header.connected {
    background: linear-gradient(135deg, var(--green-tint) 0%, transparent 70%);
    border: 0.5px solid color-mix(in srgb, var(--green) 25%, transparent);
    border-radius: var(--radius-md);
    padding: var(--space-4);
    margin-bottom: var(--space-5);
  }
  .detail-header h2 {
    margin: 0;
    font: var(--text-title-1);
    color: var(--text-primary);
    cursor: text;
    flex: 1;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .btn-rename {
    background: transparent;
    border: 0;
    color: var(--text-secondary);
    cursor: pointer;
    padding: var(--space-1) var(--space-2);
    border-radius: var(--radius-btn);
    font: var(--text-body);
    opacity: 0.65;
  }
  .btn-rename:hover {
    background: var(--bg-hover);
    opacity: 1;
  }
  .rename-input {
    font: var(--text-title-1);
    padding: 2px var(--space-2);
    background: var(--bg-input);
    border: 1px solid var(--accent);
    border-radius: var(--radius-sm);
    color: var(--text-primary);
    outline: none;
    flex: 1;
    max-width: 320px;
    box-shadow: 0 0 0 3px var(--blue-tint);
  }

  /* ---------- State badge (connected / connecting / disconnected) ---------- */
  .state-badge {
    padding: 4px var(--space-3);
    border-radius: var(--radius-xs);
    font: 600 11px/14px var(--font-sans);
    letter-spacing: 0.02em;
    text-transform: uppercase;
    background: var(--bg-card);
    color: var(--text-muted);
  }
  @media (prefers-reduced-motion: no-preference) {
    .state-badge {
      transition: background-color var(--dur-base) var(--ease-out),
                  color var(--dur-base) var(--ease-out);
    }
  }
  .state-badge.on {
    background: var(--green-tint);
    color: var(--green);
  }
  .state-badge.connecting {
    background: var(--yellow-tint);
    color: var(--yellow);
  }
  .state-badge.warning {
    background: var(--orange-tint, rgba(255, 149, 0, 0.12));
    color: var(--orange, #FF9500);
  }
  @media (prefers-reduced-motion: no-preference) {
    .state-badge.connecting {
      animation: pulse 1.6s ease-in-out infinite;
    }
  }
  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50%      { opacity: 0.55; }
  }

  /* ---------- Stats grid ---------- */
  .stats-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: var(--space-2);
    margin-bottom: var(--space-5);
  }
  .stat {
    background: var(--bg-card);
    border: 0.5px solid var(--border);
    border-radius: var(--radius-md);
    padding: var(--space-3);
    box-shadow: var(--shadow-xs);
  }
  .stat-rx {
    background: var(--stats-rx-fill);
    border-color: color-mix(in srgb, var(--stats-rx) 30%, transparent);
  }
  .stat-tx {
    background: var(--stats-tx-fill);
    border-color: color-mix(in srgb, var(--stats-tx) 30%, transparent);
  }
  .stat-label {
    display: block;
    font: var(--text-footnote);
    font-weight: 500;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.06em;
    margin-bottom: var(--space-1);
  }
  .stat-value {
    font: 600 18px/22px var(--font-sans);
    font-feature-settings: "tnum";   /* tabular numerals for stable alignment */
    color: var(--text-primary);
  }
  .stat-value.down { color: var(--stats-rx); }
  .stat-value.up   { color: var(--stats-tx); }

  /* ---------- Info rows ---------- */
  .detail-info {
    margin-bottom: var(--space-5);
  }
  .info-row {
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    gap: var(--space-4);
    padding: var(--space-2) 0;
    border-bottom: 0.5px solid var(--border);
    font: var(--text-body);
  }
  .info-row:last-child { border-bottom: 0; }
  .label { color: var(--text-secondary); flex-shrink: 0; }
  .value {
    color: var(--text-primary);
    text-align: right;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .value.mono {
    font-family: var(--font-mono);
    font-size: 11px;
  }

  /* ---------- Auto-reconnect toggle ---------- */
  .toggle-wrap {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    cursor: pointer;
    user-select: none;
  }
  .toggle-input {
    position: absolute;
    opacity: 0;
    pointer-events: none;
    width: 0;
    height: 0;
  }
  .toggle-track {
    width: 36px;
    height: 20px;
    border-radius: 10px;
    background: var(--border);
    position: relative;
    flex-shrink: 0;
  }
  @media (prefers-reduced-motion: no-preference) {
    .toggle-track {
      transition: background-color var(--dur-fast) var(--ease-out);
    }
    .toggle-thumb {
      transition: transform var(--dur-fast) var(--ease-out);
    }
  }
  .toggle-input:checked + .toggle-track {
    background: var(--accent);
  }
  .toggle-thumb {
    position: absolute;
    top: 2px;
    left: 2px;
    width: 16px;
    height: 16px;
    border-radius: 50%;
    background: #fff;
    box-shadow: 0 1px 2px rgba(0, 0, 0, 0.2);
  }
  .toggle-input:checked + .toggle-track .toggle-thumb {
    transform: translateX(16px);
  }
  .toggle-input:focus-visible + .toggle-track {
    outline: 2px solid var(--accent);
    outline-offset: 2px;
  }
  .toggle-hint {
    font: var(--text-footnote);
    color: var(--text-secondary);
  }

  /* ---------- Error message ---------- */
  .error-msg {
    padding: var(--space-2) var(--space-3);
    margin-bottom: var(--space-3);
    background: var(--error-bg);
    border: 0.5px solid var(--red);
    border-radius: var(--radius-sm);
    color: var(--error-text);
    font: var(--text-body);
  }

  /* ---------- Actions (button row) ---------- */
  .actions {
    display: flex;
    gap: var(--space-2);
    flex-wrap: wrap;
  }
  .btn {
    height: 28px;
    padding: 0 var(--space-3);
    border: 0;
    border-radius: var(--radius-btn);
    font: var(--text-headline);
    cursor: pointer;
    color: var(--text-primary);
    display: inline-flex;
    align-items: center;
    justify-content: center;
  }
  @media (prefers-reduced-motion: no-preference) {
    .btn {
      transition: background-color var(--dur-fast) var(--ease-out),
                  border-color var(--dur-fast) var(--ease-out),
                  filter var(--dur-fast) var(--ease-out);
    }
  }
  .btn:disabled { opacity: 0.45; cursor: not-allowed; }
  .btn-connect {
    background: var(--gradient-accent);
    color: var(--text-inverse);
  }
  .actions .btn-connect,
  .actions .btn-disconnect {
    height: 34px;
    min-width: 120px;
    font: 600 13px/18px var(--font-sans);
  }
  .btn-connect:hover:not(:disabled) { filter: brightness(1.1); }
  .btn-connect:active:not(:disabled) { filter: brightness(0.92); }
  .btn-disconnect {
    background: var(--red);
    color: var(--text-inverse);
  }
  .btn-disconnect:hover:not(:disabled) { background: color-mix(in srgb, var(--red) 84%, white); }
  .btn-disconnect:active:not(:disabled) { background: color-mix(in srgb, var(--red) 76%, black); }
  .btn-secondary {
    background: var(--bg-card);
    border: 0.5px solid var(--border);
  }
  .btn-secondary:hover { background: var(--bg-hover); }
  .btn-secondary:active { background: var(--bg-active); }
  .btn-danger {
    background: transparent;
    color: var(--red);
    border: 0.5px solid var(--red);
  }
  .btn-danger:hover { background: var(--error-bg); }

  /* ---------- Delete confirmation dialog ---------- */
  .confirm-backdrop {
    position: fixed;
    inset: 0;
    background: var(--overlay-bg);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 400;
  }
  .confirm-dialog {
    background: var(--bg-primary);
    border: 0.5px solid var(--border);
    border-radius: var(--radius-lg);
    padding: var(--space-5);
    width: 380px;
    box-shadow: var(--shadow-md);
  }
  .confirm-dialog h3 {
    margin: 0 0 var(--space-2);
    color: var(--text-primary);
    font: var(--text-title-3);
  }
  .confirm-dialog p {
    margin: 0 0 var(--space-4);
    color: var(--text-secondary);
    font: var(--text-body);
  }
  .confirm-footer {
    display: flex;
    gap: var(--space-2);
    justify-content: flex-end;
  }
</style>
