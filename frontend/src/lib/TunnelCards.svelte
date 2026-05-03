<script>
  import { createEventDispatcher, tick, onDestroy } from 'svelte';
  import { slide } from 'svelte/transition';
  import { cubicOut } from 'svelte/easing';
  import { tunnels, connectionStatus, selectedTunnel, refreshTunnels, refreshStatus } from '../stores/tunnels.js';
  import { t } from '../i18n/index.js';
  import { errText } from './errors.js';
  import StatsDashboard from './StatsDashboard.svelte';

  export let TunnelService;
  const dispatch = createEventDispatcher();

  let expandedName = null;
  let chartReadyNames = new Set(); // names where slide animation has finished
  let details = {};   // name → TunnelDetail object
  let metas = {};     // name → TunnelMeta object
  let loading = {};   // name → bool (disconnect in progress)
  let errors = {};    // name → string
  let search = '';
  let latencies = {}; // name → ms (-1 = unreachable)
  let latencyIntervals = {}; // name → intervalId

  async function pollLatency(name, endpoint) {
    if (!endpoint) return;
    try {
      const ms = await TunnelService.GetEndpointLatency(endpoint);
      latencies = { ...latencies, [name]: ms };
    } catch (e) {}
  }

  function startLatencyPolling(name, endpoint) {
    if (!endpoint || latencyIntervals[name]) return;
    pollLatency(name, endpoint);
    latencyIntervals[name] = setInterval(() => pollLatency(name, endpoint), 10000);
  }

  function stopLatencyPolling(name) {
    if (latencyIntervals[name]) {
      clearInterval(latencyIntervals[name]);
      delete latencyIntervals[name];
      latencyIntervals = latencyIntervals;
    }
  }

  onDestroy(() => {
    for (const id of Object.values(latencyIntervals)) clearInterval(id);
  });

  // Delete confirm state
  let deleteConfirmName = null;
  let deleteConfirmBtn = null;

  $: activeSet = new Set($connectionStatus?.active_tunnels || []);
  $: filtered = ($tunnels || []).filter(t =>
    t.name.toLowerCase().includes(search.toLowerCase())
  );

  // Build handshake map for dot state. Prefer the explicit `has_handshake`
  // boolean from the backend; fall back to truthiness of the formatted
  // `last_handshake` string for older helper versions.
  $: handshakeMap = (() => {
    const map = {};
    for (const ts of ($connectionStatus?.tunnels || [])) {
      map[ts.tunnel_name] = !!(ts.has_handshake || ts.last_handshake);
    }
    if ($connectionStatus?.tunnel_name) {
      map[$connectionStatus.tunnel_name] =
        !!($connectionStatus.has_handshake || $connectionStatus.last_handshake);
    }
    return map;
  })();

  function getStatus(name) {
    if ($connectionStatus?.tunnel_name === name) return $connectionStatus;
    return ($connectionStatus?.tunnels || []).find(t => t.tunnel_name === name) || null;
  }

  async function toggleExpand(name) {
    if (expandedName === name) {
      expandedName = null;
      chartReadyNames.delete(name);
      chartReadyNames = chartReadyNames;
      stopLatencyPolling(name);
      selectedTunnel.set(null);
      return;
    }
    if (expandedName) stopLatencyPolling(expandedName);
    expandedName = name;
    const tun = ($tunnels || []).find(t => t.name === name);
    if (tun?.endpoint) startLatencyPolling(name, tun.endpoint);
    if (tun) selectedTunnel.set(tun);
    // Delay chart mount until after the 180ms slide animation so the canvas
    // can read non-zero offsetWidth/offsetHeight on its first draw tick.
    setTimeout(() => {
      chartReadyNames = new Set([...chartReadyNames, name]);
    }, 220);

    if (!details[name]) {
      try {
        const d = await TunnelService.GetTunnelDetail(name);
        details = { ...details, [name]: d };
      } catch (e) {}
    }
    if (!metas[name]) {
      try {
        const m = await TunnelService.GetTunnelMeta(name);
        metas = { ...metas, [name]: m };
      } catch (e) {}
    }
  }

  async function doDisconnect(name) {
    errors = { ...errors, [name]: '' };
    loading = { ...loading, [name]: true };
    try {
      await TunnelService.DisconnectTunnel(name);
      await refreshTunnels(TunnelService);
      await refreshStatus(TunnelService);
    } catch (e) {
      errors = { ...errors, [name]: errText(e) };
    }
    loading = { ...loading, [name]: false };
  }

  async function toggleAutoReconnect(name) {
    const current = metas[name]?.auto_reconnect ?? false;
    metas = { ...metas, [name]: { ...metas[name], auto_reconnect: !current } };
    try {
      await TunnelService.SaveTunnelMeta(name, { auto_reconnect: !current });
    } catch (e) {
      metas = { ...metas, [name]: { ...metas[name], auto_reconnect: current } };
    }
  }

  async function askDelete(name) {
    if (activeSet.has(name)) {
      errors = { ...errors, [name]: 'Disconnect before deleting' };
      return;
    }
    deleteConfirmName = name;
    await tick();
    deleteConfirmBtn?.focus();
  }

  async function confirmDelete() {
    const name = deleteConfirmName;
    deleteConfirmName = null;
    try {
      await TunnelService.DeleteTunnel(name);
      if (expandedName === name) expandedName = null;
      selectedTunnel.set(null);
      dispatch('refresh');
    } catch (e) {
      errors = { ...errors, [name]: errText(e) };
    }
  }

  function formatBytes(bytes) {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  }
</script>

<div class="cards-view">
  <div class="cards-header">
    <h1 class="cards-title">{$t('tunnel.list_title')}</h1>
    <div class="header-actions">
      <button class="hdr-btn hdr-btn-primary" on:click={() => dispatch('new')}>+ {$t('tunnel.new_tunnel')}</button>
      <button class="hdr-btn hdr-btn-secondary" on:click={() => dispatch('import')}>↓ {$t('tunnel.import')}</button>
      <button class="hdr-btn hdr-btn-secondary hdr-btn-icon" on:click={() => dispatch('import-qr')} title={$t('import.qr_button')} aria-label={$t('import.qr_button')}>
        <svg width="14" height="14" viewBox="0 0 14 14" fill="currentColor" aria-hidden="true">
          <rect x="0" y="0" width="5" height="5" rx="0.5"/>
          <rect x="1.5" y="1.5" width="2" height="2" fill="var(--bg-secondary)"/>
          <rect x="9" y="0" width="5" height="5" rx="0.5"/>
          <rect x="10.5" y="1.5" width="2" height="2" fill="var(--bg-secondary)"/>
          <rect x="0" y="9" width="5" height="5" rx="0.5"/>
          <rect x="1.5" y="10.5" width="2" height="2" fill="var(--bg-secondary)"/>
          <rect x="7" y="7" width="2" height="2"/>
          <rect x="10" y="7" width="2" height="2"/>
          <rect x="7" y="10" width="2" height="2"/>
          <rect x="12" y="10" width="2" height="2"/>
        </svg>
      </button>
    </div>
  </div>

  {#if ($tunnels || []).length > 4}
    <div class="search-wrap">
      <input class="search-input" type="text" placeholder={$t('tunnel.search')} bind:value={search} />
    </div>
  {/if}

  {#if filtered.length === 0 && search === ''}
    <div class="empty-cards">
      <p class="empty-title">{$t('tunnel.no_tunnels')}</p>
      <p class="empty-hint">{$t('tunnel.drop_hint')}</p>
      <div class="empty-actions">
        <button class="hdr-btn hdr-btn-primary" on:click={() => dispatch('new')}>+ {$t('tunnel.new_tunnel')}</button>
        <button class="hdr-btn hdr-btn-secondary" on:click={() => dispatch('import')}>↓ {$t('tunnel.import')}</button>
      </div>
    </div>
  {:else}
    <div class="cards-list">
      {#each filtered as tun (tun.name)}
        {@const isConnected = activeSet.has(tun.name)}
        {@const isExpanded = expandedName === tun.name}
        {@const hasHandshake = handshakeMap[tun.name]}
        {@const status = getStatus(tun.name)}
        {@const isLoading = loading[tun.name]}
        {@const cardError = errors[tun.name]}

        <div class="tunnel-card" class:connected={isConnected} class:expanded={isExpanded}>
          <!-- Card header — always visible, click to expand -->
          <div class="card-header" on:click={() => toggleExpand(tun.name)} role="button" tabindex="0"
               on:keydown={e => e.key === 'Enter' && toggleExpand(tun.name)}>
            <span class="card-dot"
              class:dot-on={isConnected && hasHandshake}
              class:dot-warn={isConnected && !hasHandshake}></span>
            <span class="card-chevron" class:open={isExpanded}>›</span>
            <span class="card-name-wrap">
              <span class="card-name">{tun.name}</span>
              {#if tun.notes}
                <span class="card-notes">{tun.notes}</span>
              {/if}
            </span>
            <span class="card-flex"></span>
            {#if isExpanded && latencies[tun.name] !== undefined}
              {@const ms = latencies[tun.name]}
              <span class="latency-badge"
                class:lat-good={ms >= 0 && ms < 50}
                class:lat-ok={ms >= 50 && ms < 150}
                class:lat-bad={ms >= 150}
                class:lat-none={ms < 0}>
                {ms >= 0 ? ms + ' ms' : '—'}
              </span>
            {/if}
            {#if isConnected}
              <span class="card-badge">{isConnected && !hasHandshake ? $t('app.no_handshake') : $t('app.connected')}</span>
            {/if}
            <button
              class="card-btn"
              class:card-btn-connect={!isConnected}
              class:card-btn-disconnect={isConnected}
              disabled={isLoading}
              on:click|stopPropagation={() => isConnected ? doDisconnect(tun.name) : dispatch('connect', { name: tun.name })}>
              {isLoading ? $t('app.connecting') : isConnected ? $t('tunnel.disconnect') : $t('tunnel.connect')}
            </button>
          </div>

          <!-- Expanded body -->
          {#if isExpanded}
            <div class="card-body" transition:slide={{ duration: 180, easing: cubicOut }}>

              {#if cardError}
                <div class="card-error">{cardError}</div>
              {/if}

              <!-- Live stats pills (only when connected) -->
              {#if isConnected && status}
                <div class="stats-pills">
                  <span class="stat-pill pill-rx">↓ {formatBytes(status.rx_bytes || 0)}</span>
                  <span class="stat-pill pill-tx">↑ {formatBytes(status.tx_bytes || 0)}</span>
                  {#if status.duration}
                    <span class="stat-pill">⏱ {status.duration}</span>
                  {/if}
                  {#if status.last_handshake}
                    <span class="stat-pill">⇄ {status.last_handshake}</span>
                  {/if}
                </div>
                {#if chartReadyNames.has(tun.name)}
                  <div class="card-chart">
                    <StatsDashboard />
                  </div>
                {/if}
              {/if}

              <!-- Config info rows -->
              {#if details[tun.name]}
                {@const d = details[tun.name]}
                <div class="info-rows">
                  {#if d.interface?.address?.length}
                    <div class="info-row">
                      <span class="info-label">{$t('tunnel.address')}</span>
                      <span class="info-value">{d.interface.address.join(', ')}</span>
                    </div>
                  {/if}
                  {#if d.interface?.dns?.length}
                    <div class="info-row">
                      <span class="info-label">DNS</span>
                      <span class="info-value">{d.interface.dns.join(', ')}</span>
                    </div>
                  {/if}
                  {#each d.peers || [] as peer, i}
                    {#if peer.endpoint}
                      <div class="info-row">
                        <span class="info-label">{$t('tunnel.endpoint')}{d.peers.length > 1 ? ` ${i+1}` : ''}</span>
                        <span class="info-value">{peer.endpoint}</span>
                      </div>
                    {/if}
                    {#if peer.allowed_ips?.length}
                      <div class="info-row">
                        <span class="info-label">{$t('tunnel.allowed_ips')}</span>
                        <span class="info-value">{peer.allowed_ips.join(', ')}</span>
                      </div>
                    {/if}
                  {/each}
                </div>
              {/if}

              <!-- Footer: auto-reconnect + actions -->
              <div class="card-footer">
                <label class="toggle-row">
                  <input type="checkbox" class="toggle-input" checked={metas[tun.name]?.auto_reconnect ?? false}
                    on:change={() => toggleAutoReconnect(tun.name)} />
                  <span class="toggle-track"><span class="toggle-thumb"></span></span>
                  <span class="toggle-label">Auto-reconnect</span>
                </label>
                <div class="footer-actions">
                  <button class="foot-btn" on:click={() => dispatch('edit', tun.name)}>{$t('tunnel.edit')}</button>
                  <button class="foot-btn" on:click={() => dispatch('export', tun.name)}>{$t('tunnel.export')}</button>
                  <button class="foot-btn foot-btn-danger" on:click={() => askDelete(tun.name)}>{$t('tunnel.delete')}</button>
                </div>
              </div>
            </div>
          {/if}
        </div>
      {/each}
    </div>
  {/if}
</div>

<!-- Delete confirmation -->
{#if deleteConfirmName}
  <div class="confirm-backdrop" on:click={() => deleteConfirmName = null}>
    <div class="confirm-dialog" on:click|stopPropagation>
      <h3>{$t('confirm.delete_title')}</h3>
      <p>{$t('confirm.delete_message', { name: deleteConfirmName })}</p>
      <div class="confirm-footer">
        <button class="card-btn card-btn-disconnect" bind:this={deleteConfirmBtn} on:click={confirmDelete}>{$t('confirm.yes')}</button>
        <button class="foot-btn" on:click={() => deleteConfirmName = null}>{$t('confirm.no')}</button>
      </div>
    </div>
  </div>
{/if}

<style>
  /* ---------- View shell ---------- */
  .cards-view {
    flex: 1;
    padding: var(--space-6);
    padding-top: calc(52px + var(--space-5));
    overflow-y: auto;
    min-height: 0;
  }

  /* ---------- Header ---------- */
  .cards-header {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    margin-bottom: var(--space-5);
  }
  .cards-title {
    font: var(--text-title-1);
    color: var(--text-primary);
    flex: 1;
  }
  .header-actions { display: flex; gap: var(--space-2); }
  .hdr-btn {
    height: 28px;
    padding: 0 var(--space-3);
    border-radius: var(--radius-btn);
    font: var(--text-headline);
    border: 0;
    cursor: pointer;
  }
  .hdr-btn-primary { background: var(--gradient-accent); color: var(--text-inverse); }
  .hdr-btn-primary:hover { filter: brightness(1.1); }
  .hdr-btn-secondary { background: var(--bg-card); color: var(--text-primary); border: 0.5px solid var(--border); }
  .hdr-btn-secondary:hover { background: var(--bg-hover); }
  .hdr-btn-icon { width: 28px; padding: 0; display: inline-flex; align-items: center; justify-content: center; }

  /* ---------- Search ---------- */
  .search-wrap { margin-bottom: var(--space-4); }
  .search-input {
    width: 100%;
    max-width: 400px;
    height: 28px;
    padding: 0 var(--space-3);
    background: var(--bg-input);
    border: 0.5px solid var(--border);
    border-radius: var(--radius-sm);
    color: var(--text-primary);
    font: var(--text-body);
    outline: none;
    box-sizing: border-box;
  }
  .search-input:focus { border-color: var(--accent); box-shadow: 0 0 0 3px var(--blue-tint); }

  /* ---------- Empty state ---------- */
  .empty-cards {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: var(--space-12) var(--space-6);
    gap: var(--space-3);
    color: var(--text-muted);
    text-align: center;
  }
  .empty-title { font: var(--text-title-3); color: var(--text-secondary); }
  .empty-hint { font: var(--text-body); }
  .empty-actions { display: flex; gap: var(--space-2); margin-top: var(--space-2); }

  /* ---------- Cards list ---------- */
  .cards-list {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
  }

  /* ---------- Tunnel card ---------- */
  .tunnel-card {
    background: var(--bg-card);
    border: 0.5px solid var(--border);
    border-radius: var(--radius-lg);
    overflow: hidden;
    box-shadow: var(--shadow-sm);
    transition: border-color var(--dur-fast) var(--ease-out),
                box-shadow var(--dur-fast) var(--ease-out);
  }
  .tunnel-card.connected {
    border-color: color-mix(in srgb, var(--accent) 50%, transparent);
    box-shadow: 0 0 20px color-mix(in srgb, var(--accent) 15%, transparent),
                var(--shadow-sm);
  }
  .tunnel-card.expanded { box-shadow: var(--shadow-md); }

  /* Card header row */
  .card-header {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    padding: var(--space-3) var(--space-4);
    cursor: pointer;
    user-select: none;
    min-height: 44px;
  }
  .card-header:hover { background: var(--bg-hover); }

  .card-dot {
    width: 9px;
    height: 9px;
    border-radius: 50%;
    background: var(--text-muted);
    flex-shrink: 0;
    transition: background-color var(--dur-base) var(--ease-out), box-shadow var(--dur-base) var(--ease-out);
  }
  .card-dot.dot-on {
    background: var(--green);
    box-shadow: 0 0 0 2px color-mix(in srgb, var(--green) 25%, transparent);
  }
  .card-dot.dot-warn {
    background: var(--orange, #FF9F0A);
    box-shadow: 0 0 0 2px color-mix(in srgb, var(--orange, #FF9F0A) 25%, transparent);
  }

  .card-name-wrap {
    display: flex;
    flex-direction: column;
    flex: 1;
    min-width: 0;
    gap: 1px;
  }
  .card-name {
    font: 500 14px/20px var(--font-sans);
    color: var(--text-primary);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .card-notes {
    font: var(--text-footnote);
    color: var(--text-muted);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .card-flex { flex: 1; }

  /* Latency badge */
  .latency-badge {
    padding: 1px 6px;
    border-radius: 100px;
    font: 600 10px/14px var(--font-mono);
    flex-shrink: 0;
    margin-right: var(--space-1);
  }
  .lat-good  { background: var(--green-tint);  color: var(--green); }
  .lat-ok    { background: var(--yellow-tint); color: var(--yellow); }
  .lat-bad   { background: var(--error-bg);    color: var(--red); }
  .lat-none  { background: var(--bg-secondary); color: var(--text-muted); }

  .card-badge {
    padding: 2px var(--space-2);
    border-radius: var(--radius-xs);
    font: 600 10px/13px var(--font-sans);
    letter-spacing: 0.02em;
    text-transform: uppercase;
    background: var(--green-tint);
    color: var(--green);
    flex-shrink: 0;
  }

  /* Connect/Disconnect button in card header */
  .card-btn {
    height: 28px;
    padding: 0 var(--space-3);
    border: 0;
    border-radius: var(--radius-btn);
    font: var(--text-headline);
    cursor: pointer;
    flex-shrink: 0;
    transition: background-color var(--dur-fast) var(--ease-out),
                filter var(--dur-fast) var(--ease-out);
  }
  .card-btn:disabled { opacity: 0.45; cursor: not-allowed; }
  .card-btn-connect { background: var(--gradient-accent); color: var(--text-inverse); }
  .card-btn-connect:hover:not(:disabled) { filter: brightness(1.1); }
  .card-btn-connect:active:not(:disabled) { filter: brightness(0.92); }
  .card-btn-disconnect { background: var(--red); color: var(--text-inverse); }
  .card-btn-disconnect:hover:not(:disabled) { background: color-mix(in srgb, var(--red) 84%, white); }
  .card-btn-disconnect:active:not(:disabled) { background: color-mix(in srgb, var(--red) 76%, black); }

  .card-chevron {
    font-size: 18px;
    line-height: 1;
    color: var(--text-muted);
    display: inline-block;
    transform: rotate(0deg);
    transition: transform var(--dur-fast) var(--ease-out);
    flex-shrink: 0;
  }
  .card-chevron.open { transform: rotate(90deg); }

  /* ---------- Card body (expanded) ---------- */
  .card-body {
    border-top: 0.5px solid var(--border);
    padding: var(--space-4);
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
    background: var(--bg-primary);
  }
  .card-chart {
    border-radius: var(--radius-md);
    overflow: hidden;
  }

  .card-error {
    padding: var(--space-2) var(--space-3);
    background: var(--error-bg);
    border: 0.5px solid var(--red);
    border-radius: var(--radius-sm);
    color: var(--error-text);
    font: var(--text-body);
  }

  /* Stats pills */
  .stats-pills {
    display: flex;
    gap: var(--space-2);
    flex-wrap: wrap;
  }
  .stat-pill {
    padding: var(--space-1) var(--space-3);
    background: var(--bg-secondary);
    border: 0.5px solid var(--border);
    border-radius: 100px;
    font: var(--text-headline);
    color: var(--text-secondary);
    white-space: nowrap;
  }
  .pill-rx { background: var(--stats-rx-fill); border-color: color-mix(in srgb, var(--stats-rx) 30%, transparent); color: var(--stats-rx); }
  .pill-tx { background: var(--stats-tx-fill); border-color: color-mix(in srgb, var(--stats-tx) 30%, transparent); color: var(--stats-tx); }

  /* Info rows */
  .info-rows { display: flex; flex-direction: column; }
  .info-row {
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    gap: var(--space-4);
    padding: var(--space-2) 0;
    font: var(--text-body);
  }
  .info-label { color: var(--text-secondary); flex-shrink: 0; }
  .info-value { color: var(--text-primary); text-align: right; overflow: hidden; text-overflow: ellipsis; }

  /* Card footer */
  .card-footer {
    display: flex;
    align-items: center;
    gap: var(--space-4);
    padding-top: var(--space-3);
    flex-wrap: wrap;
  }

  /* Auto-reconnect toggle */
  .toggle-row {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    cursor: pointer;
    user-select: none;
  }
  .toggle-input { position: absolute; opacity: 0; pointer-events: none; width: 0; height: 0; }
  .toggle-track {
    width: 36px;
    height: 20px;
    border-radius: 10px;
    background: var(--border);
    position: relative;
    flex-shrink: 0;
    transition: background-color var(--dur-fast) var(--ease-out);
  }
  .toggle-input:checked + .toggle-track { background: var(--accent); }
  .toggle-thumb {
    position: absolute;
    top: 2px; left: 2px;
    width: 16px; height: 16px;
    border-radius: 50%;
    background: #fff;
    box-shadow: 0 1px 2px rgba(0,0,0,0.2);
    transition: transform var(--dur-fast) var(--ease-out);
  }
  .toggle-input:checked + .toggle-track .toggle-thumb { transform: translateX(16px); }
  .toggle-label { font: var(--text-body); color: var(--text-secondary); }

  /* Footer action buttons */
  .footer-actions { display: flex; gap: var(--space-2); margin-left: auto; }
  .foot-btn {
    height: 26px;
    padding: 0 var(--space-3);
    background: var(--bg-secondary);
    border: 0.5px solid var(--border);
    border-radius: var(--radius-btn);
    font: var(--text-callout);
    color: var(--text-secondary);
    cursor: pointer;
    transition: background-color var(--dur-fast) var(--ease-out), color var(--dur-fast) var(--ease-out);
  }
  .foot-btn:hover { background: var(--bg-hover); color: var(--text-primary); }
  .foot-btn-danger { color: var(--red); border-color: var(--red); background: transparent; }
  .foot-btn-danger:hover { background: var(--error-bg); }

  /* ---------- Delete confirm ---------- */
  .confirm-backdrop {
    position: fixed; inset: 0;
    background: var(--overlay-bg);
    display: flex; align-items: center; justify-content: center;
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
  .confirm-dialog h3 { margin: 0 0 var(--space-2); font: var(--text-title-3); }
  .confirm-dialog p { margin: 0 0 var(--space-4); color: var(--text-secondary); font: var(--text-body); }
  .confirm-footer { display: flex; gap: var(--space-2); justify-content: flex-end; }
</style>
