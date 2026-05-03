<script>
  import { onMount } from 'svelte';
  import { slide } from 'svelte/transition';
  import { TunnelService } from '../../bindings/github.com/korjwl1/wireguide/internal/app';
  import { t } from '../i18n/index.js';

  let sessions = [];
  let loading = true;
  let expandedId = null;
  let confirmingClear = false;

  onMount(async () => {
    await load();
  });

  async function load() {
    loading = true;
    try {
      sessions = (await TunnelService.GetConnectionHistory()) || [];
    } catch (e) {
      console.error('history load failed:', e);
      sessions = [];
    }
    loading = false;
  }

  async function clearAll() {
    try {
      await TunnelService.ClearConnectionHistory();
      sessions = [];
      expandedId = null;
    } catch (e) {
      console.error('history clear failed:', e);
    }
    confirmingClear = false;
  }

  // Group sessions by local-day bucket. Buckets: "Today", "Yesterday", or
  // YYYY-MM-DD. Order preserved (newest first within each bucket).
  function bucketLabel(d) {
    const now = new Date();
    const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const sd = new Date(d.getFullYear(), d.getMonth(), d.getDate());
    const diffDays = Math.round((today - sd) / 86400000);
    if (diffDays === 0) return $t('history.today');
    if (diffDays === 1) return $t('history.yesterday');
    return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
  }

  $: groups = (() => {
    const out = [];
    let cur = null;
    for (const s of sessions) {
      const start = new Date(s.start_time);
      const label = bucketLabel(start);
      if (!cur || cur.label !== label) {
        cur = { label, items: [] };
        out.push(cur);
      }
      cur.items.push(s);
    }
    return out;
  })();

  function formatTime(iso) {
    if (!iso) return '';
    const d = new Date(iso);
    if (isNaN(d.getTime())) return '';
    return d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
  }

  function formatDateTime(iso) {
    if (!iso) return '';
    const d = new Date(iso);
    if (isNaN(d.getTime())) return '';
    return d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
  }

  function formatDuration(sec) {
    if (!sec || sec < 0) return '0s';
    const s = Math.floor(sec);
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    const ss = s % 60;
    if (h > 0) return `${h}h ${m}m`;
    if (m > 0) return `${m}m ${ss}s`;
    return `${ss}s`;
  }

  function formatBytes(n) {
    if (!n || n < 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = 0;
    let v = n;
    while (v >= 1024 && i < units.length - 1) {
      v /= 1024;
      i++;
    }
    return `${v.toFixed(v >= 100 || i === 0 ? 0 : 1)} ${units[i]}`;
  }

  function reasonLabel(reason) {
    switch (reason) {
      case 'user': return $t('history.reason_user');
      case 'error': return $t('history.reason_error');
      case 'health_check': return $t('history.reason_health_check');
      case 'reconnect': return $t('history.reason_reconnect');
      case 'app_quit': return $t('history.reason_app_quit');
      default: return $t('history.reason_user');
    }
  }

  function toggle(id) {
    expandedId = expandedId === id ? null : id;
  }
</script>

<div class="history-view">
  <div class="history-header">
    <h2>{$t('history.title')}</h2>
    <div class="header-actions">
      {#if sessions.length > 0}
        <button class="btn-action" on:click={() => confirmingClear = true}>{$t('history.clear')}</button>
      {/if}
    </div>
  </div>

  {#if confirmingClear}
    <div class="confirm-backdrop" on:click={() => confirmingClear = false}>
      <div class="confirm-dialog" on:click|stopPropagation>
        <h3>{$t('history.confirm_clear_title')}</h3>
        <p>{$t('history.confirm_clear_message')}</p>
        <div class="confirm-footer">
          <button class="btn-action btn-danger" on:click={clearAll}>{$t('history.clear')}</button>
          <button class="btn-action" on:click={() => confirmingClear = false}>{$t('confirm.no')}</button>
        </div>
      </div>
    </div>
  {/if}

  <div class="history-body">
    {#if loading}
      <div class="empty"></div>
    {:else if sessions.length === 0}
      <div class="empty">{$t('history.no_history')}</div>
    {:else}
      {#each groups as group (group.label)}
        <div class="group">
          <div class="group-label">{group.label}</div>
          <div class="group-items">
            {#each group.items as s (s.id)}
              {@const active = !s.end_time}
              <div class="session-card" class:expanded={expandedId === s.id}>
                <button class="session-row" on:click={() => toggle(s.id)}>
                  <div class="row-main">
                    <span class="tunnel-name">{s.tunnel_name}</span>
                    <span class="row-time">{formatTime(s.start_time)}</span>
                  </div>
                  <div class="row-aside">
                    {#if active}
                      <span class="active-badge">
                        <span class="active-dot"></span>{$t('history.active')}
                      </span>
                    {:else}
                      <span class="duration-text">{formatDuration(s.duration_sec)}</span>
                    {/if}
                    <span class="stat-pill pill-rx">↓ {formatBytes(s.rx_bytes)}</span>
                    <span class="stat-pill pill-tx">↑ {formatBytes(s.tx_bytes)}</span>
                  </div>
                </button>
                {#if expandedId === s.id}
                  <div class="session-details" transition:slide|local={{ duration: 160 }}>
                    <div class="detail-row">
                      <span class="detail-label">{$t('tunnel.status')}</span>
                      <span class="detail-value">
                        {#if active}
                          <span class="active-dot"></span>{$t('history.active')}
                        {:else}
                          {reasonLabel(s.disconnect_reason)}
                        {/if}
                      </span>
                    </div>
                    <div class="detail-row">
                      <span class="detail-label">{$t('history.started')}</span>
                      <span class="detail-value">{formatDateTime(s.start_time)}</span>
                    </div>
                    {#if s.end_time}
                      <div class="detail-row">
                        <span class="detail-label">{$t('history.ended')}</span>
                        <span class="detail-value">{formatDateTime(s.end_time)}</span>
                      </div>
                    {/if}
                    <div class="detail-row">
                      <span class="detail-label">{$t('tunnel.duration')}</span>
                      <span class="detail-value">
                        {active ? '–' : formatDuration(s.duration_sec)}
                      </span>
                    </div>
                    <div class="detail-row">
                      <span class="detail-label">{$t('tunnel.rx')}</span>
                      <span class="detail-value">{formatBytes(s.rx_bytes)}</span>
                    </div>
                    <div class="detail-row">
                      <span class="detail-label">{$t('tunnel.tx')}</span>
                      <span class="detail-value">{formatBytes(s.tx_bytes)}</span>
                    </div>
                  </div>
                {/if}
              </div>
            {/each}
          </div>
        </div>
      {/each}
    {/if}
  </div>
</div>

<style>
  .history-view {
    display: flex;
    flex-direction: column;
    flex: 1;
    min-height: 0;
    padding-top: 52px;
  }
  .history-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: var(--space-3) var(--space-5) var(--space-3);
    flex-shrink: 0;
  }
  .history-header h2 {
    margin: 0;
    font: var(--text-title-1);
    color: var(--text-primary);
  }
  .header-actions {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    font: var(--text-footnote);
    color: var(--text-secondary);
  }

  .btn-action {
    height: 28px;
    padding: 0 var(--space-4);
    background: var(--bg-card);
    border: 0.5px solid var(--border);
    border-radius: var(--radius-btn);
    color: var(--text-secondary);
    font: var(--text-footnote);
    cursor: pointer;
    transition: background-color var(--dur-fast) var(--ease-out), color var(--dur-fast) var(--ease-out);
  }
  .btn-action:hover { background: var(--bg-hover); color: var(--text-primary); }
  .btn-danger { color: var(--red); border-color: color-mix(in srgb, var(--red) 40%, transparent); }
  .btn-danger:hover { background: color-mix(in srgb, var(--red) 12%, transparent); color: var(--red); }

  .history-body {
    flex: 1;
    min-height: 0;
    overflow-y: auto;
    padding: var(--space-3) var(--space-5) var(--space-6);
  }

  .empty {
    padding: var(--space-10) var(--space-4);
    text-align: center;
    color: var(--text-muted);
    font: var(--text-body);
  }

  .group { margin-bottom: var(--space-5); }
  .group-label {
    font: var(--text-footnote);
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: var(--text-secondary);
    margin: var(--space-2) var(--space-1);
  }
  .group-items {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
  }

  .session-card {
    background: var(--bg-card);
    border: 0.5px solid var(--border);
    border-radius: var(--radius-lg);
    overflow: hidden;
    transition: background-color var(--dur-fast) var(--ease-out), border-color var(--dur-fast) var(--ease-out);
  }
  .session-card.expanded { border-color: color-mix(in srgb, var(--accent) 40%, var(--border)); }

  .session-row {
    width: 100%;
    background: transparent;
    border: 0;
    color: var(--text-primary);
    padding: var(--space-3) var(--space-4);
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-3);
    cursor: pointer;
    text-align: left;
  }
  .session-row:hover { background: var(--bg-hover); }
  .row-main {
    display: flex;
    align-items: baseline;
    gap: var(--space-3);
    min-width: 0;
    flex: 1;
  }
  .tunnel-name {
    font: var(--text-headline);
    color: var(--text-primary);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .row-time {
    font: var(--text-footnote);
    color: var(--text-secondary);
    font-variant-numeric: tabular-nums;
  }
  .row-aside {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    flex-shrink: 0;
  }
  .duration-text {
    font: var(--text-footnote);
    color: var(--text-secondary);
    font-variant-numeric: tabular-nums;
  }
  .active-badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    color: var(--green);
    font: var(--text-footnote);
    font-weight: 600;
  }
  .active-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--green);
    box-shadow: 0 0 0 0 color-mix(in srgb, var(--green) 60%, transparent);
    animation: pulse-dot 1.6s ease-out infinite;
  }
  @keyframes pulse-dot {
    0%   { box-shadow: 0 0 0 0 color-mix(in srgb, var(--green) 60%, transparent); }
    70%  { box-shadow: 0 0 0 6px color-mix(in srgb, var(--green) 0%, transparent); }
    100% { box-shadow: 0 0 0 0 color-mix(in srgb, var(--green) 0%, transparent); }
  }
  @media (prefers-reduced-motion: reduce) {
    .active-dot { animation: none; }
  }

  .stat-pill {
    padding: 1px var(--space-2);
    background: var(--bg-secondary);
    border: 0.5px solid var(--border);
    border-radius: 100px;
    font: var(--text-footnote);
    color: var(--text-secondary);
    white-space: nowrap;
    font-variant-numeric: tabular-nums;
  }
  .pill-rx { background: var(--stats-rx-fill); border-color: color-mix(in srgb, var(--stats-rx) 30%, transparent); color: var(--stats-rx); }
  .pill-tx { background: var(--stats-tx-fill); border-color: color-mix(in srgb, var(--stats-tx) 30%, transparent); color: var(--stats-tx); }

  .session-details {
    border-top: 0.5px solid var(--border);
    padding: var(--space-3) var(--space-4);
    background: var(--bg-primary);
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
  }
  .detail-row {
    display: flex;
    justify-content: space-between;
    gap: var(--space-3);
    font: var(--text-body);
  }
  .detail-label {
    color: var(--text-secondary);
    font: var(--text-subheadline);
  }
  .detail-value {
    color: var(--text-primary);
    text-align: right;
    font-variant-numeric: tabular-nums;
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }

  .confirm-backdrop {
    position: absolute;
    inset: 0;
    background: rgba(0, 0, 0, 0.5);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 10;
    backdrop-filter: blur(2px);
  }
  .confirm-dialog {
    background: var(--bg-card);
    border: 0.5px solid var(--border);
    border-radius: var(--radius-lg);
    padding: var(--space-5);
    width: 320px;
    box-shadow: 0 8px 32px rgba(0,0,0,0.4);
  }
  .confirm-dialog h3 { margin: 0 0 var(--space-2); font: var(--text-title-3); color: var(--text-primary); }
  .confirm-dialog p { margin: 0 0 var(--space-4); color: var(--text-secondary); font: var(--text-body); line-height: 1.5; }
  .confirm-footer { display: flex; gap: var(--space-2); justify-content: flex-end; }
</style>
