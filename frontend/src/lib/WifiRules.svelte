<script>
  import { createEventDispatcher, onMount, onDestroy } from 'svelte';
  import { t } from '../i18n/index.js';

  export let rules = {
    enabled: false,
    default_tunnel: '',
    auto_connect_untrusted: false,
    trusted_ssids: [],
    ssid_tunnel_map: {}
  };
  export let tunnelNames = [];
  export let TunnelService = null;

  const dispatch = createEventDispatcher();
  let newTrusted = '';
  let newSSID = '';
  let newSSIDTunnel = '';
  let currentSSID = '';
  let ssidTimer = null;

  // Poll the current SSID every 10 s while the panel is mounted so the
  // "Currently on:" badge stays fresh as the user moves between networks
  // — the backend wifi.Monitor already polls every 5 s, but the GUI has
  // no event channel for it yet, so a light frontend poll is enough.
  async function refreshSSID() {
    if (!TunnelService?.GetCurrentSSID) return;
    try {
      currentSSID = await TunnelService.GetCurrentSSID();
    } catch (_) {
      currentSSID = '';
    }
  }

  onMount(() => {
    refreshSSID();
    ssidTimer = setInterval(refreshSSID, 10000);
  });

  onDestroy(() => {
    if (ssidTimer) clearInterval(ssidTimer);
  });

  function emit() {
    dispatch('change', rules);
  }

  function addTrusted() {
    const v = newTrusted.trim();
    if (!v) return;
    if (!rules.trusted_ssids.includes(v)) {
      rules.trusted_ssids = [...rules.trusted_ssids, v];
      emit();
    }
    newTrusted = '';
  }

  function removeTrusted(ssid) {
    rules.trusted_ssids = rules.trusted_ssids.filter((s) => s !== ssid);
    emit();
  }

  function addMapping() {
    const v = newSSID.trim();
    if (!v || !newSSIDTunnel) return;
    rules.ssid_tunnel_map = { ...rules.ssid_tunnel_map, [v]: newSSIDTunnel };
    emit();
    newSSID = '';
    newSSIDTunnel = '';
  }

  function removeMapping(ssid) {
    const { [ssid]: _drop, ...rest } = rules.ssid_tunnel_map;
    rules.ssid_tunnel_map = rest;
    emit();
  }

  // Helper: trust the SSID we're currently on with one click. Saves the
  // user from typing it. Hidden when already trusted or empty.
  function addCurrentToTrusted() {
    if (!currentSSID) return;
    if (!rules.trusted_ssids.includes(currentSSID)) {
      rules.trusted_ssids = [...rules.trusted_ssids, currentSSID];
      emit();
    }
  }

  $: currentTrusted = currentSSID && rules.trusted_ssids.includes(currentSSID);
</script>

<div class="wifi-rules">
  <div class="ssid-banner">
    {#if currentSSID}
      <span class="ssid-label">{$t('wifi_rules.current_ssid')}:</span>
      <span class="ssid-name" class:trusted={currentTrusted}>{currentSSID}</span>
      {#if rules.enabled && !currentTrusted}
        <button class="ssid-add-btn" on:click={addCurrentToTrusted}>+ {$t('wifi_rules.add_trusted')}</button>
      {/if}
    {:else}
      <span class="ssid-label muted">{$t('wifi_rules.no_ssid')}</span>
    {/if}
  </div>

  <div class="setting-row">
    <label for="wifi-enabled">{$t('wifi_rules.enabled')}</label>
    <input id="wifi-enabled" type="checkbox" bind:checked={rules.enabled} on:change={emit} />
  </div>
  <p class="setting-hint">{$t('wifi_rules.enabled_hint')}</p>

  {#if rules.enabled}
    <div class="setting-row">
      <label for="wifi-untrusted">{$t('wifi_rules.connect_untrusted')}</label>
      <input id="wifi-untrusted" type="checkbox" bind:checked={rules.auto_connect_untrusted} on:change={emit} />
    </div>

    <div class="setting-row">
      <label for="wifi-default">{$t('wifi_rules.default_tunnel')}</label>
      <select id="wifi-default" bind:value={rules.default_tunnel} on:change={emit}>
        <option value="">—</option>
        {#each tunnelNames as name}
          <option value={name}>{name}</option>
        {/each}
      </select>
    </div>

    <h5>{$t('wifi_rules.trusted_ssids')}</h5>
    <p class="setting-hint">{$t('wifi_rules.trusted_hint')}</p>
    <div class="list">
      {#each rules.trusted_ssids as ssid}
        <div class="list-item">
          <span class="list-item-text">{ssid}</span>
          <button class="remove" aria-label="Remove" on:click={() => removeTrusted(ssid)}>✕</button>
        </div>
      {/each}
      {#if rules.trusted_ssids.length === 0}
        <div class="list-empty">—</div>
      {/if}
    </div>
    <div class="add-row">
      <input
        placeholder={$t('wifi_rules.ssid_placeholder')}
        bind:value={newTrusted}
        on:keydown={(e) => e.key === 'Enter' && addTrusted()}
      />
      <button class="btn-add" on:click={addTrusted}>{$t('wifi_rules.add_trusted')}</button>
    </div>

    <h5>{$t('wifi_rules.ssid_tunnel_map')}</h5>
    <p class="setting-hint">{$t('wifi_rules.mapping_hint')}</p>
    <div class="list">
      {#each Object.entries(rules.ssid_tunnel_map) as [ssid, tunnel]}
        <div class="list-item">
          <span class="list-item-text">{ssid} → {tunnel}</span>
          <button class="remove" aria-label="Remove" on:click={() => removeMapping(ssid)}>✕</button>
        </div>
      {/each}
      {#if Object.keys(rules.ssid_tunnel_map).length === 0}
        <div class="list-empty">—</div>
      {/if}
    </div>
    <div class="add-row">
      <input
        placeholder={$t('wifi_rules.ssid_placeholder')}
        bind:value={newSSID}
        on:keydown={(e) => e.key === 'Enter' && addMapping()}
      />
      <select bind:value={newSSIDTunnel}>
        <option value="">{$t('wifi_rules.select_tunnel')}</option>
        {#each tunnelNames as name}
          <option value={name}>{name}</option>
        {/each}
      </select>
      <button class="btn-add" on:click={addMapping}>{$t('wifi_rules.add_mapping')}</button>
    </div>
  {/if}
</div>

<style>
  .wifi-rules {
    display: flex;
    flex-direction: column;
  }
  .ssid-banner {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 6px 10px;
    margin-bottom: 12px;
    background: var(--bg-card);
    border: 0.5px solid var(--border);
    border-radius: 6px;
    font-size: 12px;
  }
  .ssid-label {
    color: var(--text-secondary);
  }
  .ssid-label.muted {
    font-style: italic;
  }
  .ssid-name {
    font-weight: 600;
    color: var(--text-primary);
  }
  .ssid-name.trusted {
    color: var(--green, #34C759);
  }
  .ssid-add-btn {
    margin-left: auto;
    height: 22px;
    padding: 0 10px;
    border: 0;
    border-radius: 11px;
    background: var(--accent, #007AFF);
    color: var(--text-inverse, #fff);
    font: 500 11px/14px var(--font-sans, -apple-system, BlinkMacSystemFont, sans-serif);
    cursor: pointer;
  }
  .ssid-add-btn:hover { filter: brightness(1.08); }

  .setting-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 4px 0;
    min-height: 28px;
  }
  .setting-hint {
    margin: 2px 0 8px;
    padding: 0;
    font: 400 11px/14px var(--font-sans, -apple-system, BlinkMacSystemFont, sans-serif);
    color: var(--text-secondary);
    letter-spacing: 0.02em;
  }

  h5 {
    margin: 14px 0 4px;
    font: 500 10px/13px var(--font-sans, -apple-system, BlinkMacSystemFont, sans-serif);
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.06em;
  }

  .list {
    display: flex;
    flex-direction: column;
    gap: 2px;
    margin-bottom: 6px;
  }
  .list-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 4px 8px;
    background: var(--bg-card);
    border: 0.5px solid var(--border);
    border-radius: 4px;
    font-size: 13px;
  }
  .list-item-text {
    color: var(--text-primary);
    word-break: break-all;
  }
  .list-empty {
    padding: 4px 8px;
    color: var(--text-secondary);
    font-size: 12px;
    font-style: italic;
  }
  .remove {
    background: none;
    border: none;
    color: var(--text-secondary);
    cursor: pointer;
    padding: 0 4px;
    font-size: 12px;
    line-height: 1;
  }
  .remove:hover { color: var(--red, #FF3B30); }

  .add-row {
    display: flex;
    gap: 6px;
    margin-bottom: 4px;
  }
  .add-row input,
  .add-row select {
    flex: 1;
    height: 26px;
    padding: 0 8px;
    background: var(--bg-input);
    border: 0.5px solid var(--border);
    border-radius: 6px;
    color: var(--text-primary);
    font-size: 12px;
    outline: none;
  }
  .add-row input:focus,
  .add-row select:focus {
    border-color: var(--accent, #007AFF);
  }
  .add-row select { min-width: 110px; }
  .btn-add {
    height: 26px;
    padding: 0 12px;
    background: var(--accent, #007AFF);
    border: 0;
    border-radius: 13px;
    color: var(--text-inverse, #fff);
    font: 500 12px/16px var(--font-sans, -apple-system, BlinkMacSystemFont, sans-serif);
    cursor: pointer;
  }
  .btn-add:hover { filter: brightness(1.08); }
  .btn-add:active { filter: brightness(0.94); }

  input[type="checkbox"] {
    width: 16px;
    height: 16px;
    accent-color: var(--green, #34C759);
    min-width: 16px;
  }
  input[type="checkbox"]:focus,
  input[type="checkbox"]:focus-visible {
    outline: none;
    box-shadow: none;
  }

  select {
    -webkit-appearance: none;
    appearance: none;
    height: 28px;
    padding: 0 28px 0 12px;
    background-color: var(--bg-input);
    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6' viewBox='0 0 10 6'%3E%3Cpath d='M1 1l4 4 4-4' stroke='%233C3C43' stroke-opacity='.56' stroke-width='1.5' fill='none' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E");
    background-repeat: no-repeat;
    background-position: right 9px center;
    border: 1px solid rgba(60, 60, 67, 0.5);
    border-radius: 6px;
    color: var(--text-primary);
    font-size: 13px;
    cursor: pointer;
  }
  :global([data-theme="dark"]) select {
    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6' viewBox='0 0 10 6'%3E%3Cpath d='M1 1l4 4 4-4' stroke='%23FFFFFF' stroke-opacity='.55' stroke-width='1.5' fill='none' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E");
    border-color: rgba(84, 84, 88, 0.72);
  }
</style>
