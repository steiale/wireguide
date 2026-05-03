<script>
  import { createEventDispatcher, onMount } from 'svelte';
  import { TunnelService } from '../../bindings/github.com/steiale/wireguide/internal/app';
  import { uint8ArrayToBase64 } from './encoding.js';
  import { errText } from './errors.js';

  const dispatch = createEventDispatcher();

  let scanning = true;
  let configs = [];
  let selected = new Set();
  let importing = false;
  let results = null;

  onMount(async () => {
    try {
      configs = await TunnelService.ScanForWireGuardConfigs() ?? [];
      selected = new Set(configs.map(c => c.path));
    } catch (e) {
      configs = [];
    } finally {
      scanning = false;
    }
  });

  function toggle(path) {
    const next = new Set(selected);
    if (next.has(path)) next.delete(path);
    else next.add(path);
    selected = next;
  }

  async function importSelected() {
    importing = true;
    try {
      const paths = [...selected];
      results = await TunnelService.ImportFoundConfigs(paths);
      await TunnelService.CompleteOnboarding();
      // Brief pause so user can see the results, then close
      await new Promise(r => setTimeout(r, 1200));
      dispatch('complete');
    } catch (e) {
      importing = false;
    }
  }

  async function handleFileImport(e) {
    const file = e.target.files?.[0];
    if (!file) return;
    importing = true;
    try {
      if (file.name.toLowerCase().endsWith('.zip')) {
        const buf = await file.arrayBuffer();
        // Chunked encoding — see lib/encoding.js. The naïve spread version
        // here used to blow the call stack on zips larger than ~120 KB.
        const b64 = uint8ArrayToBase64(new Uint8Array(buf));
        const res = await TunnelService.ImportZipData(b64);
        results = res ?? [];
      } else {
        const text = await file.text();
        const name = file.name.replace(/\.conf$/i, '');
        await TunnelService.ImportConfig(name, text);
        results = [{ name }];
      }
      await TunnelService.CompleteOnboarding();
      await new Promise(r => setTimeout(r, 1200));
      dispatch('complete');
    } catch (err) {
      results = [{ name: file.name, error: errText(err) }];
      importing = false;
    }
  }

  async function skip() {
    await TunnelService.CompleteOnboarding().catch(() => {});
    dispatch('complete');
  }
</script>

<div class="onboarding-backdrop">
  <div class="onboarding-card">
    <div class="onboarding-header">
      <div class="app-icon">W</div>
      <h1>Welcome to WireGuide+</h1>
      <p class="subtitle">Your WireGuard VPN manager</p>
    </div>

    {#if scanning}
      <div class="scanning-state">
        <div class="spinner"></div>
        <span>Scanning for existing configs…</span>
      </div>
    {:else if results}
      <div class="results-list">
        {#each results as r}
          <div class="result-row" class:error={r.error}>
            <span class="result-icon">{r.error ? '✗' : '✓'}</span>
            <span class="result-name">{r.name}</span>
            {#if r.error}<span class="result-error">{r.error}</span>{/if}
          </div>
        {/each}
      </div>
    {:else if configs.length === 0}
      <div class="no-configs-block">
        <p class="no-configs">No WireGuard config files found automatically.</p>
        <div class="no-configs-tip">
          <strong>Using the WireGuard app (Mac App Store)?</strong><br>
          Its configs aren't stored as files. Export them first:<br>
          Open WireGuard → <em>File → Export Tunnel(s) as Zip</em><br>
          then import the zip below.
        </div>
      </div>
    {:else}
      <p class="found-label">Found {configs.length} existing config{configs.length !== 1 ? 's' : ''}. Select which to import:</p>
      <div class="config-list">
        {#each configs as c}
          <label class="config-row">
            <input type="checkbox" checked={selected.has(c.path)} on:change={() => toggle(c.path)} />
            <span class="config-name">{c.name}</span>
            <span class="config-path">{c.path}</span>
          </label>
        {/each}
      </div>
    {/if}

    {#if !scanning && !results}
      <div class="onboarding-actions">
        {#if configs.length > 0}
          <button class="btn-primary" on:click={importSelected} disabled={importing || selected.size === 0}>
            {importing ? 'Importing…' : `Import ${selected.size} config${selected.size !== 1 ? 's' : ''}`}
          </button>
        {:else}
          <label class="btn-primary btn-import-file" class:disabled={importing}>
            <input type="file" accept=".conf,.zip" style="display:none" on:change={handleFileImport} />
            Import .conf / .zip
          </label>
        {/if}
        <button class="btn-secondary" on:click={skip} disabled={importing}>
          {configs.length === 0 ? 'Get started' : 'Skip'}
        </button>
      </div>
    {/if}
  </div>
</div>

<style>
  .onboarding-backdrop {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.7);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 9999;
  }

  .onboarding-card {
    background: var(--bg-primary);
    border: 0.5px solid var(--border);
    border-radius: var(--radius-lg, 12px);
    padding: 36px 40px;
    width: 480px;
    max-width: 90vw;
    max-height: 80vh;
    overflow-y: auto;
    display: flex;
    flex-direction: column;
    gap: 20px;
    box-shadow: var(--shadow-lg);
  }

  .onboarding-header {
    text-align: center;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 8px;
  }

  .app-icon {
    width: 56px;
    height: 56px;
    background: var(--accent);
    border-radius: 14px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 28px;
    font-weight: 700;
    color: var(--text-inverse, #fff);
    margin-bottom: 4px;
  }

  h1 {
    font-size: 20px;
    font-weight: 600;
    color: var(--text-primary);
    margin: 0;
  }

  .subtitle {
    font-size: 13px;
    color: var(--text-secondary);
    margin: 0;
  }

  .scanning-state {
    display: flex;
    align-items: center;
    gap: 10px;
    color: var(--text-secondary);
    font-size: 13px;
    justify-content: center;
    padding: 12px 0;
  }

  .spinner {
    width: 16px;
    height: 16px;
    border: 2px solid var(--border);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: spin 0.7s linear infinite;
  }

  @keyframes spin { to { transform: rotate(360deg); } }

  .found-label {
    font-size: 13px;
    color: var(--text-secondary);
    margin: 0;
  }

  .no-configs {
    font-size: 14px;
    color: var(--text-primary);
    text-align: center;
    margin: 0;
  }

  .no-configs-hint {
    font-size: 12px;
    color: var(--text-secondary);
    text-align: center;
    margin: 0;
  }

  .config-list {
    display: flex;
    flex-direction: column;
    gap: 6px;
    max-height: 240px;
    overflow-y: auto;
  }

  .config-row {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 8px 10px;
    border-radius: 6px;
    background: var(--bg-secondary);
    cursor: pointer;
    user-select: none;
  }

  .config-row:hover {
    background: var(--bg-hover, var(--bg-secondary));
  }

  .config-name {
    font-size: 13px;
    font-weight: 500;
    color: var(--text-primary);
    flex: 0 0 auto;
  }

  .config-path {
    font-size: 11px;
    color: var(--text-secondary);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    flex: 1;
    min-width: 0;
  }

  .results-list {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .result-row {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 8px 10px;
    border-radius: 6px;
    background: var(--bg-secondary);
    font-size: 13px;
  }

  .result-icon {
    color: var(--accent);
    font-weight: 700;
  }

  .result-row.error .result-icon {
    color: var(--red, #e05);
  }

  .result-name {
    color: var(--text-primary);
    font-weight: 500;
  }

  .result-error {
    color: var(--text-secondary);
    font-size: 11px;
  }

  .onboarding-actions {
    display: flex;
    gap: 10px;
    justify-content: flex-end;
    margin-top: 4px;
  }

  .btn-primary {
    padding: 8px 18px;
    background: var(--accent);
    color: var(--text-inverse, #fff);
    border: none;
    border-radius: 6px;
    font-size: 13px;
    font-weight: 500;
    cursor: pointer;
  }

  .btn-primary:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .btn-secondary {
    padding: 8px 18px;
    background: transparent;
    color: var(--text-secondary);
    border: 0.5px solid var(--border);
    border-radius: 6px;
    font-size: 13px;
    cursor: pointer;
  }

  .btn-secondary:hover:not(:disabled) {
    color: var(--text-primary);
  }

  .btn-secondary:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .no-configs-block {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .no-configs {
    font-size: 14px;
    color: var(--text-primary);
    margin: 0;
  }

  .no-configs-tip {
    font-size: 12px;
    color: var(--text-secondary);
    line-height: 1.6;
    padding: 12px 14px;
    background: var(--bg-secondary);
    border-radius: 8px;
    border-left: 3px solid var(--accent);
  }

  .no-configs-tip strong {
    color: var(--text-primary);
  }

  .no-configs-tip em {
    font-style: normal;
    font-weight: 500;
    color: var(--text-primary);
  }

  .btn-import-file {
    display: inline-flex;
    align-items: center;
    cursor: pointer;
  }

  .btn-import-file.disabled {
    opacity: 0.5;
    pointer-events: none;
  }
</style>
