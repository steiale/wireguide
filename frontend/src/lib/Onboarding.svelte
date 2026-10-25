<script>
  import { createEventDispatcher, onMount } from 'svelte';
  import { TunnelService } from '../../bindings/github.com/steiale/wireguide/internal/app';
  import { importFile, pickFile } from './importer.js';
  import { errText } from './errors.js';
  import { t } from '../i18n/index.js';

  const dispatch = createEventDispatcher();

  let scanning = true;
  let configs = [];
  let selected = new Set();
  let importing = false;
  let results = null; // [{ name, error? }] of the last import, or null
  let finishing = false;

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

  // Show the results; close on its own only when every import succeeded.
  // On any failure the list stays up with Continue / Import another file.
  async function showResults(res) {
    results = res;
    importing = false;
    if (res.length > 0 && res.every(r => !r.error)) {
      await new Promise(r => setTimeout(r, 1200));
      await finish();
    }
  }

  async function importSelected() {
    importing = true;
    let res;
    try {
      res = (await TunnelService.ImportFoundConfigs([...selected])) ?? [];
    } catch (e) {
      res = [{ name: $t('onboarding.selected_configs'), error: errText(e) }];
    }
    configs = [];
    await showResults(res);
  }

  function chooseFile() {
    pickFile('.conf,.ovpn,.zip', async (file) => {
      importing = true;
      await showResults(await importFile(file));
    });
  }

  // finish marks onboarding done (never shown again) and closes it. Always
  // reachable, whatever state the imports are in.
  async function finish() {
    if (finishing) return;
    finishing = true;
    await TunnelService.CompleteOnboarding().catch((e) => console.warn('CompleteOnboarding failed:', e));
    dispatch('complete');
  }
</script>

<div class="onboarding-backdrop">
  <div class="onboarding-card" role="dialog" aria-modal="true" aria-labelledby="onboarding-title">
    <div class="onboarding-header">
      <img src="/appicon.png" class="app-icon-img" alt="LockPlus" />
      <h1 id="onboarding-title">{$t('onboarding.title')}</h1>
      <p class="subtitle">{$t('onboarding.subtitle')}</p>
    </div>

    {#if scanning}
      <div class="scanning-state">
        <div class="spinner"></div>
        <span>{$t('onboarding.scanning')}</span>
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
        <p class="no-configs">{$t('onboarding.no_configs')}</p>
        <div class="no-configs-tip">
          <strong>{$t('onboarding.tip_title')}</strong><br>
          {$t('onboarding.tip_body')}<br>
          <em>{$t('onboarding.tip_steps')}</em><br>
          {$t('onboarding.tip_then')}
        </div>
      </div>
    {:else}
      <p class="found-label">{$t(configs.length === 1 ? 'onboarding.found_one' : 'onboarding.found_many', { count: configs.length })}</p>
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

    {#if !scanning}
      <div class="onboarding-actions">
        {#if configs.length > 0 && !results}
          <button class="btn-primary" on:click={importSelected} disabled={importing || selected.size === 0}>
            {importing ? $t('onboarding.importing') : $t('onboarding.import_selected', { count: selected.size })}
          </button>
        {:else}
          <button class="btn-primary" on:click={chooseFile} disabled={importing}>
            {importing ? $t('onboarding.importing') : results ? $t('onboarding.import_another') : $t('onboarding.import_file')}
          </button>
        {/if}
        <!-- Always available: onboarding must never trap the user. -->
        <button class="btn-secondary" on:click={finish} disabled={finishing}>
          {results ? $t('onboarding.continue') : configs.length === 0 ? $t('onboarding.get_started') : $t('onboarding.skip')}
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

  .app-icon-img {
    width: 56px;
    height: 56px;
    border-radius: 14px;
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
    word-break: break-word;
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

</style>
