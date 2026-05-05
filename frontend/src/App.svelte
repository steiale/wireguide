<script>
  import { onMount, onDestroy } from 'svelte';
  import { Events } from '@wailsio/runtime';
  import TunnelCards from './lib/TunnelCards.svelte';
  import KofiBanner from './lib/KofiBanner.svelte';
  import ConflictWarning from './lib/ConflictWarning.svelte';
  import ConfigEditor from './lib/ConfigEditor.svelte';
  import Settings from './lib/Settings.svelte';
  import LogViewer from './lib/LogViewer.svelte';
  import History from './lib/History.svelte';
  import DNSLeakTest from './lib/DNSLeakTest.svelte';
  import RouteVisualization from './lib/RouteVisualization.svelte';
  import UpdateNotice from './lib/UpdateNotice.svelte';
  import Onboarding from './lib/Onboarding.svelte';
  import { tunnels, selectedTunnel, refreshTunnels, refreshStatus, subscribeToEvents, unsubscribe, initialLoad, connectionStatus } from './stores/tunnels.js';
  import { applyTheme, initThemeWatcher } from './stores/theme.js';
  import { startLogListener, stopLogListener } from './stores/logs.js';
  import { errText } from './lib/errors.js';
  import { uint8ArrayToBase64 } from './lib/encoding.js';
  import { t, setLanguage, detectLanguage } from './i18n/index.js';
  import { TunnelService } from '../bindings/github.com/steiale/wireguide/internal/app';

  // View state
  let currentView = 'tunnels'; // 'tunnels' | 'dnsleak' | 'routes' | 'logs' | 'history'

  $: isToolsView = currentView === 'dnsleak' || currentView === 'routes';
  $: isTunnelsView = currentView === 'tunnels';

  // Modal state
  let showEditor = false;
  let showSettings = false;
  let showConflictWarning = false;
  let showZipResult = false;
  let showOnboarding = false;
  let kofiDismissed = false;
  let currentSettings = null;
  let zipResults = [];
  let conflictList = [];
  let pendingConnectName = '';
  let editName = '';
  let editorContent = '';
  let editorOriginalName = ''; // preserved across bind updates for rename detection
  let editorErrors = [];
  let toast = '';
  let toastTimer = null;
  let updateInfo = null;
  let filesDroppedUnsub = null;
  let helperUnsub = null;
  let helperResetUnsub = null;
  let helperReady = false;
  let helperEverConnected = false;

  onMount(async () => {
    // Load and apply saved theme before loading other data.
    // applyTheme sets the data-theme attribute AND the resolvedTheme store
    // that CodeMirror subscribes to for its own light/dark swap.
    let s = null;
    try {
      s = await TunnelService.GetSettings();
      currentSettings = s;
      kofiDismissed = s?.kofi_dismissed || false;
      applyTheme(s?.theme || 'system');
      // Apply persisted language. 'auto' means "follow OS locale" — we
      // resolve that via detectLanguage(). Without this, launching the
      // app always showed the detected language even if the user had
      // explicitly picked Korean before.
      const lang = s?.language || 'auto';
      setLanguage(lang === 'auto' ? detectLanguage() : lang);
    } catch (e) {
      applyTheme('system');
    }
    if (!s?.onboarding_complete) {
      showOnboarding = true;
    }
    initThemeWatcher();

    // Start piping backend log events into the LogViewer store BEFORE
    // initialLoad so the first slog records (tunnel list scan, etc.) are
    // captured. Idempotent.
    startLogListener();

    await initialLoad(TunnelService);
    subscribeToEvents();

    // Auto-check for updates ~3s after launch. Delayed so the network
    // call doesn't compete with initial tunnel scan / status refresh on
    // startup. The result feeds the existing UpdateNotice popup and the
    // About-tab badge by setting `updateInfo` — no separate UI path.
    setTimeout(async () => {
      try {
        const info = await TunnelService.CheckForUpdate();
        if (info?.available) updateInfo = info;
      } catch (e) {
        // Silent — update check failure should never block the app
      }
    }, 3000);

    // Wails v3 native file drop — HTML5 dragdrop doesn't work in WebKit.
    // Event payload: { files: string[], details: {...} }
    filesDroppedUnsub = Events.On('files-dropped', async (event) => {
      const payload = event.data || {};
      const paths = payload.files || [];
      for (const path of paths) {
        const lower = path.toLowerCase();
        if (lower.endsWith('.conf')) {
          await importFromPath(path);
        } else if (lower.endsWith('.zip')) {
          await importZipFromPath(path);
        } else if (lower.endsWith('.png') || lower.endsWith('.jpg') || lower.endsWith('.jpeg') || lower.endsWith('.gif')) {
          await importQRFromPath(path);
        } else {
          showToast('Only .conf, .zip, and QR image files are supported');
        }
      }
    });

    // Helper health events (crash detection)
    helperUnsub = Events.On('helper', (event) => {
      const { alive } = event.data || {};
      if (alive) {
        helperReady = true;
        if (helperEverConnected) showToast('Helper reconnected');
        helperEverConnected = true;
      } else {
        helperReady = false;
      }
    });

    // Helper reset — the GUI's IPC client was swapped after a helper
    // restart. Local caches may be stale; re-fetch everything.
    helperResetUnsub = Events.On('helper_reset', async () => {
      await initialLoad(TunnelService);
      await refreshStatus(TunnelService);
    });
  });

  onDestroy(() => {
    unsubscribe();
    stopLogListener();
    if (filesDroppedUnsub) filesDroppedUnsub();
    if (helperUnsub) helperUnsub();
    if (helperResetUnsub) helperResetUnsub();
    if (toastTimer) clearTimeout(toastTimer);
  });

  function showToast(msg) {
    if (toastTimer) clearTimeout(toastTimer);
    toast = msg;
    toastTimer = setTimeout(() => { toast = ''; toastTimer = null; }, 3000);
  }

  // Generate a unique tunnel name by appending -1, -2, etc. if needed.
  async function uniqueName(baseName) {
    if (!(await TunnelService.TunnelExists(baseName))) return baseName;
    for (let i = 1; i < 1000; i++) {
      const candidate = `${baseName}-${i}`;
      if (!(await TunnelService.TunnelExists(candidate))) return candidate;
    }
    return baseName + '-' + Date.now();
  }

  // Show zip import result modal.
  function showZipResults(results) {
    zipResults = results;
    showZipResult = true;
    if (results.some(r => !r.error)) {
      refreshTunnels(TunnelService);
    }
  }

  // Import a .zip from a filesystem path (used by native file drop).
  async function importZipFromPath(path) {
    try {
      const results = await TunnelService.ImportZip(path);
      showZipResults(results);
    } catch (e) {
      showToast('Import failed: ' + errText(e));
    }
  }

  // Import a .zip from a browser File object (used by file picker).
  // Wails serialises []byte as a base64 JSON string, so we must encode manually.
  // See lib/encoding.js for the chunked-encoder rationale.
  async function importZipFromFile(file) {
    if (!file) return;
    try {
      const buf = await file.arrayBuffer();
      const b64 = uint8ArrayToBase64(new Uint8Array(buf));
      const results = await TunnelService.ImportZipData(b64);
      showZipResults(results);
    } catch (e) {
      showToast('Import failed: ' + errText(e));
    }
  }

  // Import from a file path (used by native file drop).
  async function importFromPath(path) {
    try {
      const content = await TunnelService.ReadFile(path);
      const errors = await TunnelService.ValidateConfig(content);
      if (errors && errors.length > 0) {
        showToast('Invalid config: ' + errors[0]);
        return;
      }
      const baseName = await TunnelService.BaseName(path);
      const name = await uniqueName(baseName);
      await TunnelService.ImportConfig(name, content);
      showToast(`Imported "${name}"`);
      await refreshTunnels(TunnelService);
    } catch (e) {
      showToast("Import failed: " + errText(e));
    }
  }

  // Import a QR code image from a filesystem path (native drag-drop).
  async function importQRFromPath(path) {
    try {
      const baseName = (path.split('/').pop() || 'tunnel').replace(/\.[^.]+$/, '');
      const name = await uniqueName(baseName);
      await TunnelService.ImportQRFromPath(path, name);
      showToast(`Imported "${name}" from QR`);
      await refreshTunnels(TunnelService);
    } catch (e) {
      showToast($t('import.qr_error'));
    }
  }

  // Import a QR code image from a browser File object (file picker).
  async function importQRFromFile(file) {
    if (!file) return;
    try {
      const baseName = file.name.replace(/\.[^.]+$/, '');
      const name = await uniqueName(baseName);
      const buf = await file.arrayBuffer();
      const b64 = uint8ArrayToBase64(new Uint8Array(buf));
      await TunnelService.ImportQRFromBytes(b64, name);
      showToast(`Imported "${name}" from QR`);
      await refreshTunnels(TunnelService);
    } catch (e) {
      showToast($t('import.qr_error'));
    }
  }

  // Show the file picker for QR image import.
  function handleImportQR() {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = 'image/*';
    input.onchange = (e) => {
      const file = e.target.files[0];
      if (file) importQRFromFile(file);
    };
    input.click();
  }

  // Import from a browser File object (used by file picker button).
  async function importFile(file) {
    if (!file) return;
    const baseName = file.name.replace(/\.conf$/i, '');
    const content = await file.text();
    try {
      const errors = await TunnelService.ValidateConfig(content);
      if (errors && errors.length > 0) {
        showToast('Invalid config: ' + errors[0]);
        return;
      }
      const name = await uniqueName(baseName);
      await TunnelService.ImportConfig(name, content);
      showToast(`Imported "${name}"`);
      await refreshTunnels(TunnelService);
    } catch (e) {
      showToast("Import failed: " + errText(e));
    }
  }

  async function handleImportOpen() {
    // Directly open the native file picker — no modal needed.
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.conf,.zip';
    input.onchange = async (e) => {
      const file = e.target.files[0];
      if (!file) return;
      if (file.name.toLowerCase().endsWith('.zip')) {
        await importZipFromFile(file);
      } else {
        await importFile(file);
      }
    };
    input.click();
  }

  let editorIsNew = false;

  async function handleNewTunnelOpen() {
    editName = '';
    editorContent = ''; // ConfigEditor will generate template when isNew + empty
    editorErrors = [];
    editorIsNew = true;
    showEditor = true;
  }

  async function handleEdit(e) {
    editName = e.detail;
    editorOriginalName = editName; // snapshot before bind can mutate it
    try {
      editorContent = await TunnelService.GetConfigText(editName);
      editorErrors = [];
      editorIsNew = false;
      showEditor = true;
    } catch (err) {
      console.error(err);
    }
  }

  async function doSave(e) {
    const { name: saveName, content: saveContent } = e.detail;
    editorErrors = [];

    if (!saveName) {
      editorErrors = [$t('editor.name_required')];
      return;
    }

    try {
      const errors = await TunnelService.ValidateConfig(saveContent);
      if (errors && errors.length > 0) {
        editorErrors = errors;
        return;
      }
      if (editorIsNew) {
        await TunnelService.ImportConfig(saveName, saveContent);
      } else {
        // Compare against the ORIGINAL name (snapshot before bind could
        // mutate editName). bind:name={editName} updates editName live
        // as the user types, so by save-time editName === saveName always
        // — which meant RenameTunnel was never called, and UpdateConfig
        // created a new file instead of overwriting the old one.
        if (saveName !== editorOriginalName) {
          await TunnelService.RenameTunnel(editorOriginalName, saveName);
          // Update selectedTunnel so refreshTunnels' find() matches the
          // new name. Without this, the list refreshes but the detail
          // pane stays on the stale old name.
          selectedTunnel.update(sel => sel ? { ...sel, name: saveName } : sel);
        }
        await TunnelService.UpdateConfig(saveName, saveContent);
      }
      showEditor = false;
      await refreshTunnels(TunnelService);
    } catch (err) {
      editorErrors = [errText(err)];
    }
  }

  async function handleRefresh() {
    await refreshTunnels(TunnelService);
  }

  async function handleExport(e) {
    const name = e.detail;
    try {
      const path = await TunnelService.ExportTunnel(name);
      if (path) {
        showToast(`Exported to ${path}`);
      }
    } catch (err) {
      showToast('Export failed: ' + err.toString());
    }
  }

  // Actually perform the connect RPC (after all warnings have been resolved).
  // After successful connect, auto-apply kill switch and DNS protection
  // based on saved settings (global preferences, not per-tunnel).
  async function doConnectFinal(name) {
    try {
      await TunnelService.Connect(name);
      await refreshTunnels(TunnelService);
      await refreshStatus(TunnelService);

      // Auto-apply firewall settings after successful connect
      try {
        const s = await TunnelService.GetSettings();
        if (s?.kill_switch) {
          await TunnelService.SetKillSwitch(true);
        }
        if (s?.dns_protection) {
          await TunnelService.SetDNSProtection(true);
        }
      } catch (e) {
        console.warn('auto-apply firewall settings failed:', e);
      }
    } catch (e) {
      if (!helperReady) {
        showToast("Helper is still starting up — please wait a moment");
      } else {
        showToast("Connect failed: " + errText(e));
      }
    }
  }

  async function handleDismissKofi() {
    kofiDismissed = true;
    try {
      const s = currentSettings || await TunnelService.GetSettings();
      await TunnelService.SaveSettings({ ...s, kofi_dismissed: true });
    } catch (e) {
      console.warn('failed to persist kofi dismissed state:', e);
    }
  }

  // Check for routing conflicts before connecting. If conflicts exist, show
  // the ConflictWarning dialog; otherwise proceed directly.
  async function doConnect(name) {
    try {
      const conflicts = await TunnelService.CheckConflicts(name);
      if (conflicts && conflicts.length > 0) {
        conflictList = conflicts;
        pendingConnectName = name;
        showConflictWarning = true;
        return;
      }
    } catch (e) {
      // Non-fatal — if the conflict check itself fails, proceed anyway.
      console.warn('conflict check failed:', e);
    }
    await doConnectFinal(name);
  }

  async function handleConflictProceed() {
    showConflictWarning = false;
    await doConnectFinal(pendingConnectName);
  }

  function handleConflictCancel() {
    showConflictWarning = false;
    conflictList = [];
  }

  async function handleConnect(e) {
    const { name } = e.detail;
    await doConnect(name);
  }

  async function handleUpdate() {
    try {
      await TunnelService.RunUpdate(updateInfo);
    } catch (e) {
      showToast('Update failed: ' + errText(e));
    }
  }
</script>

<!-- The `$: $locale` subscription in the script block lets every `$t(...)`
     call inside this template re-evaluate on language change. Modals are
     separate components mounted conditionally below; they pick up the new
     language on their next open (deliberate — otherwise changing language
     mid-interaction would destroy the modal). -->
<div class="app" class:modal-open={showSettings || showEditor || showConflictWarning || showZipResult} data-file-drop-target={!(showSettings || showEditor || showConflictWarning || showZipResult) && currentView === 'tunnels' ? true : undefined}>
  <!-- Wails adds .file-drop-target-active class to .app when dragging files.
       We only render the overlay when drop-target is actually active — i.e.
       on the tunnels view with no modal open — so it can never steal clicks
       from modals. The data-file-drop-target attribute above also removes
       the drop affordance entirely in those states so Wails doesn't even
       detect the drag. -->
  {#if currentView === 'tunnels' && !(showSettings || showEditor || showConflictWarning || showZipResult)}
    <div class="drop-overlay">
      <div class="drop-overlay-content">
        <div class="drop-icon">↓</div>
        <div class="drop-text">{$t('tunnel.drop_overlay')}</div>
      </div>
    </div>
  {/if}

  {#if toast}
    <div class="toast">{toast}</div>
  {/if}

  <div class="layout">
    <nav class="icon-rail">
      <div class="rail-logo">W+</div>
      <button class="rail-btn" class:active={isTunnelsView} on:click={() => { currentView = 'tunnels'; }}>
        <span class="rail-icon">⊡</span>
        <span class="rail-label">{$t('nav.tunnels')}</span>
      </button>
      <button class="rail-btn" class:active={isToolsView} on:click={() => currentView = 'dnsleak'}>
        <span class="rail-icon">◈</span>
        <span class="rail-label">{$t('nav.tools')}</span>
      </button>
      <button class="rail-btn" class:active={currentView === 'logs'} on:click={() => currentView = 'logs'}>
        <span class="rail-icon">≡</span>
        <span class="rail-label">{$t('nav.logs')}</span>
      </button>
      <button class="rail-btn" class:active={currentView === 'history'} on:click={() => currentView = 'history'}>
        <span class="rail-icon" aria-hidden="true">
          <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="10" cy="10" r="8"/>
            <polyline points="10,5 10,10 13,13"/>
            <path d="M3.5 3.5 A8 8 0 0 0 2 10" stroke-dasharray="2 2"/>
          </svg>
        </span>
        <span class="rail-label">{$t('nav.history')}</span>
      </button>
      <div class="rail-spacer"></div>
      <button class="rail-btn" on:click={() => showSettings = true}>
        <span class="rail-icon">⚙</span>
        <span class="rail-label">{$t('nav.settings')}</span>
      </button>
    </nav>

    <!-- Main content -->
    <div class="main-content">
      <UpdateNotice {updateInfo} onInstall={handleUpdate} />

      <KofiBanner {TunnelService} dismissed={kofiDismissed} onDismiss={handleDismissKofi} />

      {#if !helperReady}
        <div class="helper-connecting">
          <span class="helper-spinner"></span>
          Starting helper service…
        </div>
      {/if}

      {#if currentView === 'tunnels'}
        <div class="tunnels-view">
          <TunnelCards {TunnelService}
            on:new={handleNewTunnelOpen}
            on:import={handleImportOpen}
            on:import-qr={handleImportQR}
            on:connect={handleConnect}
            on:edit={handleEdit}
            on:export={handleExport}
            on:refresh={handleRefresh} />
        </div>
      {:else if currentView === 'dnsleak'}
        <div class="tool-view">
          <DNSLeakTest />
        </div>
      {:else if currentView === 'routes'}
        <div class="tool-view">
          <RouteVisualization />
        </div>
      {:else if currentView === 'logs'}
        <div class="logs-view">
          <LogViewer />
        </div>
      {:else if currentView === 'history'}
        <History />
      {/if}
    </div>
  </div>

  <!-- Modals -->
  {#if showEditor}
    <div class="modal-backdrop" on:click={() => showEditor = false}>
      <div class="modal modal-editor" on:click|stopPropagation>
        <ConfigEditor
          bind:content={editorContent}
          bind:name={editName}
          errors={editorErrors}
          isNew={editorIsNew}
          nameEditable={true}
          on:save={doSave}
          on:cancel={() => showEditor = false} />
      </div>
    </div>
  {/if}

  {#if showSettings}
    <Settings {TunnelService} onClose={() => showSettings = false} {updateInfo} onInstall={handleUpdate} />
  {/if}

  {#if showConflictWarning}
    <ConflictWarning
      conflicts={conflictList}
      on:proceed={handleConflictProceed}
      on:cancel={handleConflictCancel} />
  {/if}

  {#if showOnboarding}
    <Onboarding on:complete={async () => { showOnboarding = false; await refreshTunnels(TunnelService); }} />
  {/if}

  {#if showZipResult}
    <div class="modal-backdrop" on:click={() => showZipResult = false}>
      <div class="modal modal-zip-result" on:click|stopPropagation>
        <h3>{$t('import.zip_result_title')}</h3>
        <div class="zip-result-list">
          {#each zipResults as r}
            <div class="zip-result-row">
              <span class="zip-result-icon" class:zip-ok={!r.error} class:zip-err={!!r.error}>{r.error ? '✕' : '✓'}</span>
              <span class="zip-result-name" class:zip-err={!!r.error}>{r.name}</span>
              {#if r.error}<span class="zip-result-msg">{r.error}</span>{/if}
            </div>
          {/each}
        </div>
        <div class="zip-result-footer">
          <span class="zip-result-summary">
            {#if zipResults.some(r => !!r.error)}
              {$t('import.zip_summary', { ok: zipResults.filter(r => !r.error).length, fail: zipResults.filter(r => !!r.error).length })}
            {:else}
              {$t('import.zip_summary_ok', { ok: zipResults.length })}
            {/if}
          </span>
          <button class="btn-primary" on:click={() => showZipResult = false}>{$t('import.zip_ok')}</button>
        </div>
      </div>
    </div>
  {/if}
</div>

<style>
  :global(body) {
    margin: 0;
    background: var(--bg-primary);
    color: var(--text-primary);
    font-family: var(--font-sans);
    font-size: 13px;
    line-height: 1.38;
    overflow: hidden;
  }
  .app {
    width: 100vw;
    height: 100vh;
    position: relative;
  }

  /* ---------- Drop overlay ----------
   * IMPORTANT: this sits at z-index 1000 and covers the full viewport.
   * `pointer-events: none` is NOT enough on WebKit — a compositing layer
   * created by `backdrop-filter` on a full-viewport element intercepts
   * custom <button> clicks (form controls like <select>/<input> use a
   * separate native event path and still work, which is why the bug
   * looked inconsistent: modal selects worked, modal close buttons
   * didn't). We use `visibility: hidden` by default so the element is
   * completely removed from hit-testing until a drag is actually in
   * progress. `visibility` still transitions with opacity because we
   * only toggle it on the active class.
   */
  .drop-overlay {
    position: fixed;
    inset: 0;
    background: var(--drop-overlay-bg);
    display: flex;
    align-items: center;
    justify-content: center;
    pointer-events: none;
    z-index: 1000;
    opacity: 0;
    visibility: hidden;
  }
  @media (prefers-reduced-motion: no-preference) {
    .drop-overlay { transition: opacity var(--dur-base) var(--ease-out); }
  }
  :global(.file-drop-target-active) > .drop-overlay {
    opacity: 1;
    visibility: visible;
    backdrop-filter: blur(10px) saturate(180%);
    -webkit-backdrop-filter: blur(10px) saturate(180%);
  }
  .drop-overlay-content {
    padding: var(--space-10) var(--space-12);
    background: var(--bg-primary);
    border: 2px dashed var(--accent);
    border-radius: var(--radius-lg);
    text-align: center;
    box-shadow: var(--shadow-lg);
  }
  .drop-icon {
    font-size: 40px;
    color: var(--accent);
    margin-bottom: var(--space-2);
    line-height: 1;
  }
  .drop-text {
    font: var(--text-title-3);
    color: var(--text-primary);
  }

  /* ---------- Layout ---------- */
  .layout {
    display: flex;
    height: 100%;
  }

  /* ---------- Icon rail (replaces old sidebar) ---------- */
  .icon-rail {
    width: 88px;
    background: var(--bg-secondary);
    border-right: 0.5px solid var(--border);
    display: flex;
    flex-direction: column;
    align-items: center;
    padding-top: 52px;
    padding-bottom: var(--space-2);
    gap: 2px;
    flex-shrink: 0;
  }
  .rail-logo {
    font: 700 15px/20px var(--font-sans);
    color: var(--accent);
    letter-spacing: -0.03em;
    padding: var(--space-2) 0 var(--space-4);
    user-select: none;
  }
  .rail-btn {
    width: 72px;
    height: 56px;
    border-radius: var(--radius-md);
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 4px;
    color: var(--text-secondary);
    background: transparent;
    border: 0;
    cursor: pointer;
    transition: background-color var(--dur-fast) var(--ease-out),
                color var(--dur-fast) var(--ease-out);
  }
  .rail-btn:hover { background: var(--bg-hover); color: var(--text-primary); }
  .rail-btn.active { background: var(--bg-selected); color: var(--accent); }
  .rail-icon { font-size: 20px; line-height: 1; }
  .rail-label {
    font: 400 9px/11px var(--font-sans);
    text-transform: uppercase;
    letter-spacing: 0.06em;
  }
  .rail-spacer { flex: 1; }

  /* ---------- Main content ---------- */
  .main-content {
    flex: 1;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }
  .tunnels-view {
    display: flex;
    flex: 1;
    overflow: hidden;
    min-height: 0;
  }

  .btn-primary {
    height: 28px;
    padding: 0 var(--space-4);
    background: var(--gradient-accent);
    border: 0;
    border-radius: var(--radius-btn);
    color: var(--text-inverse);
    cursor: pointer;
    font: var(--text-headline);
  }
  .btn-primary:hover { filter: brightness(1.1); }
  .btn-primary:active { filter: brightness(0.92); }
  .btn-secondary {
    height: 28px;
    padding: 0 var(--space-4);
    background: var(--bg-card);
    border: 0.5px solid var(--border);
    border-radius: var(--radius-btn);
    color: var(--text-primary);
    cursor: pointer;
    font: var(--text-headline);
  }
  .btn-secondary:hover { background: var(--bg-hover); }
  .btn-secondary:active { background: var(--bg-active); }
  @media (prefers-reduced-motion: no-preference) {
    .btn-primary, .btn-secondary {
      transition: background-color var(--dur-fast) var(--ease-out),
                  filter var(--dur-fast) var(--ease-out);
    }
  }

  /* ---------- Tool view (individual tool panel) ---------- */
  .tool-view {
    flex: 1;
    display: flex;
    flex-direction: column;
    padding-top: 52px;
    overflow: hidden;
  }

  .logs-view {
    flex: 1;
    min-height: 0;
    padding-top: 52px;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }

  .history-view-host {
    flex: 1;
    min-height: 0;
    padding-top: 52px;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }
  .rail-icon svg {
    display: block;
  }

  /* ---------- Helper connecting bar ---------- */
  .helper-connecting {
    position: fixed;
    bottom: 20px;
    left: 50%;
    transform: translateX(-50%);
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 8px 14px;
    border-radius: 10px;
    background: var(--bg-card);
    border: 0.5px solid var(--border);
    box-shadow: 0 4px 16px rgba(0,0,0,0.3);
    z-index: 199;
    font: 400 12px/16px var(--font-sans, -apple-system, BlinkMacSystemFont, sans-serif);
    color: var(--text-secondary);
    white-space: nowrap;
  }
  .helper-spinner {
    width: 10px;
    height: 10px;
    border: 1.5px solid var(--border);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
    flex-shrink: 0;
  }
  @keyframes spin { to { transform: rotate(360deg); } }

  /* ---------- Toast (bottom-centre) ---------- */
  .toast {
    position: fixed;
    bottom: var(--space-6);
    left: 50%;
    transform: translateX(-50%);
    padding: var(--space-3) var(--space-4);
    background: var(--bg-card);
    border: 0.5px solid var(--border);
    border-radius: var(--radius-md);
    color: var(--text-primary);
    font: var(--text-body);
    box-shadow: var(--shadow-md);
    z-index: 300;
    max-width: 480px;
    white-space: normal;
    word-break: break-word;
  }

  /* ---------- Modal (shared) ---------- */
  .modal-backdrop {
    position: fixed;
    inset: 0;
    background: var(--overlay-bg);
    /* NOTE: no backdrop-filter here. WebKit has a known compositing bug
     * where a child element's box-shadow "bleeds" through the parent's
     * backdrop-filter pass, producing a grey halo around the modal's
     * rounded corners (especially visible at modal open/close transitions).
     * The opaque overlay is enough to separate the modal from the app
     * behind it — blur costs clarity for no visual gain here. */
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 200;
  }
  .modal {
    background: var(--bg-primary);
    border: 0.5px solid var(--border);
    border-radius: var(--radius-lg);
    padding: var(--space-5);
    width: 440px;
    max-height: 80vh;
    overflow-y: auto;
    box-shadow: var(--shadow-lg);
  }
  .modal-editor {
    width: 640px;
    height: 520px;
    padding: 0;
    overflow: hidden;
    resize: both;
    min-width: 480px;
    min-height: 380px;
    max-width: calc(100vw - 40px);
    max-height: calc(100vh - 40px);
  }
  .modal-zip-result {
    width: 520px;
    max-width: 90vw;
    max-height: 70vh;
    overflow: hidden;
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }
  /* Use .modal.modal-zip-result h3 (specificity 0,3,1) to beat
     .modal h3 (0,2,1 after Svelte scoping) which appears later. */
  .modal.modal-zip-result h3 {
    margin: 0;
    flex-shrink: 0;
  }
  .zip-result-list {
    /* flex: 1 + min-height: 0 is the correct pattern for a scrollable
       child inside a max-height flex container. Without min-height: 0
       the child refuses to shrink below its content size, causing the
       outer container to overflow and clip content instead of scroll. */
    flex: 1;
    min-height: 0;
    overflow-y: auto;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .zip-result-footer {
    flex-shrink: 0;
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: var(--space-3);
  }
  .zip-result-row {
    display: flex;
    align-items: baseline;
    gap: 8px;
    font-size: 13px;
    color: var(--text-primary);
  }
  .zip-result-icon {
    flex-shrink: 0;
    font-size: 11px;
  }
  .zip-ok { color: var(--green); }
  .zip-err { color: var(--red); }
  .zip-result-name {
    font-weight: 500;
    word-break: break-all;
  }
  .zip-result-msg {
    color: var(--text-secondary);
    font-size: 12px;
    word-break: break-word;
  }
  .zip-result-summary {
    font-size: 12px;
    color: var(--text-secondary);
  }

  .modal h3 {
    margin: 0 0 var(--space-4);
    color: var(--text-primary);
    font: var(--text-title-2);
  }
  .modal label {
    display: block;
    margin: var(--space-3) 0 var(--space-1);
    font: var(--text-subheadline);
    color: var(--text-secondary);
  }
  .modal input[type="text"] {
    width: 100%;
    height: 24px;
    padding: 0 var(--space-2);
    background: var(--bg-input);
    border: 0.5px solid var(--border);
    border-radius: var(--radius-sm);
    color: var(--text-primary);
    font: var(--text-body);
    box-sizing: border-box;
    outline: none;
  }
  .modal input[type="text"]:focus {
    border-color: var(--accent);
    box-shadow: 0 0 0 3px var(--blue-tint);
  }
  .hint {
    font: var(--text-footnote);
    color: var(--text-secondary);
    margin: 0 0 var(--space-3);
  }
  .btn-file-select {
    width: 100%;
    padding: var(--space-3);
    background: var(--bg-card);
    border: 1px dashed var(--border);
    border-radius: var(--radius-btn);
    color: var(--text-primary);
    font: var(--text-body);
    cursor: pointer;
    margin-bottom: var(--space-2);
  }
  @media (prefers-reduced-motion: no-preference) {
    .btn-file-select {
      transition: background-color var(--dur-fast) var(--ease-out),
                  border-color var(--dur-fast) var(--ease-out);
    }
  }
  .btn-file-select:hover {
    background: var(--bg-hover);
    border-color: var(--accent);
  }
  .preview {
    margin: var(--space-3) 0;
    padding: var(--space-3);
    background: var(--editor-bg);
    border: 0.5px solid var(--editor-border);
    border-radius: var(--radius-sm);
    font: 10px/14px var(--font-mono);
    color: var(--text-secondary);
    max-height: 200px;
    overflow-y: auto;
    white-space: pre-wrap;
  }
  .errors {
    margin: var(--space-2) 0;
    padding: var(--space-2) var(--space-3);
    background: var(--error-bg);
    border: 0.5px solid var(--red);
    border-radius: var(--radius-sm);
  }
  .errors p {
    margin: var(--space-1) 0;
    color: var(--error-text);
    font: var(--text-body);
  }
  .modal-footer {
    display: flex;
    gap: var(--space-2);
    justify-content: flex-end;
    margin-top: var(--space-4);
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
  .btn:disabled { opacity: 0.45; cursor: not-allowed; }
  .btn-connect {
    background: var(--gradient-accent);
    color: var(--text-inverse);
  }
  @media (prefers-reduced-motion: no-preference) {
    .btn, .btn-connect {
      transition: background-color var(--dur-fast) var(--ease-out),
                  filter var(--dur-fast) var(--ease-out);
    }
  }
  .btn-connect:hover:not(:disabled) { filter: brightness(1.1); }
  .btn-connect:active:not(:disabled) { filter: brightness(0.92); }
</style>
