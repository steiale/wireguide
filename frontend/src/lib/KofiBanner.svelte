<script>
  import { t } from '../i18n/index.js';
  import { connectCount } from '../stores/tunnels.js';

  export let TunnelService;
  export let dismissed = false;
  export let onDismiss = () => {};

  const THRESHOLD = 10;

  $: show = $connectCount >= THRESHOLD && !dismissed;
</script>

{#if show}
  <div class="kofi-toast">
    <span class="kofi-text">{$t('kofi.banner_text')}</span>
    <button class="kofi-cta" on:click={() => TunnelService.OpenURL('https://ko-fi.com/steiale')}>
      ☕ {$t('kofi.buy_coffee')}
    </button>
    <button class="kofi-dismiss" on:click={onDismiss} title={$t('kofi.dismiss')}>✕</button>
  </div>
{/if}

<style>
  .kofi-toast {
    position: fixed;
    bottom: 20px;
    left: 50%;
    transform: translateX(-50%);
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 10px 14px;
    border-radius: 10px;
    background: var(--bg-card);
    border: 0.5px solid var(--border);
    box-shadow: 0 4px 16px rgba(0,0,0,0.3);
    z-index: 200;
    white-space: nowrap;
  }
  .kofi-text {
    font: 400 12px/16px var(--font-sans, -apple-system, BlinkMacSystemFont, sans-serif);
    color: var(--text-secondary);
  }
  .kofi-cta {
    flex-shrink: 0;
    padding: 4px 10px;
    border-radius: 14px;
    border: 1px solid #FF5E5B55;
    background: #FF5E5B22;
    color: #FF5E5B;
    font: 500 12px/16px var(--font-sans, -apple-system, BlinkMacSystemFont, sans-serif);
    cursor: pointer;
    transition: background 0.15s;
  }
  .kofi-cta:hover { background: #FF5E5B33; }
  .kofi-dismiss {
    flex-shrink: 0;
    width: 24px;
    height: 24px;
    border: none;
    background: none;
    color: var(--text-secondary);
    font-size: 12px;
    cursor: pointer;
    opacity: 0.6;
    padding: 0;
    line-height: 1;
    display: flex;
    align-items: center;
    justify-content: center;
  }
  .kofi-dismiss:hover { opacity: 1; }
</style>
