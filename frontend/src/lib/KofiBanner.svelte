<script>
  import { t } from '../i18n/index.js';
  import { connectCount, kofiDismissed, dismissKofi } from '../stores/tunnels.js';

  export let TunnelService;

  const THRESHOLD = 10;

  $: show = $connectCount >= THRESHOLD && !$kofiDismissed;
</script>

{#if show}
  <div class="kofi-banner">
    <span class="kofi-text">{$t('kofi.banner_text')}</span>
    <button class="kofi-cta" on:click={() => TunnelService.OpenURL('https://ko-fi.com/steiale')}>
      ☕ {$t('kofi.buy_coffee')}
    </button>
    <button class="kofi-dismiss" on:click={dismissKofi} title={$t('kofi.dismiss')}>✕</button>
  </div>
{/if}

<style>
  .kofi-banner {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 8px 14px;
    margin: 8px 12px;
    border-radius: 8px;
    background: #FF5E5B14;
    border: 1px solid #FF5E5B33;
  }
  .kofi-text {
    flex: 1;
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
    width: 18px;
    height: 18px;
    border: none;
    background: none;
    color: var(--text-secondary);
    font-size: 10px;
    cursor: pointer;
    opacity: 0.6;
    padding: 0;
    line-height: 1;
  }
  .kofi-dismiss:hover { opacity: 1; }
</style>
