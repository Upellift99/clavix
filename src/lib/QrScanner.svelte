<script lang="ts">
  import { onDestroy } from "svelte";
  import jsQR from "jsqr";
  import * as m from "$lib/paraglide/messages";

  let {
    open,
    onCancel,
    onDetected,
  }: {
    open: boolean;
    onCancel: () => void;
    onDetected: (uri: string) => void;
  } = $props();

  let video = $state<HTMLVideoElement | null>(null);
  let canvas = $state<HTMLCanvasElement | null>(null);
  let stream: MediaStream | null = null;
  let frameTimer: number | null = null;
  let error = $state<string | null>(null);

  async function start() {
    error = null;
    try {
      stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: "environment" },
        audio: false,
      });
      if (video) {
        video.srcObject = stream;
        await video.play();
      }
      tick();
    } catch (e) {
      const msg = (e as Error).message ?? String(e);
      error = m.qr_camera_error({ cause: msg });
    }
  }

  function tick() {
    if (!video || !canvas || !stream) return;
    if (video.readyState === video.HAVE_ENOUGH_DATA) {
      const w = video.videoWidth;
      const h = video.videoHeight;
      canvas.width = w;
      canvas.height = h;
      const ctx = canvas.getContext("2d", { willReadFrequently: true });
      if (ctx) {
        ctx.drawImage(video, 0, 0, w, h);
        const imageData = ctx.getImageData(0, 0, w, h);
        const code = jsQR(imageData.data, w, h);
        if (code && code.data) {
          const raw = code.data.trim();
          if (raw.toLowerCase().startsWith("otpauth://")) {
            stop();
            onDetected(raw);
            return;
          }
        }
      }
    }
    frameTimer = requestAnimationFrame(tick);
  }

  function stop() {
    if (frameTimer !== null) {
      cancelAnimationFrame(frameTimer);
      frameTimer = null;
    }
    if (stream) {
      for (const track of stream.getTracks()) track.stop();
      stream = null;
    }
  }

  $effect(() => {
    if (open) {
      void start();
    } else {
      stop();
    }
  });

  onDestroy(() => {
    stop();
  });
</script>

{#if open}
  <div
    class="qr-backdrop"
    onclick={() => {
      stop();
      onCancel();
    }}
    onkeydown={(e) => {
      if (e.key === "Escape") {
        stop();
        onCancel();
      }
    }}
    role="presentation"
  >
    <div
      class="qr-panel"
      onclick={(e) => e.stopPropagation()}
      onkeydown={(e) => {
        // Escape closes the scanner; otherwise stopPropagation
        // swallowed it before the backdrop's keydown handler ran.
        if (e.key === "Escape") {
          stop();
          onCancel();
        }
        e.stopPropagation();
      }}
      role="dialog"
      aria-modal="true"
      aria-labelledby="qr-title"
      tabindex="-1"
    >
      <header class="qr-header">
        <h2 id="qr-title">{m.qr_title()}</h2>
        <button
          type="button"
          class="secondary small"
          onclick={() => {
            stop();
            onCancel();
          }}
          aria-label={m.action_close()}
        >
          ✕
        </button>
      </header>
      <p class="hint">{m.qr_hint()}</p>

      <div class="qr-video-wrap">
        <!-- svelte-ignore a11y_media_has_caption -->
        <video bind:this={video} playsinline muted></video>
      </div>
      <canvas bind:this={canvas} class="qr-hidden"></canvas>

      {#if error}
        <p class="qr-error">{error}</p>
      {/if}
    </div>
  </div>
{/if}

<style>
  .qr-backdrop {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.5);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 200;
  }

  .qr-panel {
    background: #fff;
    border-radius: 10px;
    padding: 1rem 1.25rem;
    width: min(440px, 94vw);
    box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
  }

  .qr-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 0.5rem;
  }

  .qr-header h2 {
    margin: 0;
    font-size: 1.05rem;
  }

  .hint {
    color: #555;
    font-size: 0.85rem;
    margin: 0 0 0.6rem;
  }

  .qr-video-wrap {
    width: 100%;
    aspect-ratio: 4 / 3;
    background: #000;
    border-radius: 8px;
    overflow: hidden;
  }

  video {
    width: 100%;
    height: 100%;
    object-fit: cover;
  }

  .qr-hidden {
    display: none;
  }

  .qr-error {
    color: #7a1d1d;
    background: #fdecec;
    padding: 0.5rem 0.7rem;
    border-radius: 6px;
    margin: 0.6rem 0 0;
    font-size: 0.88rem;
  }

  button {
    cursor: pointer;
    background: #fff;
    color: #333;
    border: 1px solid #d0d0d0;
    border-radius: 6px;
    padding: 0.3rem 0.6rem;
    font: inherit;
    font-size: 0.85rem;
  }

  button:hover {
    filter: brightness(0.95);
  }
</style>
