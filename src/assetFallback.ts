/**
 * Graceful degradation for CDN-hosted fonts/icons (Google Fonts, Material
 * Symbols). If they fail to load (offline, blocked, slow), flag <html> so
 * index.css can swap in system font stacks and neutral icon markers instead of
 * showing raw ligature text. Never throws and never blocks rendering.
 */
const TIMEOUT_MS = 4000;

function withTimeout<T>(p: Promise<T>, ms: number): Promise<T | 'timeout'> {
  return Promise.race([p, new Promise<'timeout'>(resolve => window.setTimeout(() => resolve('timeout'), ms))]);
}

async function fontLoaded(spec: string): Promise<boolean> {
  try {
    if (!document.fonts?.load) return false;
    const faces = await withTimeout(document.fonts.load(spec, 'a'), TIMEOUT_MS);
    return faces !== 'timeout' && faces.length > 0;
  } catch {
    return false;
  }
}

export function installAssetFallbacks(): void {
  const root = document.documentElement;
  void (async () => {
    const [text, icons] = await Promise.all([
      fontLoaded('400 1em "JetBrains Mono"'),
      fontLoaded('400 1em "Material Symbols Outlined"'),
    ]);
    if (!text) root.classList.add('webfonts-failed');
    if (!icons) root.classList.add('icons-failed');
  })();
  // If the stylesheet arrives late (slow CDN), recover automatically.
  // (FontFaceSet.check() returns true for undeclared fonts, so inspect faces directly.)
  const hasLoadedFace = (family: string) =>
    Array.from(document.fonts ?? []).some(f => f.family.replace(/["']/g, '') === family && f.status === 'loaded');
  document.fonts?.addEventListener?.('loadingdone', () => {
    if (hasLoadedFace('Material Symbols Outlined')) root.classList.remove('icons-failed');
    if (hasLoadedFace('JetBrains Mono')) root.classList.remove('webfonts-failed');
  });
}
