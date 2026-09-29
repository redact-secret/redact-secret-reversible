// Seeded, deterministic pseudo-random numbers (mulberry32). Used for the
// corpus generator and for bootstrap resampling, so every figure and every
// corpus byte is reproducible from its seed. Not for anything security-related.

/** Returns a function yielding floats in [0, 1) from a 32-bit seed. */
export function mulberry32(seed) {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** Integer in [0, n) from a float generator. */
export function randomInt(random, n) {
  return Math.floor(random() * n);
}
