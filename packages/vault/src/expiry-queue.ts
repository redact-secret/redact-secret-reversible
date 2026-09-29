/**
 * A binary min-heap ordered by `expiresAt`. Internal to the vault: it lets
 * the expiry sweep visit only items that are due instead of walking every
 * retained entry. Equal keys pop in an unspecified order; callers must not
 * depend on it.
 */
export interface Expiring {
  readonly expiresAt: number;
}

export class ExpiryQueue<T extends Expiring> {
  #items: T[] = [];

  get size(): number {
    return this.#items.length;
  }

  push(item: T): void {
    const items = this.#items;
    items.push(item);
    let i = items.length - 1;
    // Items usually arrive in expiry order, so this loop rarely runs.
    while (i > 0) {
      const parent = (i - 1) >> 1;
      if ((items[parent] as T).expiresAt <= item.expiresAt) break;
      items[i] = items[parent] as T;
      i = parent;
    }
    items[i] = item;
  }

  /** The earliest-expiring item, or undefined when empty. */
  peek(): T | undefined {
    return this.#items[0];
  }

  pop(): T | undefined {
    const items = this.#items;
    const top = items[0];
    const last = items.pop();
    if (top !== undefined && last !== undefined && items.length > 0) {
      items[0] = last;
      this.#siftDown(0);
    }
    return top;
  }

  /** Keeps only items for which `keep` returns true, in O(n). */
  retain(keep: (item: T) => boolean): void {
    this.#items = this.#items.filter(keep);
    for (let i = (this.#items.length >> 1) - 1; i >= 0; i -= 1) this.#siftDown(i);
  }

  clear(): void {
    this.#items = [];
  }

  #siftDown(start: number): void {
    const items = this.#items;
    const n = items.length;
    const item = items[start] as T;
    let i = start;
    for (;;) {
      const left = 2 * i + 1;
      if (left >= n) break;
      const right = left + 1;
      const child =
        right < n && (items[right] as T).expiresAt < (items[left] as T).expiresAt ? right : left;
      if ((items[child] as T).expiresAt >= item.expiresAt) break;
      items[i] = items[child] as T;
      i = child;
    }
    items[i] = item;
  }
}
