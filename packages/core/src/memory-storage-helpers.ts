export function cloneStored<T>(value: T): T {
  return structuredClone(value);
}

export function someStored<T>(store: ReadonlyMap<string, T>, predicate: (value: T) => boolean): boolean {
  for (const value of store.values()) {
    if (predicate(value)) return true;
  }
  return false;
}

export function findStored<T>(
  store: ReadonlyMap<string, T>,
  predicate: (value: T) => boolean
): T | null {
  for (const value of store.values()) {
    if (predicate(value)) {
      return cloneStored(value);
    }
  }

  return null;
}

export function updateStoredEntity<T extends { id: string }>(
  store: Map<string, T>,
  id: string,
  patch: Partial<T>
): T | null {
  const existing = store.get(id);
  if (!existing) {
    return null;
  }

  const updated = cloneStored({ ...existing, ...patch, id: existing.id });
  store.set(id, updated);
  return cloneStored(updated);
}

export function updateStoredWhere<T extends { id: string }>(
  store: Map<string, T>,
  predicate: (value: T) => boolean,
  patch: Partial<T>
): void {
  for (const [id, value] of store) {
    if (predicate(value)) updateStoredEntity(store, id, patch);
  }
}
