export class DragController {
  cipherId = $state<string | null>(null);
  folderPath = $state<string | null>(null);
  overKey = $state<string | null>(null);

  /**
   * Set while the vault is open without a server, where every drop
   * would be a write.
   *
   * Gated here rather than at each drop target because a drag that
   * *starts* and then quietly does nothing is worse than one that
   * never starts: the user has already committed to the gesture by the
   * time a drop target could refuse it. With no drag in flight, every
   * `dragover`/`drop` handler downstream sees a null source and
   * declines on its own.
   */
  disabled = $state(false);

  startCipher(id: string) {
    if (this.disabled) return;
    this.cipherId = id;
    this.folderPath = null;
  }

  startFolder(path: string) {
    if (this.disabled) return;
    this.folderPath = path;
    this.cipherId = null;
  }

  end() {
    this.cipherId = null;
    this.folderPath = null;
    this.overKey = null;
  }

  resetCipher() {
    this.cipherId = null;
    this.overKey = null;
  }

  resetFolder() {
    this.folderPath = null;
    this.overKey = null;
  }
}
