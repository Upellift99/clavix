export class DragController {
  cipherId = $state<string | null>(null);
  folderPath = $state<string | null>(null);
  overKey = $state<string | null>(null);

  startCipher(id: string) {
    this.cipherId = id;
    this.folderPath = null;
  }

  startFolder(path: string) {
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
