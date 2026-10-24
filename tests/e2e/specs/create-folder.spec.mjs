// Folder creation from the sidebar: "+" next to "Mon coffre" → type a
// name → Enter → the folder is on the server and selected in the tree.
// `create_folder` itself is exercised by the rename/delete specs; this
// one covers the UI that composes the path, including a `/` in the
// name, which Bitwarden stores as one flat folder that the tree splits
// into a parent and a child.

import { loginAsSeededUser } from "../helpers/auth.mjs";

const RUN = `${Date.now().toString(36)}`;
const TOP = `e2e-newfolder-${RUN}`;
const NESTED_PARENT = `e2e-newnested-${RUN}`;
const NESTED_TYPED = `${NESTED_PARENT} / child`;
const NESTED_STORED = `${NESTED_PARENT}/child`;

async function createFromSidebar(name) {
  const button = await $('button[aria-label="Nouveau dossier"]');
  await button.waitForClickable({ timeout: 10_000 });
  await button.click();
  const input = await $('.tree-rename input[aria-label="Nouveau dossier"]');
  await input.waitForDisplayed({ timeout: 5_000 });
  await input.setValue(name);
  await browser.keys("Enter");
}

// WDIO's `*=` text selectors cannot follow a descendant combinator, so
// read the selected tree row's label from the DOM instead.
async function waitForSelectedFolder(label, timeoutMsg) {
  await browser.waitUntil(
    () =>
      browser.execute(
        (text) =>
          Array.from(document.querySelectorAll(".tree-row.selected .tree-label-text")).some(
            (el) => el.textContent === text,
          ),
        label,
      ),
    { timeout: 15_000, timeoutMsg },
  );
}

async function serverFolderNames() {
  return browser.execute(async () => {
    // @ts-expect-error — tauri injects this global
    const { invoke } = window.__TAURI__.core;
    const summary = await invoke("sync");
    return summary.folders.map((f) => f.name);
  });
}

describe("Create a folder from the sidebar", () => {
  before(async () => {
    await loginAsSeededUser();
  });

  it("creates a top-level folder and selects it", async () => {
    await createFromSidebar(TOP);

    await waitForSelectedFolder(TOP, "new folder never appeared selected in the tree");
    expect(await serverFolderNames()).toContain(TOP);
  });

  it("stores a `/` name as one nested path and opens its parent", async () => {
    await createFromSidebar(NESTED_TYPED);

    // The parent is expanded so the selected child is on screen.
    await waitForSelectedFolder("child", "nested folder never appeared selected in the tree");
    const names = await serverFolderNames();
    expect(names).toContain(NESTED_STORED);
    expect(names).not.toContain(NESTED_TYPED);
  });
});
