import { describe, expect, it } from "vitest";
import { DragController } from "./drag.svelte";

/**
 * Every drop in this app is a write — move to folder, move to
 * collection, share. A standalone vault has nowhere for one to land,
 * so no drag may start.
 *
 * Gated at the source rather than at each drop target on purpose: a
 * drag that starts and then quietly does nothing is worse than one
 * that never starts, because the user has already committed to the
 * gesture by the time a target could refuse it.
 */
describe("DragController in a read-only vault", () => {
  it("starts a cipher drag normally when writable", () => {
    const drag = new DragController();
    drag.startCipher("cipher-1");
    expect(drag.cipherId).toBe("cipher-1");
  });

  it("refuses to start a cipher drag when disabled", () => {
    const drag = new DragController();
    drag.disabled = true;
    drag.startCipher("cipher-1");
    expect(drag.cipherId).toBeNull();
  });

  it("refuses to start a folder drag when disabled", () => {
    const drag = new DragController();
    drag.disabled = true;
    drag.startFolder("Work/Clients");
    expect(drag.folderPath).toBeNull();
  });

  it("leaves no stale source behind after being disabled mid-drag", () => {
    // Flipping to standalone while something is in flight must not
    // leave a droppable source hanging around.
    const drag = new DragController();
    drag.startCipher("cipher-1");
    drag.disabled = true;
    drag.end();
    expect(drag.cipherId).toBeNull();
    expect(drag.folderPath).toBeNull();
    expect(drag.overKey).toBeNull();
  });
});
