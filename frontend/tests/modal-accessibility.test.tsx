import { act, useState } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { Modal } from '../src/app/App';

let host: HTMLDivElement;
let root: Root;

function ModalFixture() {
  const [open, setOpen] = useState(false);
  return <><button onClick={() => setOpen(true)}>Open</button><Modal open={open} onClose={() => setOpen(false)} title="Confirm action"><button>Confirm</button><button>Cancel</button></Modal></>;
}

beforeEach(() => {
  host = document.createElement('div');
  document.body.append(host);
  root = createRoot(host);
  (globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
  act(() => root.render(<ModalFixture />));
});

afterEach(() => {
  act(() => root.unmount());
  host.remove();
});

describe('accessible modal behavior', () => {
  it('moves focus into the dialog, traps reverse tab, and restores focus after Escape', () => {
    const opener = host.querySelector('button');
    expect(opener).not.toBeNull();
    act(() => opener?.focus());
    act(() => opener?.click());
    const dialog = host.querySelector('[role="dialog"]');
    const close = host.querySelector('[aria-label="Close dialog"]');
    const cancel = Array.from(host.querySelectorAll('button')).find((button) => button.textContent === 'Cancel');
    expect(dialog?.getAttribute('aria-labelledby')).toBeTruthy();
    expect(document.activeElement).toBe(close);
    act(() => close?.dispatchEvent(new KeyboardEvent('keydown', { key: 'Tab', shiftKey: true, bubbles: true })));
    expect(document.activeElement).toBe(cancel);
    act(() => window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true })));
    expect(host.querySelector('[role="dialog"]')).toBeNull();
    expect(document.activeElement).toBe(opener);
  });
});
