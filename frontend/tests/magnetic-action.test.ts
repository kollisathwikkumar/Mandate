import { describe, expect, it } from 'vitest';
import { getMagneticOffset } from '../src/app/magneticAction';

describe('magnetic action offset', () => {
  it('keeps the action centered when the pointer is at the element center', () => {
    expect(getMagneticOffset(150, 75, { left: 100, top: 50, width: 100, height: 50 })).toEqual({ x: 0, y: 0 });
  });

  it('moves gently toward the pointer and clamps at the configured distance', () => {
    const bounds = { left: 100, top: 50, width: 100, height: 50 };
    expect(getMagneticOffset(150, 75, bounds, 4)).toEqual({ x: 0, y: 0 });
    expect(getMagneticOffset(200, 100, bounds, 4)).toEqual({ x: 4, y: 4 });
    expect(getMagneticOffset(100, 50, bounds, 4)).toEqual({ x: -4, y: -4 });
    expect(getMagneticOffset(500, -200, bounds, 4)).toEqual({ x: 4, y: -4 });
  });

  it('returns zero movement for zero-sized elements or a zero travel distance', () => {
    expect(getMagneticOffset(10, 10, { left: 0, top: 0, width: 0, height: 20 })).toEqual({ x: 0, y: 0 });
    expect(getMagneticOffset(10, 10, { left: 0, top: 0, width: 20, height: 0 })).toEqual({ x: 0, y: 0 });
    expect(getMagneticOffset(20, 20, { left: 0, top: 0, width: 20, height: 20 }, 0)).toEqual({ x: 0, y: 0 });
  });
});
