import { describe, expect, it } from 'vitest';
import { updateAmbientPose, type MutablePoseTarget } from '../src/app/ambientMotion';

function target(): MutablePoseTarget {
  return { position: { x: 0, y: 0, z: 0 }, rotation: { x: 0, y: 0, z: 0 } };
}

describe('updateAmbientPose', () => {
  it('moves a shard deterministically with scroll and pointer input', () => {
    const node = target();
    updateAmbientPose(node, [2, 1, -1], 0.7, 0.4, 2, 0.5, 0.5, -0.25);

    expect(node.position.x).not.toBe(2);
    expect(node.position.y).not.toBe(1);
    expect(node.position.z).toBe(-1);
    expect(node.rotation.y).toBeCloseTo(2 * 0.7 * 0.2 + 0.5 * 0.1 + 0.5 * 0.22);
  });

  it('clamps out-of-range scroll and pointer input', () => {
    const node = target();
    const extreme = target();

    updateAmbientPose(node, [0, 0, 0], 1, 0, 1, 1, 1, -1);
    updateAmbientPose(extreme, [0, 0, 0], 1, 0, 1, 4, 5, -8);

    expect(extreme.position.x).toBeCloseTo(node.position.x);
    expect(extreme.position.y).toBeCloseTo(node.position.y);
    expect(extreme.rotation.x).toBeCloseTo(node.rotation.x);
    expect(extreme.rotation.y).toBeCloseTo(node.rotation.y);
    expect(extreme.rotation.z).toBeCloseTo(node.rotation.z);
  });
});
