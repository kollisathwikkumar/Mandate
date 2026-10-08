export interface MutablePoseTarget {
  readonly position: { x: number; y: number; z: number };
  readonly rotation: { x: number; y: number; z: number };
}

const clamp = (value: number, low: number, high: number): number => Math.min(high, Math.max(low, value));

/** Applies low-amplitude scroll and pointer parallax without allocating in the render loop. */
export function updateAmbientPose(
  target: MutablePoseTarget,
  base: readonly [number, number, number],
  speed: number,
  phase: number,
  time: number,
  scrollProgress: number,
  pointerXInput: number,
  pointerYInput: number,
): void {
  const scroll = clamp(scrollProgress, 0, 1);
  const pointerX = clamp(pointerXInput, -1, 1);
  const pointerY = clamp(pointerYInput, -1, 1);
  const float = Math.sin(time * speed + phase);

  target.position.x = base[0] + pointerX * 0.18 + Math.sin(scroll * Math.PI * 2 + phase) * 0.12;
  target.position.y = base[1] + float * 0.12 - pointerY * 0.12 + (scroll - 0.5) * -0.18;
  target.position.z = base[2];
  target.rotation.x = Math.sin(time * 0.24 + phase) * 0.16 + pointerY * 0.08;
  target.rotation.y = time * speed * 0.2 + pointerX * 0.1 + scroll * 0.22;
  target.rotation.z = Math.cos(time * 0.18 + phase) * 0.08 + scroll * 0.12;
}
