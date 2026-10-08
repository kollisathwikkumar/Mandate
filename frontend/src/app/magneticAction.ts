export interface MagneticBounds {
  readonly left: number;
  readonly top: number;
  readonly width: number;
  readonly height: number;
}

export interface MagneticOffset {
  readonly x: number;
  readonly y: number;
}

export function getMagneticOffset(
  pointerX: number,
  pointerY: number,
  bounds: MagneticBounds,
  maxDistance = 4,
): MagneticOffset {
  if (bounds.width <= 0 || bounds.height <= 0 || maxDistance <= 0) return { x: 0, y: 0 };
  const normalizedX = Math.min(1, Math.max(-1, (pointerX - bounds.left - bounds.width / 2) / (bounds.width / 2)));
  const normalizedY = Math.min(1, Math.max(-1, (pointerY - bounds.top - bounds.height / 2) / (bounds.height / 2)));
  return { x: normalizedX * maxDistance, y: normalizedY * maxDistance };
}
