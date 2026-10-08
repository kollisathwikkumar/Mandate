import { Canvas, useFrame, useThree } from '@react-three/fiber';
import { useMotionValueEvent, useReducedMotion, useScroll } from 'motion/react';
import { Suspense, useEffect, useRef, type MutableRefObject } from 'react';
import type { Mesh } from 'three';
import { updateAmbientPose } from './ambientMotion';

type PointerRef = MutableRefObject<[number, number]>;

function Shard({ position, scale, speed, color, index, progress, pointer }: { position: [number, number, number]; scale: number; speed: number; color: string; index: number; progress: MutableRefObject<number>; pointer: PointerRef }) {
  const mesh = useRef<Mesh>(null);
  const smoothPointer = useRef<[number, number]>([0, 0]);
  useFrame((state, delta) => {
    if (mesh.current === null) return;
    const blend = 1 - Math.exp(-4 * Math.min(delta, 0.05));
    smoothPointer.current[0] += (pointer.current[0] - smoothPointer.current[0]) * blend;
    smoothPointer.current[1] += (pointer.current[1] - smoothPointer.current[1]) * blend;
    updateAmbientPose(mesh.current, position, speed, index * 0.73, state.clock.elapsedTime, progress.current, smoothPointer.current[0], smoothPointer.current[1]);
  });
  return <mesh ref={mesh} position={position} scale={scale}>
      <icosahedronGeometry args={[1, 0]} />
      <meshStandardMaterial color={color} emissive={color} emissiveIntensity={0.5} roughness={0.42} metalness={0.28} transparent opacity={0.38} depthWrite={false} />
      <mesh scale={1.015}>
        <icosahedronGeometry args={[1, 0]} />
        <meshBasicMaterial color={color} wireframe transparent opacity={0.9} depthWrite={false} />
      </mesh>
    </mesh>;
}

export function VisualStage() {
  const reduceMotion = useReducedMotion();
  const progress = useRef(0);
  const pointer = useRef<[number, number]>([0, 0]);
  const { scrollYProgress } = useScroll();
  useMotionValueEvent(scrollYProgress, 'change', (latest) => { progress.current = latest; });
  useEffect(() => {
    const onPointerMove = (event: PointerEvent) => {
      if (event.pointerType === 'touch') return;
      pointer.current[0] = (event.clientX / Math.max(window.innerWidth, 1) - 0.5) * 2;
      pointer.current[1] = (event.clientY / Math.max(window.innerHeight, 1) - 0.5) * -2;
    };
    window.addEventListener('pointermove', onPointerMove, { passive: true });
    return () => window.removeEventListener('pointermove', onPointerMove);
  }, []);
  if (reduceMotion) return <div className="stage-fallback" aria-hidden="true"><i /><i /><i /></div>;
  return <div className="visual-stage" aria-hidden="true">
    <Canvas dpr={[1, 1.4]} camera={{ position: [0, 0, 9], fov: 40 }} gl={{ alpha: true, antialias: true }}>
      <Suspense fallback={null}>
        <ambientLight intensity={0.9} />
        <pointLight position={[0, 3, 6]} color="#9c71ff" intensity={14} />
        <ResponsiveShards progress={progress} pointer={pointer} />
      </Suspense>
    </Canvas>
  </div>;
}

function ResponsiveShards({ progress, pointer }: { progress: MutableRefObject<number>; pointer: PointerRef }) {
  const { viewport } = useThree();
  const factor = Math.min(1, Math.max(0.28, viewport.width / 13.4));
  const shard = (position: [number, number, number], scale: number, speed: number, color: string, index: number) => (
    <Shard key={index} position={[position[0] * factor, position[1], position[2]]} scale={scale * factor} speed={speed} color={color} index={index} progress={progress} pointer={pointer} />
  );
  return <>
    {shard([4.2, 1.05, -1], 1.85, 0.7, '#8b5cf6', 0)}
    {shard([3.8, -1.4, -1.6], 1.7, 0.48, '#a78bfa', 1)}
    {shard([5.2, 2.7, -2.8], 1.05, 0.38, '#5d4a9a', 2)}
    {shard([2.7, -2.7, -2], 1.1, 0.6, '#6d5ca8', 3)}
  </>;
}
