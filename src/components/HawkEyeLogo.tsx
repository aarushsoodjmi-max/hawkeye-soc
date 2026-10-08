import React from 'react';
import { motion } from 'motion/react';
import hawkEyeLogo from './hawkeye-logo.webp';

interface HawkEyeLogoProps {
  variant?: 'splash' | 'header' | 'sidebar' | 'login' | 'badge' | 'full';
  animated?: boolean;
  animateClockwise?: boolean;
  onAnimationComplete?: () => void;
  className?: string;
  showText?: boolean;
}

export const HawkEyeLogo: React.FC<HawkEyeLogoProps> = ({
  variant = 'full',
  animated,
  animateClockwise = false,
  onAnimationComplete,
  className = '',
  showText = true,
}) => {
  const isSplash = variant === 'splash';
  const isAnimated = animated ?? (isSplash || animateClockwise);

  // The generated HawkEye artwork is now the single source of truth.
  // The existing laser/left-to-right reveal is preserved over the raster artwork.
  return (
    <div
      className={`relative flex items-center justify-center select-none ${className}`}
      aria-label="HawkEye SOC"
    >
      <div
        className="relative w-full overflow-hidden"
        style={{ aspectRatio: showText ? '1664 / 936' : '1 / 1' }}
      >
        <motion.div
          className="absolute inset-0"
          initial={isAnimated ? { clipPath: 'inset(0 100% 0 0)', opacity: 0.2, x: -20 } : false}
          animate={isAnimated ? { clipPath: 'inset(0 0% 0 0)', opacity: 1, x: 0 } : false}
          transition={
            isAnimated
              ? { duration: 1.8, ease: [0.16, 1, 0.3, 1], delay: 0.2 }
              : undefined
          }
        >
          <img
            src={hawkEyeLogo}
            alt="HawkEye SOC"
            className="block h-full w-full object-contain"
            draggable={false}
          />
        </motion.div>

        {isAnimated && (
          <>
            <motion.div
              className="pointer-events-none absolute inset-y-0 left-0 w-[3px] bg-red-500 shadow-[0_0_12px_#ff0033,0_0_30px_#ff0033]"
              initial={{ left: '0%', opacity: 0 }}
              animate={{
                left: ['0%', '0%', '100%'],
                opacity: [0, 1, 1, 0],
              }}
              transition={{
                duration: 1.8,
                ease: [0.16, 1, 0.3, 1],
                delay: 0.2,
              }}
              onAnimationComplete={onAnimationComplete}
            />
            <motion.div
              className="pointer-events-none absolute inset-y-0 left-0 w-px bg-white shadow-[0_0_8px_white]"
              initial={{ left: '0%', opacity: 0 }}
              animate={{
                left: ['0%', '0%', '100%'],
                opacity: [0, 0.9, 0.9, 0],
              }}
              transition={{
                duration: 1.8,
                ease: [0.16, 1, 0.3, 1],
                delay: 0.2,
              }}
            />
          </>
        )}
      </div>
    </div>
  );
};
