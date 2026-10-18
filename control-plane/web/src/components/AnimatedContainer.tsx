
import React, { ReactNode } from "react";
import { motion } from "framer-motion";
import { cn } from "@/lib/utils";

interface AnimatedContainerProps {
  children: ReactNode;
  className?: string;
  delay?: number;
  animate?: boolean;
}

const variants = {
  hidden: { opacity: 0, y: 20 },
  visible: { 
    opacity: 1, 
    y: 0,
    transition: {
      duration: 0.6,
      ease: [0.22, 1, 0.36, 1]
    }
  }
};

const AnimatedContainer = ({ 
  children, 
  className, 
  delay = 0,
  animate = true
}: AnimatedContainerProps) => {
  return (
    <motion.div
      className={cn("w-full", className)}
      initial={animate ? "hidden" : "visible"}
      animate="visible"
      variants={variants}
      transition={{
        delay: delay,
      }}
    >
      {children}
    </motion.div>
  );
};

export default AnimatedContainer;
