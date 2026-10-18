
import React from "react";
import { motion } from "framer-motion";
import { Lock } from "lucide-react";

const Header = () => {
  return (
    <header className="w-full py-6 px-4 sm:px-6">
      <motion.div 
        className="max-w-7xl mx-auto flex items-center justify-between"
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ 
          duration: 0.8,
          ease: [0.22, 1, 0.36, 1] 
        }}
      >
        <div className="flex items-center space-x-2">
          <span className="text-xl font-semibold tracking-tight">Confidential LLM Chat</span>
          <span className="text-sm text-muted-foreground hidden sm:inline">Qwen2.5 inside an AWS Nitro Enclave</span>
        </div>
        
        <div className="flex items-center space-x-1.5 bg-secondary/50 px-3 py-1.5 rounded-full">
          <Lock className="h-4 w-4 text-primary" />
          <span className="text-sm font-medium text-muted-foreground">
            Trusted Execution Environment
          </span>
        </div>
      </motion.div>
    </header>
  );
};

export default Header;
