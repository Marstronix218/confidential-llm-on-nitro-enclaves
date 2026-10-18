import React, { useEffect, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { cn } from "@/lib/utils";
import { Loader2 } from "lucide-react";

interface ProcessingStepProps {
  step: number;
  currentStep: number;
  text: string;
  isCompleted: boolean;
}

const ProcessingStep: React.FC<ProcessingStepProps> = ({
  step,
  currentStep,
  text,
  isCompleted
}) => {
  const [visible, setVisible] = useState(false);
  
  useEffect(() => {
    if (currentStep >= step) {
      setVisible(true);
    } else {
      setVisible(false);
    }
  }, [currentStep, step]);

  return (
    <AnimatePresence>
      {visible && (
        <motion.div
          key={`step-${step}`}
          initial={{ opacity: 0, y: 10, height: 0 }}
          animate={{ opacity: 1, y: 0, height: "auto" }}
          exit={{ opacity: 0, height: 0 }}
          transition={{ duration: 0.3, ease: "easeInOut" }}
          className={cn(
            "flex items-center space-x-3 py-2 px-3 rounded-md",
            currentStep === step && !isCompleted ? "bg-blue-50" : "",
            isCompleted ? "text-green-600" : "text-blue-600"
          )}
        >
          <div className="relative flex-shrink-0">
            {!isCompleted && currentStep === step ? (
              <Loader2 className="h-5 w-5 animate-spin" />
            ) : (
              <div className={cn(
                "h-5 w-5 rounded-full flex items-center justify-center",
                isCompleted ? "bg-green-100" : "bg-blue-100"
              )}>
                <span className="text-xs font-medium">{step}</span>
              </div>
            )}
          </div>
          <span className="text-sm">{text}</span>
        </motion.div>
      )}
    </AnimatePresence>
  );
};

export default ProcessingStep;