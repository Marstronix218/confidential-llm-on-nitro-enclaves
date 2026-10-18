import React from "react";
import { motion } from "framer-motion";
import { cn } from "@/lib/utils";
import { User, Bot, Lock, AlertTriangle } from "lucide-react";

interface ChatMessageProps {
  role: "user" | "assistant" | "encrypted" | "decrypted";
  content: string;
  timestamp: Date;
  simulated?: boolean;
  isPromptEncryption?: boolean;
}

const roleIcons = {
  user: <User className="h-5 w-5 text-blue-500" />,
  assistant: <Bot className="h-5 w-5 text-violet-500" />,
  encrypted: <Lock className="h-5 w-5 text-orange-500" />,
  decrypted: <Lock className="h-5 w-5 text-green-500" />
};

const ChatMessage: React.FC<ChatMessageProps> = ({ 
  role, 
  content, 
  timestamp, 
  simulated,
  isPromptEncryption // Use the explicitly passed prop
}) => {
  const isEncrypted = role === "encrypted";
  
  // Determine label based on role and encryption type
  const getRoleLabel = () => {
    switch (role) {
      case "user":
        return "You";
      case "assistant":
        return "Assistant";
      case "encrypted":
        return isPromptEncryption ? "Encrypted prompt" : "Encrypted response";
      case "decrypted":
        return "Decrypted";
      default:
        return "Unknown";
    }
  };
  
  const getMessageStyles = () => {
    switch (role) {
      case "user":
        return "bg-blue-50 border-blue-100";
      case "assistant":
        return "bg-white border-gray-100";
      case "encrypted":
        return "bg-orange-50 border-orange-100 font-mono text-xs";
      case "decrypted":
        return "bg-green-50 border-green-100";
      default:
        return "bg-white border-gray-100";
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -20 }}
      transition={{ duration: 0.3 }}
      className={cn(
        "p-4 rounded-lg border shadow-sm mb-4",
        getMessageStyles()
      )}
    >
      <div className="flex items-center space-x-2 mb-2">
        <div className="w-8 h-8 rounded-full bg-gray-100 flex items-center justify-center">
          {roleIcons[role]}
        </div>
        <div className="flex-1">
          <div className="flex items-center space-x-2">
            <p className="text-sm font-medium">{getRoleLabel()}</p>
            {simulated && (
              <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-yellow-100 text-yellow-800">
                <AlertTriangle className="h-3 w-3 mr-1" />
                Simulated
              </span>
            )}
          </div>
          <p className="text-xs text-muted-foreground">
            {timestamp.toLocaleTimeString()}
          </p>
        </div>
      </div>
      
      {isEncrypted ? (
        <pre className="p-3 bg-black/10 rounded overflow-x-auto text-orange-900 text-xs leading-relaxed">
          <code>{content}</code>
        </pre>
      ) : (
        <p className="text-sm leading-relaxed whitespace-pre-wrap">{content}</p>
      )}
    </motion.div>
  );
};

export default ChatMessage;