import React, { useState, useEffect, useRef } from "react";
import { motion } from "framer-motion";
import Header from "@/components/Header";
import KeyManagement from "@/components/KeyManagement";
import ChatInterface, { ChatInterfaceRef } from "@/components/ChatInterface";
import { toast } from "@/lib/toast";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { InfoIcon } from "lucide-react";

const Index = () => {
  const [isChatReady, setIsChatReady] = useState(true); // Always true to allow immediate chat
  const isDevelopment = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';
  const chatInterfaceRef = useRef<ChatInterfaceRef>(null);
  
  // Simulate checking if keys are set up correctly
  useEffect(() => {
    // In a real app, this would check the key status from the backend
    // For now, we'll just have KeyManagement component manage this
    
    // Show environment information
    if (!isDevelopment) {
      toast.info("Using a remote API server");
    }
  }, [isDevelopment]);
  
  const handleClearChat = () => {
    // Clear messages in ChatInterface component
    if (chatInterfaceRef.current) {
      chatInterfaceRef.current.clearAllMessages();
    }
    toast.success("Chat history cleared");
  };

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.5 }}
      className="min-h-screen bg-gradient-to-b from-gray-50 to-gray-100"
    >
      <Header />
      
      <main className="container mx-auto py-6 px-4">
        {!isDevelopment && (
          <Alert className="mb-4">
            <InfoIcon className="h-4 w-4 mr-2" />
            <AlertDescription>
              This demo is talking to a remote API server.
            </AlertDescription>
          </Alert>
        )}
        
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6 mt-4">
          <motion.div
            initial={{ x: -20, opacity: 0 }}
            animate={{ x: 0, opacity: 1 }}
            transition={{ duration: 0.5, delay: 0.2 }}
            className="lg:col-span-1"
          >
            <KeyManagement onClearChat={handleClearChat} />
          </motion.div>
          
          <motion.div
            initial={{ x: 20, opacity: 0 }}
            animate={{ x: 0, opacity: 1 }}
            transition={{ duration: 0.5, delay: 0.3 }}
            className="lg:col-span-3 bg-white rounded-lg shadow-subtle overflow-hidden h-[calc(100vh-11rem)]"
          >
            <ChatInterface 
              readyToChat={isChatReady} 
              ref={chatInterfaceRef}
            />
          </motion.div>
        </div>
      </main>
    </motion.div>
  );
};

export default Index;