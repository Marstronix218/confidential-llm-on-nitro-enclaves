import React, { useState, useRef, useEffect, forwardRef, useImperativeHandle } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { toast } from "@/lib/toast";
import { Send, RefreshCw, Lock } from "lucide-react";
import ChatMessage from "./ChatMessage";
import ProcessingStep from "./ProcessingStep";
import { encryptAndSendPrompt } from "@/lib/api";
import AnimatedContainer from "./AnimatedContainer";

export interface Message {
  role: "user" | "assistant" | "encrypted" | "decrypted";
  content: string;
  timestamp: Date;
  simulated?: boolean;
  isPromptEncryption?: boolean;
}

interface ChatInterfaceProps {
  readyToChat: boolean;
}

export type ChatInterfaceRef = {
  clearAllMessages: () => void;
};

const ChatInterface = forwardRef<ChatInterfaceRef, ChatInterfaceProps>(({ readyToChat }, ref) => {
  const [messages, setMessages] = useState<Message[]>([]);
  const [inputValue, setInputValue] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [currentStep, setCurrentStep] = useState(0);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  // Expose the clearAllMessages method via ref
  useImperativeHandle(ref, () => ({
    clearAllMessages: () => {
      setMessages([]);
    }
  }));

  // Add a welcome message when the component loads or messages are cleared
  useEffect(() => {
    if (messages.length === 0) {
      setMessages([
        {
          role: "assistant",
          content: "Hello! I'm your secure TEE-protected assistant. How can I help you today?",
          timestamp: new Date(),
          simulated: false
        }
      ]);
    }
  }, [messages]);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const handleSendMessage = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputValue.trim()) return;
  
    if (!readyToChat) {
      toast.error("Complete the key setup before chatting");
      return;
    }
  
    const userMessage: Message = {
      role: "user",
      content: inputValue,
      timestamp: new Date()
    };
  
    setMessages((prev) => [...prev, userMessage]);
    setInputValue("");
    setIsLoading(true);
    setCurrentStep(1); // Step 1: show encryption in progress
  
    try {
      const response = await encryptAndSendPrompt(inputValue);
  
      // Step 2: show the encrypted prompt
      const encryptedPromptMessage: Message = {
        role: "encrypted",
        content: response.encryptedPrompt,
        timestamp: new Date(),
        simulated: !response.success,
        isPromptEncryption: true
      };
      setMessages((prev) => [...prev, encryptedPromptMessage]);
  
      // Advance through the remaining steps with short delays for the visualization
      setTimeout(() => {
        setCurrentStep(2); // Step 2: send prompt to the enclave
  
        setTimeout(() => {
          setCurrentStep(3); // Step 3: decrypt inside the enclave
  
          setTimeout(() => {
            setCurrentStep(4); // Step 4: generate response inside the enclave
  
            setTimeout(() => {
              setCurrentStep(5); // Step 5: encrypt response with key B

              // Step 6: show the encrypted response
              const encryptedResponseMessage: Message = {
                role: "encrypted",
                content: response.encryptedResponse,
                timestamp: new Date(),
                simulated: !response.success,
                isPromptEncryption: false
              };
              setMessages((prev) => [...prev, encryptedResponseMessage]);
  
              setTimeout(() => {
                setCurrentStep(6); // Step 6: decrypt response with private key B
  
                setTimeout(() => {
                  // Step 7: show the decrypted response
                  const assistantMessage: Message = {
                    role: "assistant",
                    content: response.decryptedResponse,
                    timestamp: new Date(),
                    simulated: !response.success
                  };
                  setMessages((prev) => [...prev, assistantMessage]);
    
                  if (!response.success) {
                    toast.error(response.message || "Failed to process the message");
                  }

                  setIsLoading(false);
                  setCurrentStep(7);
                }, 3000);

              }, 1600);
  
            }, 800);
  
          }, 3000);
  
        }, 1600);
  
      }, 1600);
  
    } catch (error) {
      console.error("Error sending message:", error);
      const encryptedMessage: Message = {
        role: "encrypted",
        content: "[0x8f, 0x3a, ...]",
        timestamp: new Date(),
        simulated: true,
        isPromptEncryption: true
      };
      const encryptedResponseMessage: Message = {
        role: "encrypted",
        content: "[0xc4, 0x7b, ...]",
        timestamp: new Date(),
        simulated: true,
        isPromptEncryption: false
      };
      const errorMessage: Message = {
        role: "assistant",
        content: "Sorry, the message could not be processed due to a technical error.",
        timestamp: new Date(),
        simulated: true
      };
      setMessages((prev) => [...prev, encryptedMessage, encryptedResponseMessage, errorMessage]);
      toast.error("An error occurred while sending the message.");
      setCurrentStep(6);
      setIsLoading(false);
    }
  };
  

  return (
    <div className="flex flex-col h-full">
      <div className="p-4 border-b">
        <h2 className="text-xl font-medium tracking-tight">Secure Chat</h2>
        <p className="text-sm text-muted-foreground mt-1">
          Encrypted end to end between you and the enclave
        </p>
      </div>

      <div className="flex-1 overflow-hidden grid grid-cols-3 gap-4 p-4">
        <div className="col-span-2 flex flex-col h-full overflow-hidden">
          <div className="flex-1 overflow-y-auto pr-2">
            <AnimatePresence>
              {messages.length === 0 && (
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  className="h-full flex flex-col items-center justify-center text-center p-6"
                >
                  <div className="w-16 h-16 mb-4 rounded-full bg-blue-50 flex items-center justify-center">
                    <Lock className="w-8 h-8 text-blue-500" />
                  </div>
                  <h3 className="text-lg font-medium mb-2">Secure Enclave Chat</h3>
                  <p className="text-muted-foreground text-sm max-w-md">
                    Messages are RSA-encrypted and processed inside a Trusted Execution Environment, so the host never sees plaintext.
                  </p>
                </motion.div>
              )}
            </AnimatePresence>

            {messages.map((message, index) => (
              <ChatMessage
                key={index}
                role={message.role}
                content={message.content}
                timestamp={message.timestamp}
                simulated={message.simulated}
                isPromptEncryption={message.isPromptEncryption}
              />
            ))}
            <div ref={messagesEndRef} />
          </div>

          <form onSubmit={handleSendMessage} className="mt-4 flex space-x-2">
            <Input
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              placeholder="Type a message..."
              disabled={isLoading}
              className="flex-1"
            />
            <Button 
              type="submit" 
              disabled={isLoading || !inputValue.trim()}
            >
              {isLoading ? (
                <RefreshCw className="h-4 w-4 animate-spin" />
              ) : (
                <Send className="h-4 w-4" />
              )}
              <span className="ml-2">Send</span>
            </Button>
          </form>
        </div>

        <AnimatedContainer className="h-full bg-white rounded-lg border p-4 overflow-y-auto">
          <h3 className="text-sm font-medium mb-3">Message flow</h3>
          
          <div className="space-y-1">
            <ProcessingStep
              step={1}
              currentStep={currentStep}
              text="Encrypt prompt with public key A"
              isCompleted={currentStep > 1}
            />
            
            <ProcessingStep
              step={2}
              currentStep={currentStep}
              text="Send encrypted prompt to the enclave"
              isCompleted={currentStep > 2}
            />
            
            <ProcessingStep
              step={3}
              currentStep={currentStep}
              text="Decrypt prompt inside the enclave with private key A"
              isCompleted={currentStep > 3}
            />
            
            <ProcessingStep
              step={4}
              currentStep={currentStep}
              text="Generate response inside the enclave"
              isCompleted={currentStep > 4}
            />
            
            <ProcessingStep
              step={5}
              currentStep={currentStep}
              text="Encrypt response with public key B"
              isCompleted={currentStep > 5}
            />
            
            <ProcessingStep
              step={6}
              currentStep={currentStep}
              text="Decrypt response with private key B"
              isCompleted={currentStep > 6}
            />

            <ProcessingStep
              step={7}
              currentStep={currentStep}
              text="Done"
              isCompleted={currentStep > 6}
            />
          </div>
        </AnimatedContainer>
      </div>
    </div>
  );
});

ChatInterface.displayName = "ChatInterface";

export default ChatInterface;