import React, { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { toast } from "@/lib/toast";
import AnimatedContainer from "./AnimatedContainer";
import { 
  FolderPlus, Key, Upload, Trash2, Download, Send, RefreshCw, Check
} from "lucide-react";
import {
  createKeyDirectory,
  retrieveServerKey,
  generateKey,
  sendPublicKeyB,
  encryptKeyA,
  sendEncryptedKeyA,
  deleteKey,
  deleteAllKeys
} from "@/lib/api";

interface KeyManagementProps {
  onClearChat: () => void;
}

const KeyManagement: React.FC<KeyManagementProps> = ({ onClearChat }) => {
  const [isKeyDirCreated, setIsKeyDirCreated] = useState(false);
  const [isServerKeyRetrieved, setIsServerKeyRetrieved] = useState(false);
  const [isKeyAGenerated, setIsKeyAGenerated] = useState(false);
  const [isKeyBGenerated, setIsKeyBGenerated] = useState(false);
  const [isKeyAEncrypted, setIsKeyAEncrypted] = useState(false);
  const [isKeyASent, setIsKeyASent] = useState(false);
  const [isKeyBSent, setIsKeyBSent] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [loadingAction, setLoadingAction] = useState("");

  const handleCreateKeyDirectory = async () => {
    setIsLoading(true);
    setLoadingAction("Creating key directory");
    try {
      const result = await createKeyDirectory();
      if (result.success) {
        setIsKeyDirCreated(true);
        toast.success("Key directory created");
      } else {
        toast.error(result.message);
      }
    } catch (error) {
      toast.error("Failed to create key directory");
      console.error(error);
    } finally {
      setIsLoading(false);
      setLoadingAction("");
    }
  };

  const handleRetrieveServerKey = async () => {
    setIsLoading(true);
    setLoadingAction("Fetching enclave public key");
    try {
      const result = await retrieveServerKey();
      if (result.success) {
        setIsServerKeyRetrieved(true);
        toast.success("Enclave public key retrieved");
      } else {
        toast.error(result.message);
      }
    } catch (error) {
      toast.error("Failed to retrieve enclave public key");
      console.error(error);
    } finally {
      setIsLoading(false);
      setLoadingAction("");
    }
  };

  const handleGenerateKeyA = async () => {
    setIsLoading(true);
    setLoadingAction("Generating key A");
    try {
      const result = await generateKey("key_a");
      if (result.success) {
        setIsKeyAGenerated(true);
        toast.success("Key A generated");
      } else {
        toast.error(result.message);
      }
    } catch (error) {
      toast.error("Failed to generate key A");
      console.error(error);
    } finally {
      setIsLoading(false);
      setLoadingAction("");
    }
  };

  const handleGenerateKeyB = async () => {
    setIsLoading(true);
    setLoadingAction("Generating key B");
    try {
      const result = await generateKey("key_b");
      if (result.success) {
        setIsKeyBGenerated(true);
        toast.success("Key B generated");
      } else {
        toast.error(result.message);
      }
    } catch (error) {
      toast.error("Failed to generate key B");
      console.error(error);
    } finally {
      setIsLoading(false);
      setLoadingAction("");
    }
  };

  const handleEncryptKeyA = async () => {
    setIsLoading(true);
    setLoadingAction("Encrypting key A");
    try {
      const result = await encryptKeyA();
      if (result.success) {
        setIsKeyAEncrypted(true);
        toast.success("Key A encrypted with the enclave public key");
      } else {
        toast.error(result.message);
      }
    } catch (error) {
      toast.error("Failed to encrypt key A");
      console.error(error);
    } finally {
      setIsLoading(false);
      setLoadingAction("");
    }
  };

  const handleSendEncryptedKeyA = async () => {
    setIsLoading(true);
    setLoadingAction("Sending encrypted key A");
    try {
      const result = await sendEncryptedKeyA();
      if (result.success) {
        setIsKeyASent(true);
        toast.success("Encrypted key A sent to the enclave");
      } else {
        toast.error(result.message);
      }
    } catch (error) {
      toast.error("Failed to send encrypted key A");
      console.error(error);
    } finally {
      setIsLoading(false);
      setLoadingAction("");
    }
  };

  const handleSendKeyB = async () => {
    setIsLoading(true);
    setLoadingAction("Sending key B");
    try {
      const result = await sendPublicKeyB();
      if (result.success) {
        setIsKeyBSent(true);
        toast.success("Public key B sent to the enclave");
      } else {
        toast.error(result.message);
      }
    } catch (error) {
      toast.error("Failed to send key B");
      console.error(error);
    } finally {
      setIsLoading(false);
      setLoadingAction("");
    }
  };

  const handleDeleteKeyA = async () => {
    setIsLoading(true);
    setLoadingAction("Deleting key A");
    try {
      const result = await deleteKey("key_a");
      if (result.success) {
        setIsKeyAGenerated(false);
        setIsKeyAEncrypted(false);
        setIsKeyASent(false);
        toast.success("Key A deleted");
      } else {
        toast.error(result.message);
      }
    } catch (error) {
      toast.error("Failed to delete key A");
      console.error(error);
    } finally {
      setIsLoading(false);
      setLoadingAction("");
    }
  };

  const handleDeleteAllKeys = async () => {
    setIsLoading(true);
    setLoadingAction("Deleting all keys");
    try {
      const result = await deleteAllKeys();
      if (result.success) {
        setIsKeyDirCreated(false);
        setIsServerKeyRetrieved(false);
        setIsKeyAGenerated(false);
        setIsKeyBGenerated(false);
        setIsKeyAEncrypted(false);
        setIsKeyASent(false);
        setIsKeyBSent(false);
        toast.success("All keys deleted");
      } else {
        toast.error(result.message);
      }
    } catch (error) {
      toast.error("Failed to delete keys");
      console.error(error);
    } finally {
      setIsLoading(false);
      setLoadingAction("");
    }
  };

  const handleClearChat = () => {
    onClearChat();
    toast.success("Chat history cleared");
  };

  return (
    <div className="h-full flex flex-col bg-sidebar rounded-lg overflow-hidden shadow-subtle">
      <div className="p-4 border-b border-sidebar-border">
        <h2 className="text-xl font-medium tracking-tight">Key Management</h2>
        <p className="text-sm text-muted-foreground mt-1">
          Set up the keys for the secure session
        </p>
      </div>

      <div className="flex-1 overflow-y-auto p-4 space-y-6">
        <AnimatedContainer delay={0.1}>
          <div className="space-y-3">
            <h3 className="text-sm font-medium text-muted-foreground">
              Setup
            </h3>
            <div className="space-y-2">
              <Button
                variant="outline"
                size="sm"
                className="w-full justify-start"
                onClick={handleCreateKeyDirectory}
                disabled={isKeyDirCreated || isLoading}
              >
                {isKeyDirCreated ? (
                  <Check className="h-4 w-4 mr-2 text-green-500" />
                ) : (
                  <FolderPlus className="h-4 w-4 mr-2" />
                )}
                {isLoading && loadingAction === "Creating key directory" ? (
                  <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                ) : null}
                Create key directory
              </Button>

              <Button
                variant="outline"
                size="sm"
                className="w-full justify-start"
                onClick={handleRetrieveServerKey}
                disabled={!isKeyDirCreated || isServerKeyRetrieved || isLoading}
              >
                {isServerKeyRetrieved ? (
                  <Check className="h-4 w-4 mr-2 text-green-500" />
                ) : (
                  <Download className="h-4 w-4 mr-2" />
                )}
                {isLoading && loadingAction === "Fetching enclave public key" ? (
                  <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                ) : null}
                Get enclave public key
              </Button>
            </div>
          </div>
        </AnimatedContainer>

        <Separator />

        <AnimatedContainer delay={0.2}>
          <div className="space-y-3">
            <h3 className="text-sm font-medium text-muted-foreground">
              Key A (prompt encryption)
            </h3>
            <div className="space-y-2">
              <Button
                variant="outline"
                size="sm"
                className="w-full justify-start"
                onClick={handleGenerateKeyA}
                disabled={!isServerKeyRetrieved || isKeyAGenerated || isLoading}
              >
                {isKeyAGenerated ? (
                  <Check className="h-4 w-4 mr-2 text-green-500" />
                ) : (
                  <Key className="h-4 w-4 mr-2" />
                )}
                {isLoading && loadingAction === "Generating key A" ? (
                  <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                ) : null}
                Generate key A
              </Button>

              <AnimatePresence>
                {isKeyAGenerated && (
                  <motion.div
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: "auto" }}
                    exit={{ opacity: 0, height: 0 }}
                    transition={{ duration: 0.2 }}
                    className="space-y-2"
                  >
                    <Button
                      variant="outline"
                      size="sm"
                      className="w-full justify-start"
                      onClick={handleEncryptKeyA}
                      disabled={!isKeyAGenerated || isKeyAEncrypted || isLoading}
                    >
                      {isKeyAEncrypted ? (
                        <Check className="h-4 w-4 mr-2 text-green-500" />
                      ) : (
                        <Key className="h-4 w-4 mr-2" />
                      )}
                      {isLoading && loadingAction === "Encrypting key A" ? (
                        <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                      ) : null}
                      Encrypt private key A
                    </Button>

                    <Button
                      variant="outline"
                      size="sm"
                      className="w-full justify-start"
                      onClick={handleSendEncryptedKeyA}
                      disabled={!isKeyAEncrypted || isKeyASent || isLoading}
                    >
                      {isKeyASent ? (
                        <Check className="h-4 w-4 mr-2 text-green-500" />
                      ) : (
                        <Send className="h-4 w-4 mr-2" />
                      )}
                      {isLoading && loadingAction === "Sending encrypted key A" ? (
                        <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                      ) : null}
                      Send encrypted key A to enclave
                    </Button>

                    <Button
                      variant="outline"
                      size="sm"
                      className="w-full justify-start text-destructive hover:text-destructive"
                      onClick={handleDeleteKeyA}
                      disabled={!isKeyAGenerated || isLoading}
                    >
                      <Trash2 className="h-4 w-4 mr-2" />
                      {isLoading && loadingAction === "Deleting key A" ? (
                        <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                      ) : null}
                      Delete private key A
                    </Button>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          </div>
        </AnimatedContainer>

        <Separator />

        <AnimatedContainer delay={0.3}>
          <div className="space-y-3">
            <h3 className="text-sm font-medium text-muted-foreground">
              Key B (response encryption)
            </h3>
            <div className="space-y-2">
              <Button
                variant="outline"
                size="sm"
                className="w-full justify-start"
                onClick={handleGenerateKeyB}
                disabled={!isServerKeyRetrieved || isKeyBGenerated || isLoading}
              >
                {isKeyBGenerated ? (
                  <Check className="h-4 w-4 mr-2 text-green-500" />
                ) : (
                  <Key className="h-4 w-4 mr-2" />
                )}
                {isLoading && loadingAction === "Generating key B" ? (
                  <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                ) : null}
                Generate key B
              </Button>

              <AnimatePresence>
                {isKeyBGenerated && (
                  <motion.div
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: "auto" }}
                    exit={{ opacity: 0, height: 0 }}
                    transition={{ duration: 0.2 }}
                    className="space-y-2"
                  >
                    <Button
                      variant="outline"
                      size="sm"
                      className="w-full justify-start"
                      onClick={handleSendKeyB}
                      disabled={!isKeyBGenerated || isKeyBSent || isLoading}
                    >
                      {isKeyBSent ? (
                        <Check className="h-4 w-4 mr-2 text-green-500" />
                      ) : (
                        <Upload className="h-4 w-4 mr-2" />
                      )}
                      {isLoading && loadingAction === "Sending key B" ? (
                        <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                      ) : null}
                      Send public key B to enclave
                    </Button>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          </div>
        </AnimatedContainer>

        <Separator />

        <AnimatedContainer delay={0.4}>
          <div className="space-y-3">
            <h3 className="text-sm font-medium text-muted-foreground">
              Cleanup
            </h3>
            <div className="space-y-2">
              <Button
                variant="outline"
                size="sm"
                className="w-full justify-start text-destructive hover:text-destructive"
                onClick={handleDeleteAllKeys}
                disabled={!isKeyDirCreated || isLoading}
              >
                <Trash2 className="h-4 w-4 mr-2" />
                {isLoading && loadingAction === "Deleting all keys" ? (
                  <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                ) : null}
                Delete all keys
              </Button>

              <Button
                variant="outline"
                size="sm"
                className="w-full justify-start"
                onClick={handleClearChat}
                disabled={isLoading}
              >
                <RefreshCw className="h-4 w-4 mr-2" />
                Clear chat history
              </Button>
            </div>
          </div>
        </AnimatedContainer>
      </div>

      {isLoading && (
        <div className="p-4 border-t border-sidebar-border bg-muted/50">
          <div className="flex items-center">
            <RefreshCw className="h-4 w-4 mr-2 animate-spin text-blue-500" />
            <p className="text-sm text-muted-foreground">{loadingAction}...</p>
          </div>
        </div>
      )}
    </div>
  );
};

export default KeyManagement;