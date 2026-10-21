// import { toast } from "@/lib/toast";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8501/api";     // chat.py on the control plane
const API_TOKEN = import.meta.env.VITE_API_TOKEN;   // must match API_TOKEN on chat.py when that is set

// Headers sent on every request to chat.py
function apiHeaders(extra?: HeadersInit): HeadersInit {
  return {
    'Content-Type': 'application/json',
    ...(API_TOKEN ? { Authorization: `Bearer ${API_TOKEN}` } : {}),
    ...extra,
  };
}

// Base API request function
async function fetchApi(endpoint: string, options: RequestInit = {}) {
  try {
    const response = await fetch(`${API_BASE_URL}/${endpoint}`, {
      ...options,
      headers: apiHeaders(options.headers),
    });

    if (!response.ok) {
      let message = `Error: ${response.status} ${response.statusText}`;
      try {
        const errorData = await response.json();
        if (errorData.message) message = errorData.message;
      } catch {
        // Not JSON, keep the status text
      }
      throw new Error(message);
    }

    // Safely parse JSON - handle empty responses
    const text = await response.text();
    const data = text ? JSON.parse(text) : {};
    // Some chat.py errors come back with HTTP 200 and an error body
    if (data.status === "error" || data.success === false) {
      throw new Error(data.message || "Request failed");
    }
    return data;
  } catch (error) {
    console.error(`API Error (${endpoint}):`, error);
    throw error;
  }
}

// Key Directory Management
export async function createKeyDirectory() {
  try {
    const result = await fetchApi('create_key_directory');
    return { success: true, message: result.message };
  } catch (error) {
    console.error("Failed to create key directory:", error);
    return { success: false, message: error instanceof Error ? error.message : "Unknown error" };
  }
}

// Result of verifying the enclave's attestation document (see chat.py /api/retrieve_server_key)
export interface Attestation {
  verified: boolean;      // only true for mode "verified": a valid document with the expected, real PCRs
  chain_valid: boolean;   // signature, certificate chain to the AWS root, nonce and key X check out
  pcr0: string | null;
  pcr1: string | null;
  pcr2: string | null;
  mode: "verified" | "skipped" | "debug" | "failed";
  errors?: string[];      // present when a document was checked and failed (mode "failed")
}

// Server Key Retrieval
export async function retrieveServerKey(): Promise<{ success: boolean; message: string; attestation?: Attestation }> {
  try {
    const result = await fetchApi('retrieve_server_key');
    return { success: true, message: result.message, attestation: result.attestation };
  } catch (error) {
    console.error("Failed to retrieve server key:", error);
    return { success: false, message: error instanceof Error ? error.message : "Unknown error" };
  }
}

// Key Generation
export async function generateKey(keyName: string) {
  try {
    const result = await fetchApi('generate_key', {
      method: 'POST',
      body: JSON.stringify({ key_name: keyName }),
    });
    return { success: true, message: result.message };
  } catch (error) {
    console.error(`Failed to generate key ${keyName}:`, error);
    return { success: false, message: error instanceof Error ? error.message : "Unknown error" };
  }
}

// Encrypt Key A
export async function encryptKeyA() {
  try {
    const result = await fetchApi('encrypt_key_a');
    return { success: true, message: result.message };
  } catch (error) {
    console.error("Failed to encrypt Key A:", error);
    return { success: false, message: error instanceof Error ? error.message : "Unknown error" };
  }
}

// Send Encrypted Key A to TEE
export async function sendEncryptedKeyA() {
  try {
    const result = await fetchApi('send_encrypted_key_a');
    return { success: true, message: result.message };
  } catch (error) {
    console.error("Failed to send encrypted Key A:", error);
    return { success: false, message: error instanceof Error ? error.message : "Unknown error" };
  }
}

// Send Public Key B to TEE
export async function sendPublicKeyB() {
  try {
    const result = await fetchApi('send_public_key_b');
    return { success: true, message: result.message };
  } catch (error) {
    console.error("Failed to send public Key B:", error);
    return { success: false, message: error instanceof Error ? error.message : "Unknown error" };
  }
}

// Delete specific key
export async function deleteKey(keyName: string) {
  try {
    const result = await fetchApi('delete_key', {
      method: 'POST',
      body: JSON.stringify({ key_name: keyName }),
    });
    return { success: true, message: result.message };
  } catch (error) {
    console.error(`Failed to delete key ${keyName}:`, error);
    return { success: false, message: error instanceof Error ? error.message : "Unknown error" };
  }
}

// Delete all keys
export async function deleteAllKeys() {
  try {
    const result = await fetchApi('delete_all_keys');
    return { success: true, message: result.message };
  } catch (error) {
    console.error("Failed to delete all keys:", error);
    return { success: false, message: error instanceof Error ? error.message : "Unknown error" };
  }
}

// Chat functions
export interface ChatTurn {
  role: "user" | "assistant";
  content: string;
}

// POST a JSON body to chat.py and return the parsed response, throwing on HTTP errors
async function postJson(endpoint: string, body: unknown, label: string) {
  const res = await fetch(`${API_BASE_URL}/${endpoint}`, {
    method: "POST",
    headers: apiHeaders(),
    body: JSON.stringify(body),
  });

  let data;
  try {
    const text = await res.text();
    data = text ? JSON.parse(text) : {};
  } catch (e) {
    console.error(`Failed to parse ${label} response:`, e);
    throw new Error(`Invalid response from ${label} service`);
  }

  if (!res.ok || data.status === "error" || data.success === false) {
    throw new Error(data.message || `${label} error: ${res.status} ${res.statusText}`);
  }
  return data;
}

// Encrypt the conversation with key A, run it in the enclave, decrypt the answer with key B.
// `messages` is the whole conversation so far; the last element is the new user message.
export async function encryptAndSendPrompt(messages: ChatTurn[]) {
  try {
    // Step 1: Encrypt the conversation with Key A (public)
    const encryptData = await postJson("encrypt_prompt", { messages }, "Encryption");
    const encryptedPrompt: string = encryptData.encrypted_prompt;
    if (!encryptedPrompt) {
      throw new Error(encryptData.message || "Failed to encrypt prompt");
    }

    // Step 2: Run it inside the enclave; the answer comes back encrypted with Key B
    const generateData = await postJson("generate_text", { encrypted_prompt: encryptedPrompt }, "TEE");
    const encryptedResponse: string = generateData.encrypted_response;
    if (!encryptedResponse) {
      throw new Error(generateData.message || "No response from the enclave");
    }

    // Step 3: Decrypt response with Key B (private)
    const decryptData = await postJson("decrypt_response", { encrypted_response: encryptedResponse }, "Decryption");
    if (typeof decryptData.decrypted_response !== "string") {
      throw new Error(decryptData.message || "Failed to decrypt response");
    }

    return {
      success: true,
      encryptedPrompt,
      encryptedResponse,
      decryptedResponse: decryptData.decrypted_response as string,
    };

  } catch (err) {
    console.error("Chat processing error:", err);
    return {
      success: false,
      message: err instanceof Error ? err.message : "Failed to process message",
      encryptedPrompt: "N/A",
      encryptedResponse: "N/A",
      decryptedResponse: "I'm sorry, I couldn't process your message due to a connection issue. Please try again or check your network connection.",
    };
  }
}


// Clear chat history (frontend only)
export async function clearChatHistory() {
  // This is handled in the frontend state, no backend call needed
  return { success: true, message: "Chat history cleared" };
}