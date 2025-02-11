import React, { useState } from "react";
import {
  startRegistration,
  startAuthentication,
} from "@simplewebauthn/browser";

const PasskeyWallet = () => {
  const [publicKey, setPublicKey] = useState<string | null>(null);
  const [amount, setAmount] = useState<string>("");
  const [recipient, setRecipient] = useState<string>("");

  const registerPasskey = async () => {
    try {
      // Generate challenge on server-side
      const challenge = new Uint8Array(32);
      crypto.getRandomValues(challenge);

      const registrationOptions = {
        challenge,
        rp: {
          name: "Smart Wallet Passkey",
          id: window.location.hostname,
        },
        user: {
          id: crypto.randomUUID(),
          name: "smart-wallet-user",
          displayName: "Smart Wallet User",
        },
        pubKeyCredParams: [
          { alg: -7, type: "public-key" }, // ES256
          { alg: -257, type: "public-key" }, // RS256
        ],
        authenticatorSelection: {
          authenticatorAttachment: "platform",
          requireResidentKey: true,
          userVerification: "required",
        },
      };

      const registration = await startRegistration(registrationOptions);

      // The public key would be stored and used for smart wallet authentication
      setPublicKey(registration.response.publicKey);
      // Here you would call contract to store the public key
      console.log("Public key to store:", registration.response.publicKey);
    } catch (error) {
      console.error("Error registering passkey:", error);
    }
  };

  const signTransfer = async () => {
    try {
      if (!amount || !recipient) {
        alert("Please enter amount and recipient");
        return;
      }

      const timestamp = Math.floor(Date.now() / 1000); // Current Unix timestamp

      // Create the message to sign, including timestamp
      const message = new TextEncoder().encode(
        `transfer:${amount}${recipient}${timestamp}`
      );

      const authOptions = {
        challenge: message, // Use our transfer message as the challenge
        allowCredentials: [
          {
            id: publicKey!,
            type: "public-key",
          },
        ],
        userVerification: "required",
      };

      const authentication = await startAuthentication(authOptions);

      // Here you would call the contract with:
      console.log("Transfer details:", {
        amount: Number(amount),
        recipient,
        timestamp,
        signature: authentication.signature,
      });

      // Clear form after successful signing
      setAmount("");
      setRecipient("");

      return authentication.signature;
    } catch (error) {
      console.error("Error signing transfer:", error);
    }
  };

  return (
    <div className="p-4 max-w-md mx-auto">
      <h2 className="text-2xl font-bold mb-6">Passkey Smart Wallet</h2>

      {!publicKey ? (
        <div className="mb-6">
          <button
            onClick={registerPasskey}
            className="w-full bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600 transition-colors"
          >
            Register Passkey
          </button>
        </div>
      ) : (
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-1">
              Amount (STX)
            </label>
            <input
              type="number"
              value={amount}
              onChange={(e) => setAmount(e.target.value)}
              placeholder="Enter amount"
              className="w-full border p-2 rounded focus:ring-2 focus:ring-blue-500 outline-none"
            />
          </div>

          <div>
            <label className="block text-sm font-medium mb-1">
              Recipient Address
            </label>
            <input
              type="text"
              value={recipient}
              onChange={(e) => setRecipient(e.target.value)}
              placeholder="Enter Stacks address"
              className="w-full border p-2 rounded focus:ring-2 focus:ring-blue-500 outline-none"
            />
          </div>

          <button
            onClick={signTransfer}
            className="w-full bg-green-500 text-white px-4 py-2 rounded hover:bg-green-600 transition-colors"
            disabled={!amount || !recipient}
          >
            Sign Transfer
          </button>
        </div>
      )}

      {publicKey && (
        <div className="mt-4 p-4 bg-gray-100 rounded">
          <p className="text-sm text-gray-600">
            Wallet registered and ready for transactions
          </p>
        </div>
      )}
    </div>
  );
};

export default PasskeyWallet;
