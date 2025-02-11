import React, { useState, useEffect } from "react";
import {
  startAuthentication,
  startRegistration,
} from "@simplewebauthn/browser";

const PasskeyWallet = () => {
  const [publicKey, setPublicKey] = useState(null);

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
    } catch (error) {
      console.error("Error registering passkey:", error);
    }
  };

  const authenticateWithPasskey = async () => {
    try {
      const authOptions = {
        challenge: new Uint8Array(32),
        allowCredentials: [
          {
            id: publicKey,
            type: "public-key",
          },
        ],
        userVerification: "required",
      };

      const authentication = await startAuthentication(authOptions);
      // Use this signature for smart wallet operations
      return authentication.signature;
    } catch (error) {
      console.error("Error authenticating:", error);
    }
  };

  return (
    <div className="p-4">
      <h2 className="text-xl font-bold mb-4">Passkey Smart Wallet</h2>
      <div className="space-y-4">
        <button
          onClick={registerPasskey}
          className="bg-blue-500 text-white px-4 py-2 rounded"
        >
          Register Passkey
        </button>
        <button
          onClick={authenticateWithPasskey}
          className="bg-green-500 text-white px-4 py-2 rounded"
          disabled={!publicKey}
        >
          Authenticate Operation
        </button>
      </div>
    </div>
  );
};

export default PasskeyWallet;
