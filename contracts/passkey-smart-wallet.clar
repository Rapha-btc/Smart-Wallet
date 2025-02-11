;; Passkey-enabled Smart Wallet

(define-data-var wallet-public-key (optional (buff 65)) none)
(define-constant err-invalid-signature (err u403))
(define-constant err-unauthorized (err u401))
(define-constant TRANSFER_PREFIX (string-ascii "transfer:"))

;; Store the public key for the passkey
(define-public (set-wallet-public-key (public-key (buff 65)))
    (begin
        (asserts! (is-none (var-get wallet-public-key)) err-unauthorized)
        (ok (var-set wallet-public-key (some public-key)))
    ))

;; Verify WebAuthn signature
(define-private (verify-signature (message (buff 32)) (signature (buff 64)))
    (let ((stored-key (unwrap! (var-get wallet-public-key) err-unauthorized)))
        (is-eq (secp256k1-verify message signature stored-key) true)
    ))

;; STX transfer with passkey verification
(define-public (transfer-stx-with-passkey 
    (amount uint) 
    (recipient principal)
    (signature (buff 64)))
    (let 
        (
            ;; Create the exact message that was signed
            (amount-buff (uint-to-buff amount))
            (recipient-buff (principal-to-buff recipient))
            (message (concat TRANSFER_PREFIX 
                           (concat amount-buff recipient-buff)))
        )
        ;; Verify signature matches this exact message
        (asserts! (verify-signature message signature) err-invalid-signature)
        ;; If signature is valid, execute the transfer
        (as-contract (stx-transfer? amount tx-sender recipient))
    ))