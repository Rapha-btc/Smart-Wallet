;; Passkey-enabled Smart Wallet

(define-data-var wallet-public-key (optional (buff 65)) none)
(define-constant err-invalid-signature (err u403))
(define-constant err-unauthorized (err u401))

;; Store the public key for the passkey
(define-public (set-wallet-public-key (public-key (buff 65)))
    (begin
        (asserts! (is-none (var-get wallet-public-key)) err-unauthorized)
        (ok (var-set wallet-public-key (some public-key)))
    ))

;; Verify WebAuthn signature
(define-private (verify-signature (message (buff 32)) (signature (buff 64)) (public-key (buff 65)))
    (is-eq (secp256k1-verify message signature public-key) true))

;; Execute a transaction with passkey signature
(define-public (execute-with-passkey 
    (operation-data (buff 32))
    (signature (buff 64)))
    (let ((stored-key (unwrap! (var-get wallet-public-key) err-unauthorized)))
        (asserts! (verify-signature operation-data signature stored-key) err-invalid-signature)
        ;; If signature is valid, execute the operation
        (ok true)
    ))

;; STX transfer with passkey verification
(define-public (transfer-stx-with-passkey 
    (amount uint) 
    (recipient principal)
    (operation-hash (buff 32))
    (signature (buff 64)))
    (begin
        (try! (execute-with-passkey operation-hash signature))
        (as-contract (stx-transfer? amount tx-sender recipient))
    ))