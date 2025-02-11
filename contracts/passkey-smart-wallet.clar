;; Passkey-enabled Smart Wallet

(define-data-var wallet-public-key (optional (buff 65)) none)
(define-constant err-invalid-signature (err u403))
(define-constant err-unauthorized (err u401))
(define-constant err-signature-used (err u402))
(define-constant err-expired (err u404))
(define-constant TRANSFER_PREFIX (string-ascii "transfer:"))
(define-constant EXPIRY_WINDOW u300) ;; 5 minutes in seconds

;; Track used signatures
(define-map used-signatures (buff 64) bool)

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
    (timestamp uint)  ;; Add timestamp parameter
    (signature (buff 64)))
    (let 
        (
            (current-time (unwrap-panic (get-block-info? time (- block-height u1))))
            ;; Create the exact message that was signed, now including timestamp
            (amount-buff (uint-to-buff amount))
            (recipient-buff (principal-to-buff recipient))
            (timestamp-buff (uint-to-buff timestamp))
            (message (concat TRANSFER_PREFIX 
                           (concat amount-buff 
                                  (concat recipient-buff timestamp-buff))))
        )
        ;; Check if signature was already used
        (asserts! (not (default-to false (map-get? used-signatures signature))) err-signature-used)
        ;; Check if timestamp is within window
        (asserts! (< (- current-time timestamp) EXPIRY_WINDOW) err-expired)
        ;; Verify signature matches this exact message
        (asserts! (verify-signature message signature) err-invalid-signature)
        ;; Mark signature as used
        (map-set used-signatures signature true)
        ;; If signature is valid, execute the transfer
        (as-contract (stx-transfer? amount tx-sender recipient))
    ))