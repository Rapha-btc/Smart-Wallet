;; Convert ASCII string to buffer, skipping length prefix
(define-read-only (ascii-to-buff (in (string-ascii 100))) 
    (default-to 0x (match (to-consensus-buff? in) 
        buff (slice? buff u5 (len buff)) 
        none
    ))
)

;; Helper to convert principal to buffer format directly
(define-read-only (principal-to-buff (recipient principal))
    (match (principal-destruct? recipient)
        success 
            (let (
                (hash-bytes (get hash-bytes success))
                (version (get version success))
                (name-opt (get name success))
                ;; Reconstruct the principal
                (constructed (unwrap-panic 
                    (if (is-some name-opt)
                        (principal-construct? version hash-bytes (unwrap-panic name-opt))
                        (principal-construct? version hash-bytes))))
                ;; Convert to buffer and remove prefix
                (principal-buff (unwrap-panic (to-consensus-buff? constructed)))
            )
            (ok (unwrap-panic (slice? principal-buff u2 (len principal-buff)))))
        error (err err-unauthorized) ;; Convert any principal error to our standard uint error
    ))

;; Passkey-enabled Smart Wallet
(define-data-var wallet-public-key (optional (buff 33)) none)
(define-constant err-invalid-signature (err u403))
(define-constant err-unauthorized (err u401))
(define-constant err-signature-used (err u402))
(define-constant err-expired (err u404))
(define-data-var prefix (string-ascii 9) "transfer:")
(define-constant EXPIRY_WINDOW u300) ;; 5 minutes in seconds

;; Track used signatures
(define-map used-signatures (buff 64) bool)

;; Store the public key for the passkey
(define-public (set-wallet-public-key (public-key (buff 33)))
    (begin
        (asserts! (is-none (var-get wallet-public-key)) err-unauthorized)
        (ok (var-set wallet-public-key (some public-key)))
    ))

;; Verify WebAuthn signature
(define-private (verify-signature (message (buff 32)) (signature (buff 64)))
    (ok (let ((stored-key (unwrap-panic (var-get wallet-public-key))))
        (is-eq (secp256k1-verify message signature stored-key) true)
    )))

;; STX transfer with passkey verification
(define-public (transfer-stx-with-passkey 
    (amount int) 
    (recipient principal)
    (timestamp uint)
    (signature (buff 64)))
    (begin
        ;; First handle all our potential response values
        (let 
            (
                (current-time (unwrap-panic (get-block-info? time (- block-height u1))))
                (principal-buff (unwrap! (principal-to-buff recipient) err-unauthorized))
                ;; Convert message components to buffers for concatenation
                (prefix-buff (ascii-to-buff (var-get prefix)))
                (amount-buff (ascii-to-buff (int-to-ascii amount)))
                (timestamp-buff (ascii-to-buff (int-to-ascii timestamp)))
                ;; Construct message by concatenating buffers
                (message (concat prefix-buff 
                               (concat amount-buff
                                      (concat principal-buff timestamp-buff))))
                (signature-verified (unwrap! (verify-signature (sha256 message) signature) err-invalid-signature))
            )
            ;; Do all our checks
            (asserts! (not (default-to false (map-get? used-signatures signature))) err-signature-used)
            (asserts! (< (- current-time timestamp) EXPIRY_WINDOW) err-expired)
            (asserts! signature-verified err-invalid-signature)
            ;; Mark signature as used
            (map-set used-signatures signature true)
            ;; If signature is valid, execute the transfer
            (as-contract (stx-transfer? (to-uint amount) tx-sender recipient))
        )
    ))