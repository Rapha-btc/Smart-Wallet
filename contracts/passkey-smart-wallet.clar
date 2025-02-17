;; Convert ASCII string to buffer, ensuring correct handling of optional types
(define-read-only (ascii-to-buff (in (string-ascii 100))) 
    (match (to-consensus-buff? in) 
        some-buff (ok some-buff) ;; Return the buffer if conversion is successful
        err-ascii-to-buff            ;; Return error if conversion fails
    ))


;; Helper to convert principal to buffer format directly
(define-read-only (principal-to-buff (recipient principal))
    (match (to-consensus-buff? recipient)
            buff (slice? buff u5 (len buff)) 
            none)
)

;; Passkey-enabled Smart Wallet
(define-data-var wallet-public-key (optional (buff 33)) none)
(define-constant err-ascii-to-buff (err u400))
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
;; (define-public (transfer-stx-with-passkey 
;;     (amount int) 
;;     (recipient principal)
;;     (timestamp uint)
;;     (signature (buff 64)))
;;     (begin
;;         ;; First handle all our potential response values
;;         (let 
;;             (
;;                 (current-time (unwrap-panic (get-block-info? time (- block-height u1))))
;;                 (principal-buff (unwrap! (principal-to-buff recipient) err-unauthorized))
;;                 ;; Convert message components to buffers for concatenation
;;                 (prefix-buff (unwrap! (ascii-to-buff (var-get prefix)) err-ascii-to-buff))
;;                 (amount-buff (unwrap! (ascii-to-buff (int-to-ascii amount)) err-ascii-to-buff))
;;                 (timestamp-buff (unwrap! (ascii-to-buff (int-to-ascii timestamp)) err-ascii-to-buff))
;;                 ;; Construct message by concatenating buffers
;;                 (message (concat prefix-buff 
;;                                (concat amount-buff
;;                                       (concat principal-buff timestamp-buff))))
;;                 ;; (signature-verified (unwrap! (verify-signature (sha256 message) signature) err-invalid-signature))
;;             )
;;             ;; lets print all of it to verify it: message, sha256 message, signature, current-time, timestamp, amount, recipient
;;             (print {message: message,
;;                     sha256_message: (sha256 message),
;;                     signature: signature,
;;                     current_time: current-time,
;;                     timestamp: timestamp,
;;                     amount: amount,
;;                     recipient: recipient,
;;                     public_key: (unwrap-panic (var-get wallet-public-key)),
;;                     principal-buff: principal-buff,
;;                     prefix-buff: prefix-buff,
;;                     amount-buff: amount-buff,
;;                     timestamp-buff: timestamp-buff})
                    
;;             ;; Do all our checks
;;             (asserts! (not (default-to false (map-get? used-signatures signature))) err-signature-used)
;;             ;; (asserts! (< (- current-time timestamp) EXPIRY_WINDOW) err-expired)
;;             ;; (asserts! signature-verified err-invalid-signature)
;;             ;; Mark signature as used
;;             ;; (map-set used-signatures signature true)
;;             ;; If signature is valid, execute the transfer
;;             (ok true)
;;             ;; (as-contract (stx-transfer? (to-uint amount) tx-sender recipient))
;;         )
;;     ))

(define-public (transfer-stx-with-passkey 
    (amount int) 
    (recipient principal)
    (timestamp uint)
    (signature (buff 64)))
    (begin
        (let 
            (
                (current-time (unwrap-panic (get-block-info? time (- block-height u1))))
                ;; Instead of manual message construction, use tuple
                (message-tuple (tuple 
                    (prefix (var-get prefix))
                    (amount amount)
                    (recipient recipient)
                    (timestamp timestamp)))
                (message (to-consensus-buff? message-tuple))
            )
            (print {
                message_tuple: message-tuple,
                message: message,
                sha256_message: (sha256 (unwrap-panic message)),
                signature: signature,
                current_time: current-time,
                timestamp: timestamp,
                amount: amount,
                recipient: recipient,
                public_key: (unwrap-panic (var-get wallet-public-key))
            })
            
            ;; Do all our checks
            (asserts! (not (default-to false (map-get? used-signatures signature))) err-signature-used)
            (ok true)
        )
    ))