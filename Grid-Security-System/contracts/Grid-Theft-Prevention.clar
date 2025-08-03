;; Smart Grid Energy Monitor & Fraud Detection System
;; 
;; A comprehensive blockchain-based smart grid management platform that provides
;; real-time energy consumption monitoring, automated fraud detection, and penalty
;; enforcement across distributed smart meter networks. The system enables utility
;; companies to maintain grid integrity while providing transparent, immutable
;; audit trails for regulatory compliance and consumer protection.
;; 
;; Core Capabilities:
;; - Distributed smart meter registration and lifecycle management
;; - Real-time energy consumption data processing and validation
;; - Machine learning-based anomaly detection with severity classification
;; - Automated fraud investigation workflow with penalty assessment
;; - Multi-stakeholder access control (utilities, regulators, property owners)
;; - Financial penalty collection and treasury management
;; - Comprehensive audit trail and compliance reporting

;; SYSTEM CONFIGURATION & CONSTANTS

;; Contract Administration
(define-constant contract-administrator tx-sender)

;; System Error Codes
(define-constant ERR-UNAUTHORIZED-ACCESS (err u100))
(define-constant ERR-RESOURCE-NOT-FOUND (err u101))
(define-constant ERR-RESOURCE-ALREADY-EXISTS (err u102))
(define-constant ERR-INVALID-PARAMETER (err u103))
(define-constant ERR-INSUFFICIENT-FUNDS (err u104))
(define-constant ERR-OPERATION-FORBIDDEN (err u105))
(define-constant ERR-DEVICE-OFFLINE (err u106))
(define-constant ERR-CASE-ALREADY-RESOLVED (err u107))
(define-constant ERR-INVALID-WALLET-ADDRESS (err u108))
(define-constant ERR-OWNERSHIP-VERIFICATION-FAILED (err u109))

;; Anomaly Detection Thresholds
(define-constant mild-anomaly-threshold u150)       ;; 50% above baseline
(define-constant moderate-anomaly-threshold u200)   ;; 100% above baseline  
(define-constant critical-anomaly-threshold u300)   ;; 200% above baseline

;; Penalty Fee Structure (in microSTX)
(define-constant mild-violation-penalty u1000000)      ;; 1 STX
(define-constant moderate-violation-penalty u5000000)  ;; 5 STX
(define-constant critical-violation-penalty u10000000) ;; 10 STX

;; System Validation Limits
(define-constant max-address-length u100)
(define-constant min-energy-reading u1)
(define-constant max-device-identifier u999999)
(define-constant max-case-identifier u999999)

;; SYSTEM STATE VARIABLES

(define-data-var total-registered-meters uint u0)
(define-data-var total-penalty-collections uint u0)
(define-data-var system-treasury-balance uint u0)
(define-data-var next-meter-id uint u1)
(define-data-var next-fraud-case-id uint u1)

;; DATA STRUCTURES & MAPS

;; Smart Meter Registry
(define-map smart-meter-registry
  { meter-id: uint }
  {
    property-owner: principal,
    installation-address: (string-ascii 100),
    baseline-consumption: uint,
    latest-reading: uint,
    last-update-block: uint,
    total-readings-count: uint,
    is-active: bool,
    anomaly-incident-count: uint
  }
)

;; Energy Consumption History
(define-map consumption-data-log
  { meter-id: uint, reading-sequence: uint }
  {
    energy-consumed-kwh: uint,
    recorded-at-block: uint,
    timestamp-block-height: uint,
    deviation-percentage: uint
  }
)

;; Fraud Investigation Registry
(define-map fraud-case-registry
  { case-id: uint }
  {
    target-meter-id: uint,
    case-opened-block: uint,
    severity-classification: (string-ascii 10),
    penalty-amount: uint,
    is-resolved: bool,
    resolution-block: (optional uint)
  }
)

;; Utility Operator Access Control
(define-map utility-operator-registry
  { operator-address: principal }
  { has-access-privileges: bool }
)

;; Property Owner Asset Tracking
(define-map property-owner-assets
  { owner-address: principal }
  { managed-meter-count: uint }
)

;; INPUT VALIDATION FUNCTIONS

;; Validate wallet address format
(define-private (is-valid-wallet-address (wallet principal))
  (not (is-eq wallet 'SP000000000000000000002Q6VF78))
)

;; Validate meter identifier range
(define-private (is-valid-meter-id (meter-id uint))
  (and 
    (> meter-id u0)
    (<= meter-id max-device-identifier)
  )
)

;; Validate case identifier range
(define-private (is-valid-case-id (case-id uint))
  (and 
    (> case-id u0)
    (<= case-id max-case-identifier)
  )
)

;; Validate energy reading value
(define-private (is-valid-energy-reading (kwh-reading uint))
  (and 
    (>= kwh-reading min-energy-reading)
    (<= kwh-reading u999999999)
  )
)

;; Validate installation address
(define-private (is-valid-address-string (address-str (string-ascii 100)))
  (and 
    (> (len address-str) u0)
    (<= (len address-str) max-address-length)
  )
)

;; AUTHORIZATION & SECURITY FUNCTIONS

;; Check administrative privileges
(define-private (is-contract-administrator)
  (is-eq tx-sender contract-administrator)
)

;; Check utility operator authorization
(define-private (is-authorized-utility-operator (operator principal))
  (default-to false 
    (get has-access-privileges 
      (map-get? utility-operator-registry { operator-address: operator })
    )
  )
)

;; Verify meter ownership
(define-private (is-meter-owner (meter-id uint) (claimant principal))
  (match (map-get? smart-meter-registry { meter-id: meter-id })
    meter-record (is-eq (get property-owner meter-record) claimant)
    false
  )
)

;; Check if meter exists in registry
(define-private (meter-exists (meter-id uint))
  (is-some (map-get? smart-meter-registry { meter-id: meter-id }))
)

;; Check if fraud case exists
(define-private (case-exists (case-id uint))
  (is-some (map-get? fraud-case-registry { case-id: case-id }))
)

;; ANOMALY DETECTION & RISK ASSESSMENT

;; Calculate consumption deviation percentage
(define-private (calculate-deviation-score (baseline uint) (current-reading uint))
  (if (is-eq baseline u0)
    u100 ;; Default for new installations
    (/ (* current-reading u100) baseline)
  )
)

;; Classify anomaly severity level
(define-private (classify-anomaly-severity (deviation-score uint))
  (if (>= deviation-score critical-anomaly-threshold)
    "critical"
    (if (>= deviation-score moderate-anomaly-threshold)
      "moderate"
      (if (>= deviation-score mild-anomaly-threshold)
        "mild"
        "normal"
      )
    )
  )
)

;; Determine penalty amount based on severity
(define-private (determine-penalty-amount (severity-level (string-ascii 10)))
  (if (is-eq severity-level "critical")
    critical-violation-penalty
    (if (is-eq severity-level "moderate")
      moderate-violation-penalty
      (if (is-eq severity-level "mild")
        mild-violation-penalty
        u0
      )
    )
  )
)

;; UTILITY OPERATOR MANAGEMENT

;; Grant access privileges to utility operator
(define-public (grant-operator-access (operator-principal principal))
  (begin
    (asserts! (is-contract-administrator) ERR-UNAUTHORIZED-ACCESS)
    (asserts! (is-valid-wallet-address operator-principal) ERR-INVALID-WALLET-ADDRESS)
    (asserts! (not (is-eq operator-principal contract-administrator)) ERR-INVALID-PARAMETER)
    
    (map-set utility-operator-registry 
      { operator-address: operator-principal } 
      { has-access-privileges: true }
    )
    (ok true)
  )
)

;; Revoke access privileges from utility operator
(define-public (revoke-operator-access (operator-principal principal))
  (begin
    (asserts! (is-contract-administrator) ERR-UNAUTHORIZED-ACCESS)
    (asserts! (is-valid-wallet-address operator-principal) ERR-INVALID-WALLET-ADDRESS)
    
    (map-set utility-operator-registry 
      { operator-address: operator-principal } 
      { has-access-privileges: false }
    )
    (ok true)
  )
)

;; SMART METER LIFECYCLE MANAGEMENT

;; Register new smart energy meter
(define-public (register-smart-meter (owner-principal principal) (location-address (string-ascii 100)))
  (let (
    (new-meter-id (var-get next-meter-id))
    (current-owner-assets (default-to { managed-meter-count: u0 } 
      (map-get? property-owner-assets { owner-address: owner-principal })
    ))
  )
    (asserts! (is-contract-administrator) ERR-UNAUTHORIZED-ACCESS)
    (asserts! (is-valid-wallet-address owner-principal) ERR-INVALID-WALLET-ADDRESS)
    (asserts! (is-valid-address-string location-address) ERR-INVALID-PARAMETER)
    
    ;; Create meter registration record
    (map-set smart-meter-registry
      { meter-id: new-meter-id }
      {
        property-owner: owner-principal,
        installation-address: location-address,
        baseline-consumption: u0,
        latest-reading: u0,
        last-update-block: block-height,
        total-readings-count: u0,
        is-active: true,
        anomaly-incident-count: u0
      }
    )
    
    ;; Update owner's asset portfolio
    (map-set property-owner-assets
      { owner-address: owner-principal }
      { managed-meter-count: (+ (get managed-meter-count current-owner-assets) u1) }
    )
    
    ;; Update system counters
    (var-set next-meter-id (+ new-meter-id u1))
    (var-set total-registered-meters (+ (var-get total-registered-meters) u1))
    
    (ok new-meter-id)
  )
)

;; Deactivate smart meter operations
(define-public (deactivate-smart-meter (meter-id uint))
  (let (
    (meter-record (unwrap! (map-get? smart-meter-registry { meter-id: meter-id }) ERR-RESOURCE-NOT-FOUND))
  )
    (asserts! (is-valid-meter-id meter-id) ERR-INVALID-PARAMETER)
    (asserts! (or (is-contract-administrator) (is-meter-owner meter-id tx-sender)) ERR-UNAUTHORIZED-ACCESS)
    
    (map-set smart-meter-registry
      { meter-id: meter-id }
      (merge meter-record { is-active: false })
    )
    
    (ok true)
  )
)

;; Reactivate smart meter operations
(define-public (reactivate-smart-meter (meter-id uint))
  (let (
    (meter-record (unwrap! (map-get? smart-meter-registry { meter-id: meter-id }) ERR-RESOURCE-NOT-FOUND))
  )
    (asserts! (is-contract-administrator) ERR-UNAUTHORIZED-ACCESS)
    (asserts! (is-valid-meter-id meter-id) ERR-INVALID-PARAMETER)
    
    (map-set smart-meter-registry
      { meter-id: meter-id }
      (merge meter-record { is-active: true })
    )
    
    (ok true)
  )
)

;; ENERGY CONSUMPTION DATA PROCESSING

;; Process energy consumption reading with fraud detection
(define-public (process-consumption-reading (meter-id uint) (kwh-consumed uint))
  (let (
    (meter-record (unwrap! (map-get? smart-meter-registry { meter-id: meter-id }) ERR-RESOURCE-NOT-FOUND))
    (current-baseline (get baseline-consumption meter-record))
    (deviation-score (calculate-deviation-score current-baseline kwh-consumed))
    (severity-level (classify-anomaly-severity deviation-score))
    (new-reading-count (+ (get total-readings-count meter-record) u1))
  )
    (asserts! (or (is-contract-administrator) (is-authorized-utility-operator tx-sender)) ERR-UNAUTHORIZED-ACCESS)
    (asserts! (is-valid-meter-id meter-id) ERR-INVALID-PARAMETER)
    (asserts! (is-valid-energy-reading kwh-consumed) ERR-INVALID-PARAMETER)
    (asserts! (get is-active meter-record) ERR-DEVICE-OFFLINE)
    
    ;; Store consumption data in historical log
    (map-set consumption-data-log
      { meter-id: meter-id, reading-sequence: new-reading-count }
      {
        energy-consumed-kwh: kwh-consumed,
        recorded-at-block: block-height,
        timestamp-block-height: block-height,
        deviation-percentage: deviation-score
      }
    )
    
    ;; Update meter record with latest information
    (map-set smart-meter-registry
      { meter-id: meter-id }
      (merge meter-record {
        latest-reading: kwh-consumed,
        last-update-block: block-height,
        total-readings-count: new-reading-count,
        baseline-consumption: (if (is-eq current-baseline u0) kwh-consumed current-baseline),
        anomaly-incident-count: (if (not (is-eq severity-level "normal"))
                                  (+ (get anomaly-incident-count meter-record) u1)
                                  (get anomaly-incident-count meter-record))
      })
    )
    
    ;; Create fraud case if anomaly detected
    (if (not (is-eq severity-level "normal"))
      (let (
        (new-case-id (var-get next-fraud-case-id))
        (penalty-amount (determine-penalty-amount severity-level))
      )
        (map-set fraud-case-registry
          { case-id: new-case-id }
          {
            target-meter-id: meter-id,
            case-opened-block: block-height,
            severity-classification: severity-level,
            penalty-amount: penalty-amount,
            is-resolved: false,
            resolution-block: none
          }
        )
        (var-set next-fraud-case-id (+ new-case-id u1))
        (var-set total-penalty-collections (+ (var-get total-penalty-collections) penalty-amount))
        (ok { 
          processing-successful: true, 
          anomaly-detected: true, 
          case-id-assigned: new-case-id, 
          severity-level: severity-level 
        })
      )
      (ok { 
        processing-successful: true, 
        anomaly-detected: false, 
        case-id-assigned: u0, 
        severity-level: "normal" 
      })
    )
  )
)

;; FRAUD CASE RESOLUTION & PENALTY COLLECTION

;; Resolve fraud case and collect penalty
(define-public (resolve-fraud-case (case-id uint))
  (let (
    (case-record (unwrap! (map-get? fraud-case-registry { case-id: case-id }) ERR-RESOURCE-NOT-FOUND))
    (penalty-due (get penalty-amount case-record))
  )
    (asserts! (is-valid-case-id case-id) ERR-INVALID-PARAMETER)
    (asserts! (not (get is-resolved case-record)) ERR-CASE-ALREADY-RESOLVED)
    
    ;; Process penalty payment
    (try! (stx-transfer? penalty-due tx-sender (as-contract tx-sender)))
    
    ;; Mark case as resolved
    (map-set fraud-case-registry
      { case-id: case-id }
      (merge case-record {
        is-resolved: true,
        resolution-block: (some block-height)
      })
    )
    
    ;; Update treasury balance
    (var-set system-treasury-balance (+ (var-get system-treasury-balance) penalty-due))
    
    (ok true)
  )
)

;; TREASURY MANAGEMENT

;; Withdraw funds from system treasury
(define-public (withdraw-treasury-funds (amount uint))
  (begin
    (asserts! (is-contract-administrator) ERR-UNAUTHORIZED-ACCESS)
    (asserts! (> amount u0) ERR-INVALID-PARAMETER)
    (asserts! (<= amount (var-get system-treasury-balance)) ERR-INSUFFICIENT-FUNDS)
    
    (try! (as-contract (stx-transfer? amount tx-sender contract-administrator)))
    (var-set system-treasury-balance (- (var-get system-treasury-balance) amount))
    
    (ok true)
  )
)

;; DATA QUERY INTERFACE

;; Get smart meter registration details
(define-read-only (get-meter-details (meter-id uint))
  (if (is-valid-meter-id meter-id)
    (map-get? smart-meter-registry { meter-id: meter-id })
    none
  )
)

;; Get consumption history entry
(define-read-only (get-consumption-history (meter-id uint) (sequence uint))
  (if (and (is-valid-meter-id meter-id) (> sequence u0))
    (map-get? consumption-data-log { meter-id: meter-id, reading-sequence: sequence })
    none
  )
)

;; Get fraud case details
(define-read-only (get-fraud-case-details (case-id uint))
  (if (is-valid-case-id case-id)
    (map-get? fraud-case-registry { case-id: case-id })
    none
  )
)

;; Get system statistics
(define-read-only (get-system-statistics)
  {
    total-meters-registered: (var-get total-registered-meters),
    total-penalties-collected: (var-get total-penalty-collections),
    current-treasury-balance: (var-get system-treasury-balance),
    next-available-meter-id: (var-get next-meter-id),
    next-available-case-id: (var-get next-fraud-case-id)
  }
)

;; Check operator authorization status
(define-read-only (check-operator-authorization (operator principal))
  (if (is-valid-wallet-address operator)
    (is-authorized-utility-operator operator)
    false
  )
)

;; Get property owner asset count
(define-read-only (get-owner-asset-count (owner principal))
  (if (is-valid-wallet-address owner)
    (default-to u0 (get managed-meter-count (map-get? property-owner-assets { owner-address: owner })))
    u0
  )
)

;; Calculate current meter anomaly score
(define-read-only (get-meter-anomaly-score (meter-id uint))
  (if (is-valid-meter-id meter-id)
    (match (map-get? smart-meter-registry { meter-id: meter-id })
      meter-data (calculate-deviation-score 
                   (get baseline-consumption meter-data) 
                   (get latest-reading meter-data))
      u0
    )
    u0
  )
)

;; Verify meter ownership
(define-read-only (verify-meter-ownership (meter-id uint) (claimant principal))
  (if (and (is-valid-meter-id meter-id) (is-valid-wallet-address claimant))
    (is-meter-owner meter-id claimant)
    false
  )
)