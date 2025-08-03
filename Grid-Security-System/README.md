# Smart Grid Energy Monitor & Fraud Detection System

A comprehensive blockchain-based smart grid management platform built on Stacks that provides real-time energy consumption monitoring, automated fraud detection, and penalty enforcement across distributed smart meter networks.

## Overview

This smart contract enables utility companies to maintain grid integrity while providing transparent, immutable audit trails for regulatory compliance and consumer protection. The system uses machine learning-based anomaly detection to identify suspicious energy consumption patterns and automatically initiates fraud investigations with penalty assessments.

## Core Features

- **Distributed Smart Meter Management**: Complete lifecycle management of smart meters including registration, activation, and deactivation
- **Real-time Energy Monitoring**: Process and validate energy consumption data with historical tracking
- **Automated Fraud Detection**: ML-based anomaly detection with three severity levels (mild, moderate, critical)
- **Penalty Enforcement**: Automated penalty calculation and collection based on violation severity
- **Multi-stakeholder Access Control**: Role-based permissions for utilities, regulators, and property owners
- **Treasury Management**: Centralized penalty collection and fund management
- **Comprehensive Audit Trail**: Complete transaction history for regulatory compliance

## Architecture

### Data Structures

- **Smart Meter Registry**: Core meter information and status tracking
- **Consumption Data Log**: Historical energy consumption records
- **Fraud Case Registry**: Investigation cases and penalty tracking
- **Utility Operator Registry**: Access control for utility operators
- **Property Owner Assets**: Asset tracking for property owners

### Security Features

- **Role-based Access Control**: Administrator, utility operator, and property owner roles
- **Input Validation**: Comprehensive validation for all parameters
- **Ownership Verification**: Secure meter ownership checks
- **Authorization Guards**: Function-level access control

## Getting Started

### Prerequisites

- Stacks blockchain development environment
- Clarity smart contract development tools
- STX tokens for transaction fees and penalties

### Deployment

1. Deploy the contract to Stacks blockchain
2. The deployer automatically becomes the contract administrator
3. Grant access to utility operators using `grant-operator-access`
4. Begin registering smart meters with `register-smart-meter`

## Usage

### For Contract Administrators

#### Grant Utility Operator Access
```clarity
(contract-call? .smart-grid-contract grant-operator-access 'SP1ABCD...)
```

#### Register New Smart Meter
```clarity
(contract-call? .smart-grid-contract register-smart-meter 
  'SP1PROPERTY-OWNER... 
  "123 Main Street, City, State")
```

#### Withdraw Treasury Funds
```clarity
(contract-call? .smart-grid-contract withdraw-treasury-funds u5000000)
```

### For Utility Operators

#### Process Energy Reading
```clarity
(contract-call? .smart-grid-contract process-consumption-reading u1 u250)
```

### For Property Owners

#### Deactivate Owned Meter
```clarity
(contract-call? .smart-grid-contract deactivate-smart-meter u1)
```

#### Resolve Fraud Case (Pay Penalty)
```clarity
(contract-call? .smart-grid-contract resolve-fraud-case u1)
```

## Anomaly Detection

The system uses baseline consumption patterns to detect anomalies:

### Severity Levels
- **Normal**: Within 50% of baseline consumption
- **Mild**: 50-100% above baseline (1 STX penalty)
- **Moderate**: 100-200% above baseline (5 STX penalty)  
- **Critical**: 200%+ above baseline (10 STX penalty)

### Detection Process
1. Calculate deviation from baseline consumption
2. Classify severity based on thresholds
3. Automatically create fraud case if anomaly detected
4. Assess penalty based on severity level

## API Reference

### Public Functions

#### Administrative Functions
- `grant-operator-access(operator-principal)` - Grant utility operator access
- `revoke-operator-access(operator-principal)` - Revoke utility operator access
- `register-smart-meter(owner-principal, location-address)` - Register new meter
- `withdraw-treasury-funds(amount)` - Withdraw from treasury

#### Operational Functions
- `process-consumption-reading(meter-id, kwh-consumed)` - Process energy reading
- `deactivate-smart-meter(meter-id)` - Deactivate meter
- `reactivate-smart-meter(meter-id)` - Reactivate meter
- `resolve-fraud-case(case-id)` - Resolve fraud case and collect penalty

### Read-Only Functions

#### Data Queries
- `get-meter-details(meter-id)` - Get meter registration details
- `get-consumption-history(meter-id, sequence)` - Get consumption history
- `get-fraud-case-details(case-id)` - Get fraud case information
- `get-system-statistics()` - Get system-wide statistics

#### Verification Functions
- `check-operator-authorization(operator)` - Check operator access
- `get-owner-asset-count(owner)` - Get property owner's meter count
- `verify-meter-ownership(meter-id, claimant)` - Verify meter ownership
- `get-meter-anomaly-score(meter-id)` - Get current anomaly score

## Error Codes

| Code | Description |
|------|-------------|
| 100  | Unauthorized Access |
| 101  | Resource Not Found |
| 102  | Resource Already Exists |
| 103  | Invalid Parameter |
| 104  | Insufficient Funds |
| 105  | Operation Forbidden |
| 106  | Device Offline |
| 107  | Case Already Resolved |
| 108  | Invalid Wallet Address |
| 109  | Ownership Verification Failed |

## Configuration

### System Limits
- Maximum address length: 100 characters
- Minimum energy reading: 1 kWh
- Maximum device ID: 999,999
- Maximum case ID: 999,999

### Penalty Structure
- Mild violation: 1 STX (1,000,000 microSTX)
- Moderate violation: 5 STX (5,000,000 microSTX)
- Critical violation: 10 STX (10,000,000 microSTX)

## Security Considerations

- Only contract administrator can grant/revoke operator access
- Property owners can only manage their own meters
- Utility operators can process readings but cannot modify registrations
- All penalty payments are automatically transferred to contract treasury
- Comprehensive input validation prevents malicious data injection

## Events and Monitoring

The contract maintains comprehensive state tracking for:
- Total registered meters
- Total penalty collections
- System treasury balance
- Next available meter and case IDs
- Per-meter anomaly incident counts