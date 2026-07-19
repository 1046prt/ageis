# Zero-Knowledge Secrets Manager

A cryptographically enforced secrets management infrastructure wherein the server perpetually remains oblivious to plaintext credential material and the derivation parameters requisite for decryption. Every cryptographic operation—envelope encryption, asymmetric key wrapping, authenticated decryption—transpires exclusively within the client boundary, rendering exfiltrated database contents operationally vacuous to adversaries.

---

## Security Postulate

The fundamental invariant: **the server never possesses, processes, or transiently retains the capacity to decrypt stored secrets**. A compromised database yields nothing beyond opaque ciphertext blobs and asymmetrically wrapped Data Encryption Keys that remain indecipherable absent the corresponding private key material, which never traverses the network boundary.

This is not a theoretical aspiration—it is a structural guarantee enforced through envelope encryption with asymmetric key wrapping, where the Data Encryption Key itself exists solely as ciphertext within persistent storage.

---

## Cryptographic Architecture

### Envelope Encryption with Asymmetric Wrapping

Secrets are encrypted using AES-256-GCM with per-operation nonces, providing both confidentiality and tamper-evident integrity verification. The Data Encryption Key (DEK) is a cryptographically random 256-bit value generated per-vault, never derived from human-memorizable material.

For multi-party access, the DEK undergoes ephemeral X25519 key agreement per authorized principal. Each wrapping operation generates an ephemeral keypair, computes a shared secret via elliptic curve Diffie-Hellman, derives a symmetric wrapping key through SHA-256, and encrypts the DEK with AES-256-GCM. The ephemeral private key is zeroed immediately after use, ensuring forward secrecy: revoking a principal's access precludes retrospective DEK recovery even if the principal's prior computation artifacts were compromised.

### Key Derivation

Human-memorizable passphrases are processed through Argon2id with production-grade parameters (256 MiB memory, 4 iterations, 4 parallelism lanes), rendering brute-force attacks computationally infeasible on commodity hardware. Derived master keys exist ephemerally within client process memory and are never transmitted, logged, or persisted.

### State Machine

Each secret traverses a rigorously defined lifecycle:

```
CREATED → ACTIVE ⇄ ROTATION_PENDING → ROTATED → ACTIVE
                              ↘ REVOKED
```

Rotation produces a new ciphertext encrypted under the refreshed DEK while the prior version is archived to an immutable history table, enabling forensic audit without compromising forward secrecy.

---

## Operational Guarantees

### Authentication

The system supports two authentication modalities, either exclusively or conjunctively:

- **Mutual TLS (mTLS)**: Client certificate Common Name serves as the principal identifier. Certificate chain verification against a configurable Certificate Authority establishes cryptographic identity without supplementary token infrastructure.

- **JWT Bearer Tokens**: HMAC-signed JSON Web Tokens with expiration enforcement, revocation support via an in-memory JTI blacklist with configurable TTL, and NotBefore claim validation.

### Authorization

Authorization is structurally enforced at the storage layer. Every vault operation requires a valid, non-revoked access grant—cryptographic proof of delegation established through asymmetric DEK wrapping. The principal identity is extracted exclusively from the authentication layer (mTLS certificate or JWT claim), never from request body parameters, eliminating impersonation vectors.

### Audit Trail

Every consequential operation—vault creation, secret access, grant delegation, revocation—generates an immutable audit log entry capturing principal identity, action classification, resource attribution, and temporal context. The audit subsystem supports granular filtering by principal and action type, with configurable retention policies for compliance adherence.

### Rotation and Revocation

- **Secret Rotation**: Re-encrypts secret material under the current DEK with automatic version incrementation and archival of the predecessor ciphertext. The rotated state transitions back to active, maintaining uninterrupted access for authorized principals.

- **DEK Rotation**: Batch-updates wrapped DEK material across all authorized principals within a transactional boundary, ensuring atomic access continuity. Compromised DEKs are invalidated through cryptographic replacement rather than deletion.

- **Access Revocation**: Revocation is immediate and cryptographically enforced—revoked principals cannot unwrap the DEK, rendering their ciphertext copies permanently indecipherable.

### Expiration

Secrets support configurable time-to-live (TTL) with automatic expiration enforcement. Expired secrets transition to the revoked state without manual intervention, preventing credential staleness from persisting in production environments.

---

## Resilience Characteristics

### Graceful Degradation

The daemon performs orderly shutdown upon receiving termination signals, draining in-flight requests within a configurable timeout window before releasing database resources. This prevents data corruption and client-facing disruptions during deployment rotations or infrastructure scaling events.

### Retry Semantics

The command-line interface implements exponential backoff with configurable retry attempts, ensuring transient network disruptions during continuous integration pipelines do not cascade into build failures.

### Database Durability

SQLite operates in Write-Ahead Logging (WAL) mode with foreign key enforcement, providing concurrent read access while maintaining strict referential integrity. Connection pooling is configured with single-writer semantics to prevent write contention, and automated backup capabilities via `VACUUM INTO` ensure point-in-time recovery.

---

## Security Properties

| Property | Guarantee |
|---|---|
| **Zero-Knowledge Storage** | Server never possesses decryption capability for any stored secret |
| **Forward Secrecy** | Ephemeral key wrapping ensures revoked principals cannot recover prior DEK states |
| **Tamper Detection** | AES-GCM authenticated encryption rejects any ciphertext modification |
| **Key Material Lifecycle** | All intermediate cryptographic material is explicitly zeroed after use |
| **Transport Security** | TLS 1.3 mandatory, with cipher suite restriction to AES-256-GCM and ChaCha20-Poly1305 |
| **Input Validation** | All principal identifiers, key names, and vault names undergo length and character validation |
| **Timing Resistance** | GCM authentication failures return uniform error responses regardless of failure mode |

---

## Threat Model Acknowledgment

### Compromised Server Infrastructure

An adversary with full server access—including memory inspection, filesystem access, and process introspection—obtains ciphertext blobs, wrapped DEKs, and audit logs. Decryption remains impossible without the principal's private key, which exists exclusively within the client boundary.

### Compromised Database

Identical to server compromise: the database contains only encrypted material. The structural guarantee is that no single component in the server-side architecture possesses sufficient material to reconstruct plaintext secrets.

### Compromised CI Runner

The automated pipeline client operates under a constrained trust boundary. Private key material is protected through machine-bound secrets (hardware security modules, TPM-backed storage, or infrastructure-layer injection). The honest limitation: at 3 AM when no human is present, something must hold the unwrap capability. This tradeoff is explicitly documented rather than obfuscated.

### Compromised Private Key

A leaked private key grants the holder access to all DEK-wrapped secrets for the corresponding principal. Mitigation: revocation immediately invalidates the access grant, and DEK rotation invalidates all prior wrapped DEKs for the compromised principal.

---

## Deployment Considerations

### Single-Writer Constraint

SQLite enforces single-writer semantics, serializing all mutation operations. This is architecturally appropriate for a centralized secrets daemon serving a single organizational boundary. For multi-node deployments requiring horizontal write scaling, database migration to a distributed transactional store would be requisite.

### Key Escrow Absence

The zero-knowledge design precludes server-side key recovery. Loss of all principal private keys for a vault renders its secrets permanently irrecoverable. Organizations must implement supplementary key management procedures—hardware security module enrollment, multi-party recovery ceremonies, or escrowed key backup—to mitigate catastrophic key loss scenarios.

---

## License

This software is provided under the MIT License. The cryptographic primitives employed are sourced from audited, well-established libraries. The security guarantees described herein are structural properties of the architecture, not marketing assertions.
