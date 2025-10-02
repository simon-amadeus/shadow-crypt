# Customer Feedback

Add your feedback here. Keep it simple - just write what you think.

---

## New Feedback

- **XChaCha20 Configuration Integration**: The new configuration trait system should be extended to XChaCha20-Poly1305 algorithm for consistency. Currently only AES-GCM uses the new traits, creating an inconsistent developer experience.

- **Test File Migration for Consistency**: Many existing test files still manually inject `Argon2Params::test_params()` instead of using the new configuration provider patterns. This creates maintenance burden and inconsistent testing approaches.

- **CLI Configuration Injection Opportunity**: The successful trait-based configuration pattern could improve CLI argument processing by allowing dependency injection of configuration providers instead of hardcoded parameter creation.

## Processed Feedback

- **Algorithm Configuration Review** (Processed 2024-10-02): Review current code for refactoring needs - algorithm selection and configuration appear too concrete, argon2params and configs are poorly injected (became apparent in tests) → COMPLETED as v0.28.0 configuration architecture refactoring