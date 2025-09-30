# Customer Feedback

Add your feedback here. Keep it simple - just write what you think.

---

## New Feedback

*(Add new items here)*

- add some option to remove the source file after encryption/decryption. maybe use --inplace or --remove-source flag? not sure about the name.
- a strong security audit is requested ASAP.

---

## Addressed

*(Completed items move here)*

### September 21, 2025 - Roadmap Simplification

- **ROADMAP UPDATED**: the planned directory support for recursive encryption/decryption will never be needed.
  - **Status**: Integrated into roadmap - directory phases removed/postponed
  - **Action**: Focused roadmap on single/multi-file operations instead of directory recursion

### Phase 8.5 Roadmap Integration (September 21, 2025)

- **ROADMAP UPDATED**: the list in cryptls only shows the original filenames but not which obfuscated name corresponds to which original name. so when a user wants to decrypt a specific file they can't tell which obfuscated filename to use. the list should show both the obfuscated filename and the original filename (if it can be decrypted with the provided password). if the original filename can't be decrypted (wrong password or corrupted) it should indicate that as well.
  - **Status**: Integrated into roadmap as Phase 8.5 priority
  - **Action**: Created new priority phase for enhanced cryptls display

- **ROADMAP UPDATED**: overriding files should generally only be allowed with an explicit --force flag
  - **Status**: Integrated into roadmap as Phase 8.5 priority  
  - **Action**: Added --force flag requirement to Phase 8.5 tasks