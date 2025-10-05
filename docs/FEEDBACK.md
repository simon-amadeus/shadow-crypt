# Customer Feedback

Add your feedback here. Keep it simple - just write what you think.

---

## New Feedback

### Enforcement of Architectural Dependency Flow Directions
it is critical that the direction of dependencies between layers is strictly enforced according to clean architecture principles. This means:
- Domain layer should not depend on any oher layer (infrastructure, application, cli)
- Application layer can depend on domain, but not on infrastructure or cli
- CLI layer can depend on application and domain, but not on infrastructure
- Infrastructure layer can depend on any layer (domain, application, cli)
Maybe use cargo workspaces with crate separation to enforce this at compile time?


### Complete Progress Enhancement Integration
**Context**: Successfully implemented enhanced progress infrastructure with beautiful visual indicators, timing information, and professional formatting. Core implementation is complete and working excellently.

**Remaining Work**: The enhanced progress system needs to be properly integrated into CLI binaries. currently, the CLI binaries are still using the old progress system.
example output:
shadow -o hel*                                                                                                                                                                                          ❌  11:29:03   ─╯
Shadow File Encryption Tool
Algorithm: xchacha20
Input patterns: ["hel.txt", "hello.txt"]
Filename obfuscation: Enabled
✅ CLI parsing complete
✅ Source files will be removed after successful operation
Enter password for encryption:
Confirm password:
[PROGRESS] Checking file format and encryption safety...
[PROGRESS] Reading file contents...
[PROGRESS] Deriving encryption keys...
[PROGRESS] Encrypting file...
[PROGRESS] Creating TLV header...
[PROGRESS] Writing encrypted file...
[PROGRESS] Removing source file...
[PROGRESS] Encryption complete!
[PROGRESS] Checking file format and encryption safety...
[PROGRESS] Reading file contents...
[PROGRESS] Deriving encryption keys...
[PROGRESS] Encrypting file...
[PROGRESS] Creating TLV header...
[PROGRESS] Writing encrypted file...
[PROGRESS] Removing source file...
[PROGRESS] Encryption complete!

🔒 Encryption Complete!
✅ Successfully encrypted 2 files
⏱️  Total time: 13.10477825s
   hel.txt → 645bc610-9d0f-4a23-acc7-35dd872703ba.shadow (125.214709ms)
   hello.txt → 30f09a4d-cb2a-438f-89cc-44e426415f0f.shadow (87.987875ms)

