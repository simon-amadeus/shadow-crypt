# Customer Feedback

Add your feedback here. Keep it simple - just write what you think.

---

## New Feedback

### **V1/V2 Deprecation Work - Additional Requirements Found**

**Context:** Started v1/v2 header deprecation to clean up codebase and rename v3 to v1. Made significant progress but uncovered additional complexity requiring systematic completion.

**Technical Details Found:**
- **File Corruption Issues**: `versions/dispatch.rs` got corrupted during large-scale replacements, requires careful manual recreation
- **Extensive V1/V2 References**: Multiple critical files still contain v1/v2 logic:
  - `encryption/encrypt_file.rs` - HeaderV2 creation and V1 filename auth
  - `decryption/decrypt_file.rs` - HeaderV2 parsing and V1 filename auth  
  - `shared/header.rs` - V1 header core imports
  - Multiple test files likely affected
- **Missing Module Dependencies**: Removed v1 filename_auth module but many files still depend on it
- **Integration Test Impact**: Tests likely need updating for V3-only operation

**Implementation Considerations:**
- **File-by-File Approach**: Each affected file needs careful analysis and V3-only replacement
- **Test Strategy**: Full test suite validation needed after each major file update
- **Incremental Progress**: Work should be broken into smaller, validated steps
- **V3 Renaming**: Once cleanup complete, systematic V3->V1 renaming while preserving architecture

**Root Cause Analysis:**
- Original estimate underestimated interconnected nature of version system
- Large-scale text replacements caused file corruption
- Missing comprehensive dependency mapping before starting removal

**Architectural Insights:**
- Version system is more tightly coupled than initially assessed
- V1/V2 removal impacts encryption, decryption, and file listing subsystems
- Need systematic approach to avoid breaking working V3 functionality