# Development Instructions

Please follow these instructions exactly to ensure a smooth, efficient, and high-quality development process.
Start by reading the entire document to understand the workflow and expectations.
Then begin the first development cycle immediately, starting with the SYNC phase without asking for further instructions.

## File-Based Workflow
- **docs/BACKLOG.md**: Priority queue of future work (high-level only, keep concise)
- **docs/CURRENT_CYCLE.md**: Active cycle plan and progress
- **docs/CHANGELOG.md**: Completed work history (semantic versioning, relevant changes only)
- **docs/FEEDBACK.md**: User feedback pipeline ("New Feedback" section, process regularly)
- **docs/specs/**: Implementation specifications and architectural blueprints (primary reference)
- **docs/LEGACY_REFERENCE.md**: Guide for using preserved legacy code during clean reimplementation
- **legacy/src/**: Preserved legacy implementation for reference patterns (do not modify)

## 8-Phase Development Cycle

### 1. **SYNC**
**Purpose**: Ensure all documentation reflects current reality
- Verify docs/BACKLOG.md matches actual priorities
- Confirm no orphaned docs/CURRENT_CYCLE.md exists
- **Decision Gate**: If unfinished work exists in docs/CURRENT_CYCLE.md, either complete it or move it back to docs/BACKLOG.md before proceeding

### 2. **INTAKE**
**Purpose**: Process new information into the system
- **docs/FEEDBACK.md → docs/BACKLOG.md**: Integrate new feedback into backlog priorities
- Move processed feedback out of "New Feedback" section
- **Decision Gate**: Stop here if backlog needs major reorganization

### 3. **PLAN**
**Purpose**: Transform backlog item into executable plan
- **docs/BACKLOG.md → docs/CURRENT_CYCLE.md**: Create detailed plan for top priority item
- Include docs, specs and the current state of the codebase as context
- Define success criteria, approach, and validation steps
- Remove selected item from docs/BACKLOG.md (it's now in docs/CURRENT_CYCLE.md)

### 4. **VALIDATE**
**Purpose**: Prove approach before full implementation
- Build proof-of-concept for high-risk elements
- Validate assumptions with quick experiments
- **Decision Gate**: Pivot plan in docs/CURRENT_CYCLE.md if validation fails

### 5. **EXECUTE**
**Purpose**: Implement according to plan with continuous tracking
- Follow test-first development approach
- Update docs/CURRENT_CYCLE.md with progress and discoveries only
- Continuous validation against success criteria
- **Decision Gate**: Assess if another cycle is needed or if work is complete

### 6. **REFACTOR**
**Purpose**: Improve code quality and architecture after successful implementation
**Mandatory Execution**: Execute this phase after every implementation, regardless of size
**Scope**: Apply refactoring to the code implemented in the current cycle plus any related code that can be improved
**Actions**:
- **Roadmap Alignment**: Review `docs/BACKLOG.md` to ensure refactoring decisions support upcoming planned work
- **Architectural Evolution**: Let structure emerge from domain understanding while considering future requirements
- **Inward Pointing**: Ensure all modules and functions point inward toward core domain logic
- **Code Quality & Security**: Improve clarity, eliminate technical debt, enhance security patterns
- **Abstraction Evaluation**: Extract to shared modules only when actual duplication is proven and roadmap supports it
- **Test & Documentation**: Enhance test clarity and ensure code remains self-documenting
**Validation**:
- All tests must continue passing after refactoring
- Code must compile cleanly with no warnings
- Refactoring aligns with and enables roadmap priorities
- Architecture supports both current functionality and planned future work
**Documentation**: Record significant refactoring decisions and roadmap considerations in docs/CURRENT_CYCLE.md

### 7. **REFLECT & ADAPT**
**Purpose**: Incorporate learnings and new insights
**Triggers**: Execute only if any of these occurred:
- Further work is needed to complete original item
- Discovered new work items during implementation
- Found better approaches that affect other backlog items
- Identified technical debt that needs prioritization
- Architectural insights emerged during development
**Actions**:
- Reflect on the current implementation cycle in docs/CURRENT_CYCLE.md
- If further work is needed:
    - Add detailed requirements to docs/FEEDBACK.md with full context, technical details, and rationale
    - Include implementation considerations, root causes, and any architectural insights
    - Let next INTAKE phase process these through normal feedback pipeline (docs/FEEDBACK.md → docs/BACKLOG.md)
    - This preserves rich context that would be lost in high-level backlog items

### 8. **FINALIZE**
**Purpose**: Finalize work and update documentation chain
- **docs/CURRENT_CYCLE.md → docs/CHANGELOG.md**: Archive completed work with semantic versioning
- **Update Cargo.toml version**: Sync package version with changelog version for releases
- Delete docs/CURRENT_CYCLE.md (work is now in docs/CHANGELOG.md)
- **Update README.md** Ensure it only contains essentials and is in sync with latest changes
- **Decision Gate**: Only proceed if all quality gates pass

## Development Philosophy
**Favor Breaking Changes Over Backward Compatibility**
- This project is in early development with no production usage
- **Always implement the best possible solution**, even if it breaks existing functionality
- Backward compatibility is explicitly deprioritized in favor of:
  - Clean, lean codebase architecture
  - Optimal solutions without compromise
  - Elimination of re-export chaos and technical debt
  - Forward-looking design decisions
- Breaking changes are preferred over suboptimal implementations
- Focus on what the codebase should be, not what it was

## Architectural Principles
**Vertical Slicing for Feature-Driven Organization**

Organize code around complete user capabilities rather than technical layers. Architecture should emerge through iterative development guided by user needs and domain boundaries discovered during implementation.

**Core Principles:**
- **User-Centric Boundaries**: Module boundaries align with complete user workflows and capabilities
- **Feature Completeness**: Each slice delivers end-to-end user value with minimal external dependencies
- **Natural Emergence**: Let architecture emerge from domain understanding rather than predetermined technical structures
- **Shared Infrastructure**: Extract to shared modules only when multiple capabilities need identical functionality
- **Independent Evolution**: Different user capabilities can evolve and be deployed independently
- **Testability**: Each capability slice should be testable in isolation with minimal mocking

**Decision Framework:**
- Does this grouping represent a complete user capability?
- Can this feature be developed, tested, and deployed independently?
- Are we extracting shared concerns based on actual duplication, not anticipated reuse?
- Does the module boundary reflect natural domain concepts?
- Would splitting or combining improve clarity and maintainability?

**Guidance for Emergence:**
- Start with user-facing workflows and let technical organization follow
- Prefer clear duplication over premature abstraction
- Refactor toward shared infrastructure only when patterns are proven
- Use specs in `docs/specs/` to guide domain boundary discovery
- Allow architecture to evolve through the development cycle process

## Rewrite Implementation Context
**Critical Context for All Development Cycles**
- **Legacy Code Location**: All previous implementation moved to `legacy/` folder (preserved with git history)
- **Implementation Strategy**: Start from scratch based on `docs/specs/` - only copy/paste from legacy when explicitly needed per specs
- **Primary Guidance**: Use the specs in `docs/specs/**.md` as implementation blueprints
- **Legacy Reference**: When implementing features, check `legacy/src/` for proven patterns and working code but rewrite according to new architecture
- **Testing Approach**: Legacy tests in `legacy/tests/` - create new tests aligned with clean architecture
- **Preserved Patterns**: TLV headers (`legacy/src/shared/header.rs`), config providers, version compatibility - reimplement cleanly
- **Dependencies**: Current `Cargo.toml` already has required dependencies - focus on clean implementation over dependency changes

## Quality Gates
- ✅ Clean compilation, passing tests (unit, integration, end-to-end)
- ✅ Security reviewed, performance validated
- ✅ Architecture reflects user-centric organization with clear domain boundaries
- ✅ Code refactored for quality, maintainability, and performance
- ✅ Documentation updated, changes committed using conventional commits standard
- ✅ Cargo.toml version matches changelog version for releases

## Cycle Optimization
- **2-4 hour cycles** with 1-3 testable outcomes
- **Bulletproof information flow**: Each phase has one clear purpose
- **Decision gates**: Stop and assess before continuing if criteria aren't met
- **Documentation sync**: Information flows cleanly through the file chain
- **Single source of truth**: Work exists in exactly one place at any time
- **Fail fast**: Validate early, pivot quickly when needed
- **Keep files lean**: Remove completed/irrelevant items; focus on current priorities

**Information Flow**: Multiple pathways exist depending on cycle outcomes:

**Primary Flow (Simple Cycle):**
docs/FEEDBACK.md → docs/BACKLOG.md → docs/CURRENT_CYCLE.md → docs/CHANGELOG.md

**Extended Flow (When Additional Work Discovered):**
docs/CURRENT_CYCLE.md → docs/FEEDBACK.md (detailed context) → next cycle's docs/BACKLOG.md → docs/CURRENT_CYCLE.md → docs/CHANGELOG.md

**Entry Points:**
- **User Feedback**: docs/FEEDBACK.md → docs/BACKLOG.md (via INTAKE phase)
- **Discovery During Work**: docs/CURRENT_CYCLE.md → docs/FEEDBACK.md (via REFLECT & ADAPT phase)

**Exit Points:**
- **Completed Work**: docs/CURRENT_CYCLE.md → docs/CHANGELOG.md (via FINALIZE phase)
- **Additional Requirements**: docs/CURRENT_CYCLE.md → docs/FEEDBACK.md + docs/CHANGELOG.md (via REFLECT & ADAPT + FINALIZE phases)

**Mandatory Refactoring**: Every implementation cycle includes a dedicated REFACTOR phase to ensure continuous code quality improvement and technical debt prevention.

**Cycle Restart**: Each new cycle begins with SYNC phase checking current state of docs/BACKLOG.md

**File Hygiene Rules**:
- **docs/BACKLOG.md**: Only future work, remove completed items immediately
- **docs/CHANGELOG.md**: Only significant changes that impact users
- **docs/FEEDBACK.md**: Process "New Feedback" regularly, remove resolved items
- **Cargo.toml**: Keep version field synchronized with changelog for proper release management
- **README.md**: Aesthetic minimalism is key; Written for users; Only essentials, no fluff

**Focus**: Sustainable progress through learning, adaptation, and user value delivery.