# Development Instructions

Please follow these instructions exactly to ensure a smooth, efficient, and high-quality development process.
Start by reading the entire document to understand the workflow and expectations.
Then start your first development cycle immediately without asking for further instructions.

## File-Based Workflow
- **docs/BACKLOG.md**: Priority queue of future work (high-level only, keep concise)
- **docs/CURRENT_CYCLE.md**: Active cycle plan and progress
- **docs/CHANGELOG.md**: Completed work history (semantic versioning, relevant changes only)
- **FEEDBACK.md**: User feedback pipeline ("New Feedback" section, process regularly)

## 7-Phase Development Cycle

### 1. **SYNC**
**Purpose**: Ensure all documentation reflects current reality
- Verify docs/BACKLOG.md matches actual priorities
- Confirm no orphaned docs/CURRENT_CYCLE.md exists
- Check git state is clean and up-to-date

### 2. **INTAKE**
**Purpose**: Process new information into the system
- **FEEDBACK.md → docs/BACKLOG.md**: Integrate new feedback into backlog priorities
- Move processed feedback out of "New Feedback" section
- **Decision Gate**: Stop here if backlog needs major reorganization

### 3. **PLAN**
**Purpose**: Transform backlog item into executable plan
- **docs/BACKLOG.md → docs/CURRENT_CYCLE.md**: Create detailed plan for top priority item
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

### 6. **COMPLETE**
**Purpose**: Finalize work and update documentation chain
- **docs/CURRENT_CYCLE.md → docs/CHANGELOG.md**: Archive completed work with semantic versioning
- **Update Cargo.toml version**: Sync package version with changelog version for releases
- Delete docs/CURRENT_CYCLE.md (work is now in docs/CHANGELOG.md)
- **Decision Gate**: Only proceed if all quality gates pass

### 7. **ADAPT** - *Optional*
**Purpose**: Add feedback if new backlog items are required
**Triggers**: Execute only if any of these occurred:
- Discovered new work items during implementation
- Found better approaches that affect other backlog items
- Identified technical debt that needs prioritization
- Architectural insights emerged during development
**Actions**:
- Add new requirements to "New Feedback" section
- Document discoveries as internal feedback items
- Let next INTAKE phase process these through normal feedback pipeline

## Quality Gates
- ✅ Clean compilation, passing tests (unit, integration, end-to-end)
- ✅ Security reviewed, performance validated
- ✅ Architecture supports vertical slicing and future extension
- ✅ Documentation updated, changes committed using conventional commits standard
- ✅ Cargo.toml version matches changelog version for releases

## Git Usage
Follow the [Conventional Commits](https://www.conventionalcommits.org/) standard for all commit messages to enable automated versioning and changelog generation.

## Cycle Optimization
- **2-4 hour cycles** with 1-3 testable outcomes
- **Bulletproof information flow**: Each phase has one clear purpose
- **Decision gates**: Stop and assess before continuing if criteria aren't met
- **Documentation sync**: Information flows cleanly through the file chain
- **Single source of truth**: Work exists in exactly one place at any time
- **Fail fast**: Validate early, pivot quickly when needed
- **Keep files lean**: Remove completed/irrelevant items; focus on current priorities

**Information Flow**: FEEDBACK.md → docs/BACKLOG.md → docs/CURRENT_CYCLE.md → docs/CHANGELOG.md → FEEDBACK.md (closed loop)

**File Hygiene Rules**:
- **docs/BACKLOG.md**: Only future work, remove completed items immediately
- **docs/CHANGELOG.md**: Only significant changes that impact users or architecture
- **FEEDBACK.md**: Process "New Feedback" regularly, archive resolved items
- **Cargo.toml**: Keep version field synchronized with changelog for proper release management

**Focus**: Sustainable progress through learning, adaptation, and user value delivery.