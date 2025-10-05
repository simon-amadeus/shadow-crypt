# Architecture Essentials

> **Vision**: A screaming architecture that makes system intent immediately visible through principled layering, dependency inversion, and feature-driven organization.

## Core Principles

1. **Dependencies flow inward only** (Dependency Rule)
2. **All abstractions live in Core** (Interface Segregation)
3. **Features organize vertically** (Feature Cohesion)
4. **Composition happens at edges** (Composition Root)
5. **Pure functions preferred** (Functional Core, Imperative Shell)

## Layer Architecture

**Dependency Flow**: `Binaries → Infrastructure → Application → Core`

```
┌─────────────────────────────────┐
│         Binary Layer            │
│    Composition Root & CLI       │
└─────────────────────────────────┘
                ↓
┌─────────────────────────────────┐
│      Infrastructure Layer       │
│   External System Adapters      │
└─────────────────────────────────┘
                ↓
┌─────────────────────────────────┐
│      Application Layer          │
│    Workflow Orchestration       │
└─────────────────────────────────┘
                ↓
┌─────────────────────────────────┐
│        Core Layer               │
│   Pure Business Logic           │
└─────────────────────────────────┘
```

## Layer Responsibilities

### Core Layer (Pure Domain)
- **Purpose**: Pure business logic with zero external dependencies
- **Contains**: Domain entities, business rules, ALL abstractions
- **Dependencies**: None (pure)
- **Quality Gate**: 100% test coverage, no I/O operations

```rust
// All abstractions defined here
pub trait Repository {
    fn save(&self, entity: &Entity) -> Result<(), Self::Error>;
}

// Pure domain services
pub struct DomainService;
impl DomainService {
    pub fn validate(&self, entity: &Entity) -> Result<(), DomainError> {
        // Pure business logic only
    }
}
```

### Application Layer (Orchestration)
- **Purpose**: Orchestrates Core services into complete workflows
- **Contains**: Use case implementations, cross-cutting concerns
- **Dependencies**: Core abstractions only
- **Quality Gate**: 95% test coverage, no direct I/O

```rust
pub struct Workflow<R: Repository> {
    repository: R,
    domain_service: DomainService,
}

impl<R: Repository> Workflow<R> {
    pub fn execute(&self, input: Input) -> Result<Output, WorkflowError> {
        let validated = self.domain_service.validate(input)?;
        let entity = self.repository.find(validated.id())?;
        let processed = self.domain_service.process(entity)?;
        self.repository.save(&processed)?;
        Ok(Output::from(processed))
    }
}
```

### Infrastructure Layer (External Adapters)
- **Purpose**: Implements Core abstractions using external systems
- **Contains**: File system, crypto, network implementations
- **Dependencies**: Core + Application abstractions
- **Quality Gate**: 85% test coverage, proper error handling

```rust
pub struct FileSystemRepository {
    base_path: PathBuf,
}

impl Repository for FileSystemRepository {
    fn save(&self, entity: &Entity) -> Result<(), InfrastructureError> {
        let path = self.entity_path(entity.id());
        let data = serde_json::to_vec(entity)?;
        std::fs::write(&path, data)?;
        Ok(())
    }
}
```

### Binary Layer (Composition Root)
- **Purpose**: Dependency injection and application entry points
- **Contains**: Main functions, CLI parsing, error presentation
- **Dependencies**: All layers (for composition only)
- **Quality Gate**: Comprehensive error handling, graceful shutdown

```rust
pub struct ApplicationContainer {
    workflow: Workflow<FileSystemRepository>,
}

fn main() -> ExitCode {
    let config = Config::load().unwrap();
    let container = ApplicationContainer::new(&config).unwrap();
    
    match container.workflow.execute(parse_args()) {
        Ok(result) => { present_success(&result); ExitCode::SUCCESS }
        Err(error) => { present_error(&error); ExitCode::FAILURE }
    }
}
```

## Vertical Slice Architecture

### Feature Organization
Each feature slice spans all layers providing complete user capabilities:

```
Feature Slice: [BusinessCapability]
├── Core: Domain entities + Services + Abstractions
├── Application: Workflows + Event handlers
├── Infrastructure: Concrete implementations
└── Binary: CLI commands + DI containers
```

### Cross-Slice Communication
- **Preferred**: Domain events for loose coupling
- **When Needed**: Shared abstractions in Core
- **Composition**: At binary level only

## Async & Concurrency Patterns

### Philosophy: Synchronous First
- **Default**: Synchronous operations everywhere
- **Async Only**: True I/O-bound operations in Infrastructure
- **Never**: Async in Core or Application layers

```rust
// Core & Application: Always synchronous
pub trait Repository {
    fn save(&self, entity: &Entity) -> Result<(), Self::Error>;
}

// Infrastructure: Hide async behind sync interface
impl Repository for FileSystemRepository {
    fn save(&self, entity: &Entity) -> Result<(), Self::Error> {
        // Block on async only when absolutely necessary
        self.runtime.block_on(async {
            tokio::fs::write(&path, data).await
        })
    }
}
```

## Error Handling Strategy

### Error Flow: Infrastructure → Application → Binary

```rust
// Core: Domain errors (pure)
#[derive(thiserror::Error, Debug)]
pub enum DomainError {
    #[error("Business rule violated: {rule}")]
    BusinessRuleViolation { rule: String },
}

// Application: Workflow context
#[derive(thiserror::Error, Debug)]
pub enum WorkflowError {
    #[error("Business logic error")]
    Domain(#[from] DomainError),
    #[error("External system error")]
    Infrastructure(#[from] InfrastructureError),
}

// Infrastructure: System errors
#[derive(thiserror::Error, Debug)]
pub enum InfrastructureError {
    #[error("File system error")]
    FileSystem(#[from] std::io::Error),
}

// Binary: User-friendly presentation
#[derive(thiserror::Error, Debug)]
pub enum PresentationError {
    #[error("Command failed: {message}")]
    CommandFailed { message: String },
}
```

## Dependency Injection

### Container Pattern
```rust
pub struct ApplicationContainer {
    // Shared infrastructure
    repository: Arc<dyn Repository + Send + Sync>,
    
    // Workflows with injected dependencies
    workflow: PrimaryWorkflow,
}

impl ApplicationContainer {
    pub fn new(config: &Config) -> Result<Self, ContainerError> {
        let repository = Arc::new(FileSystemRepository::new(&config.storage)?);
        let workflow = PrimaryWorkflow::new(repository.clone());
        
        Ok(Self { repository, workflow })
    }
}
```

## Testing Strategy

### Layer-Specific Approaches

- **Core**: Unit tests, property-based testing (100% coverage)
- **Application**: Mock dependencies, workflow validation (95% coverage)
- **Infrastructure**: Contract tests, integration tests (85% coverage)
- **End-to-End**: Full system, real dependencies, user scenarios

```rust
// Core testing: Pure functions
#[test]
fn domain_logic_test() {
    let service = DomainService::new();
    let entity = Entity::new_valid();
    assert!(service.validate(&entity).is_ok());
}

// Application testing: Mocked dependencies
#[test]
fn workflow_test() {
    let mut mock_repo = MockRepository::new();
    mock_repo.expect_save().returning(|_| Ok(()));
    
    let workflow = Workflow::new(mock_repo);
    assert!(workflow.execute(test_input()).is_ok());
}
```

## Quality Gates

### Automated Validation
- **Dependency Direction**: Enforce with Cargo.toml workspace structure
- **Coverage Requirements**: Core 100%, Application 95%, Infrastructure 85%
- **Complexity Limits**: Cognitive complexity ≤ 15, cyclomatic ≤ 10
- **Documentation**: 100% public API documented

### Architecture Compliance
```toml
# Cargo.toml enforcement
[workspace]
members = ["core", "application", "infrastructure", "bin/*"]

# Core: No dependencies
[package]
name = "core"
dependencies = {}

# Application: Core only
[package]
name = "application"
dependencies = { core = { path = "../core" } }
```

## Implementation Phases

1. **Phase 1**: Core foundation (pure domain logic)
2. **Phase 2**: Application workflows (orchestration)
3. **Phase 3**: Infrastructure implementation (external adapters)
4. **Phase 4**: Binary composition (dependency injection)

## Key Patterns

- **Repository Pattern**: Data access abstraction
- **Workflow Pattern**: Use case orchestration
- **Factory Pattern**: Complex object construction
- **Event Pattern**: Cross-slice communication
- **Error Enrichment**: Context-aware error handling

## Success Metrics

- ✅ Dependencies flow inward only
- ✅ All abstractions in Core layer
- ✅ Synchronous by default
- ✅ Feature slices are autonomous
- ✅ 100% test coverage in Core
- ✅ Zero circular dependencies
- ✅ Screaming architecture (intent visible)

**Remember**: This architecture serves business value first, with technical patterns supporting clear expression of domain intent and user needs.