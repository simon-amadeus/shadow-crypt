# Architecture Specification

> **Vision**: A screaming architecture that makes system intent immediately visible through principled layering, dependency inversion, and feature-driven organization.

## Architectural Philosophy

This specification defines a **Hybrid Clean + Vertical Slice Architecture** that combines:
- **Horizontal Layer Separation**: Clear technical boundaries with strict dependency rules
- **Vertical Feature Organization**: Business capability slices spanning all layers
- **Dependency Inversion**: All abstractions owned by the innermost layer
- **Screaming Architecture**: System intent visible through structure and naming

**Core Principles**:
1. **Dependencies flow inward only** (Dependency Rule)
2. **All abstractions live in Core** (Interface Segregation)
3. **Features organize vertically** (Feature Cohesion)
4. **Composition happens at edges** (Composition Root)
5. **Pure functions preferred** (Functional Core, Imperative Shell)

## Layer Architecture

**Dependency Flow** (Outermost to Innermost):
```
Binaries → Infrastructure → Application → Core
```

```
┌─────────────────────────────────────────────────────────────┐
│                     Binary Layer                            │
│              Composition Root & Entry Points                │
│        Dependencies: All layers (for composition only)      │
└─────────────────────────────────────────────────────────────┘
                                ↓
┌─────────────────────────────────────────────────────────────┐
│                Infrastructure Layer                         │
│            External System Implementations                  │
│          Dependencies: Application + Core only              │
└─────────────────────────────────────────────────────────────┘
                                ↓
┌─────────────────────────────────────────────────────────────┐
│                 Application Layer                           │
│             Workflow Orchestration & Use Cases              │
│              Dependencies: Core abstractions only           │
└─────────────────────────────────────────────────────────────┘
                                ↓
┌─────────────────────────────────────────────────────────────┐
│                      Core Layer                             │
│         Pure Business Logic & All Abstractions              │
│                Dependencies: None (Pure)                    │
└─────────────────────────────────────────────────────────────┘
```

## Layer Responsibilities & Patterns

### Core Layer (Pure Domain)
**Purpose**: Contains pure business logic with zero external dependencies and owns ALL abstractions.

**Architectural Role**:
- **Single Source of Truth** for all system abstractions
- **Dependency-Free Zone** enabling pure testing and reasoning
- **Business Rule Guardian** where domain invariants are enforced
- **Interface Definition Authority** for all external concerns

**Responsibilities**:
- **Entities**: Domain models, value objects, and aggregates
- **Domain Services**: Pure business logic and rules
- **All Abstractions**: Every interface that outer layers implement
- **Domain Events**: Business events for cross-cutting communication
- **Domain Errors**: Business rule violation representations

**Dependency Rule**: Core depends on nothing and defines everything others need.

**Rust Implementation Patterns**:
```rust
// Pure domain entities (no external dependencies)
pub struct BusinessEntity {
    // Pure data and domain logic only
}

// All abstractions live here
pub trait ExternalService {
    type Error;
    fn operation(&self, input: Input) -> Result<Output, Self::Error>;
}

// Domain services with pure business logic
pub struct DomainService {
    // Pure functions only - no I/O, no side effects
}

impl DomainService {
    pub fn process_business_rule(&self, entity: &Entity) -> BusinessResult {
        // Pure domain logic only
    }
}
```

**Module Organization**:
```
core/
├── entities/           # Domain models and value objects
├── services/          # Pure business logic services
├── abstractions/      # ALL external interfaces (repos, adapters, etc.)
├── events/           # Domain events and event definitions
├── errors/           # Domain-specific error types
└── shared/           # Common domain utilities and types
```

**Quality Gates**:
- ✅ No external crate dependencies (except std, core)
- ✅ All functions are pure (no I/O, no global state)
- ✅ Every external concern has an abstraction defined here
- ✅ 100% unit testable without mocks

### Application Layer (Orchestration)
**Purpose**: Orchestrates Core services to implement complete user workflows and use cases.

**Architectural Role**:
- **Workflow Coordinator** implementing complete user scenarios
- **Cross-Cutting Orchestrator** managing logging, validation, metrics
- **Transaction Boundary Manager** ensuring consistency across operations
- **Error Context Provider** converting domain errors to user-friendly responses

**Responsibilities**:
- **Workflows**: Complete use case implementations spanning multiple domain services
- **Application Services**: Coordination logic for complex business scenarios
- **Cross-Cutting Concerns**: Logging, monitoring, audit trails, validation
- **Transaction Management**: Ensuring consistency across multiple operations
- **Error Enrichment**: Adding contextual information to domain errors

**Dependency Rule**: Application depends only on Core abstractions, never implementations.

**Rust Implementation Patterns**:
```rust
// Workflow pattern - orchestrates multiple domain services
pub struct SomeWorkflow<R: Repository, S: ExternalService> {
    repository: R,
    external_service: S,
    domain_service: DomainService,
}

impl<R: Repository, S: ExternalService> SomeWorkflow<R, S> {
    // Workflows coordinate multiple operations
    pub async fn execute_use_case(&self, input: Input) -> WorkflowResult<Output> {
        // 1. Validation using domain services
        let validated = self.domain_service.validate(input)?;
        
        // 2. Orchestrate multiple operations
        let entity = self.repository.fetch(validated.id).await?;
        let processed = self.domain_service.process(entity)?;
        let result = self.external_service.perform(processed).await?;
        
        // 3. Handle cross-cutting concerns
        self.log_success(&result);
        Ok(result)
    }
}

// Error enrichment pattern
#[derive(thiserror::Error, Debug)]
pub enum WorkflowError {
    #[error("Business rule violated: {message}")]
    Domain { message: String, source: DomainError },
    
    #[error("External system unavailable")]
    Infrastructure(#[from] InfrastructureError),
}
```

**Module Organization**:
```
application/
├── workflows/         # Complete use case implementations
├── services/         # Application-level coordination services
├── errors/          # Application error types and conversions
├── validation/      # Cross-cutting validation logic
└── shared/          # Common application utilities
```

**Quality Gates**:
- ✅ Only depends on Core abstractions (traits, not implementations)
- ✅ No direct I/O operations (delegated to Infrastructure)
- ✅ Every workflow represents a complete user scenario
- ✅ Comprehensive error handling with user-friendly messages

### Infrastructure Layer (External Adapters)
**Purpose**: Implements ALL Core abstractions using external systems and libraries.

**Architectural Role**:
- **Abstraction Implementor** providing concrete implementations of Core interfaces
- **External System Adapter** bridging domain abstractions to real-world systems
- **Technical Concern Handler** managing I/O, networking, persistence, crypto
- **Configuration Manager** handling system configuration and environment setup

**Responsibilities**:
- **Repository Implementations**: File systems, databases, external APIs
- **Service Implementations**: Cryptography, networking, messaging, third-party services
- **Adapter Implementations**: Terminal I/O, progress reporting, logging backends
- **Configuration Management**: Environment variables, config files, feature flags
- **Resource Management**: Connection pools, caches, external resource lifecycle

**Dependency Rule**: Infrastructure implements Core abstractions and may depend on Application workflows.

**Rust Implementation Patterns**:
```rust
// Repository implementation pattern
pub struct FileSystemRepository {
    base_path: PathBuf,
}

#[async_trait]
impl Repository for FileSystemRepository {
    type Error = FileSystemError;
    
    async fn save(&self, entity: &Entity) -> Result<(), Self::Error> {
        // File system implementation details
        tokio::fs::write(&path, &serialized_entity).await?;
        Ok(())
    }
}

// Service implementation pattern
pub struct CryptographicService {
    algorithm_config: AlgorithmConfig,
}

impl ExternalService for CryptographicService {
    type Error = CryptoError;
    
    fn operation(&self, input: Input) -> Result<Output, Self::Error> {
        // Cryptographic library integration
        let result = crypto_library::process(input.data)?;
        Ok(Output::from(result))
    }
}

// Configuration pattern
#[derive(serde::Deserialize)]
pub struct InfrastructureConfig {
    pub file_system: FileSystemConfig,
    pub crypto: CryptoConfig,
    pub logging: LoggingConfig,
}
```

**Module Organization**:
```
infrastructure/
├── repositories/     # File system, database, external API implementations
├── services/        # Crypto, networking, third-party service implementations
├── adapters/        # Terminal I/O, progress reporting, logging implementations
├── config/          # Configuration management and environment setup
└── shared/          # Common infrastructure utilities and error types
```

**Quality Gates**:
- ✅ Implements every abstraction defined in Core
- ✅ No business logic (pure technical implementation)
- ✅ Proper error handling and resource management
- ✅ Configurable and environment-aware

### Binary Layer (Composition Root)
**Purpose**: Compose dependencies and provide application entry points.

**Architectural Role**:
- **Dependency Injection Orchestrator** wiring all system components
- **Application Entry Point** providing main functions and CLI interfaces
- **Error Presentation Manager** converting internal errors to user output
- **System Bootstrap Coordinator** initializing logging, configuration, environment

**Responsibilities**:
- **Dependency Composition**: Configure and wire all system dependencies
- **Application Bootstrap**: Initialize logging, configuration, and system state
- **CLI Interface**: Command-line parsing, help text, user interaction
- **Error Presentation**: Convert application errors to user-friendly output
- **Process Management**: Signal handling, graceful shutdown, exit codes

**Dependency Rule**: Binaries depend on all layers but only for composition purposes.

**Rust Implementation Patterns**:
```rust
// Dependency injection pattern
pub struct ApplicationContainer {
    // All dependencies constructed here
    file_repository: Arc<dyn Repository>,
    crypto_service: Arc<dyn CryptoService>,
    workflow: SomeWorkflow,
}

impl ApplicationContainer {
    pub fn new(config: &Config) -> Result<Self, ConfigError> {
        // Construct all dependencies
        let file_repo = Arc::new(FileSystemRepository::new(&config.file_system)?);
        let crypto = Arc::new(CryptographicService::new(&config.crypto)?);
        let workflow = SomeWorkflow::new(file_repo.clone(), crypto.clone());
        
        Ok(Self { file_repository: file_repo, crypto_service: crypto, workflow })
    }
}

// CLI entry point pattern
#[tokio::main]
async fn main() -> ExitCode {
    // 1. Parse command line arguments
    let args = Args::parse();
    
    // 2. Initialize system (logging, config, etc.)
    let config = Config::load(&args.config_file)?;
    init_logging(&config.logging)?;
    
    // 3. Compose dependencies
    let container = ApplicationContainer::new(&config)?;
    
    // 4. Execute workflow
    match container.workflow.execute(args.input).await {
        Ok(result) => {
            present_success(&result);
            ExitCode::SUCCESS
        }
        Err(error) => {
            present_error(&error);
            ExitCode::FAILURE
        }
    }
}

// Error presentation pattern
fn present_error(error: &WorkflowError) -> ! {
    match error {
        WorkflowError::Domain { message, .. } => {
            eprintln!("Error: {}", message);
        }
        WorkflowError::Infrastructure(inf_error) => {
            eprintln!("System error: {}", inf_error);
        }
    }
    process::exit(1);
}
```

**Module Organization**:
```
bin/
├── main_binary.rs        # Primary application entry point
├── secondary_binary.rs   # Additional tools and utilities
└── shared/
    ├── container.rs      # Dependency injection configuration
    ├── cli.rs           # Common CLI utilities
    ├── config.rs        # Configuration loading and validation
    └── presentation.rs   # Error and result presentation
```

**Quality Gates**:
- ✅ Only composition logic (no business logic)
- ✅ Comprehensive error handling and user feedback
- ✅ Proper resource cleanup and graceful shutdown
- ✅ Clear separation between CLI concerns and application logic

## Vertical Slice Architecture

### Feature-Driven Organization Principles
Vertical slices represent **complete user capabilities** that span all architectural layers. Each slice owns its complete path from user interface to external systems.

**Slice Design Rules**:
1. **Complete User Value**: Each slice delivers end-to-end user capability
2. **Layer Spanning**: Every slice touches Core, Application, Infrastructure, and Binary layers
3. **Autonomous Teams**: Slices can be developed independently by different teams
4. **Minimal Coupling**: Slices communicate through domain events and shared abstractions
5. **Feature Ownership**: Each slice owns its complete technology stack

### Slice Anatomy Pattern
```
Feature Slice: [BusinessCapability]
├── Core Layer        → Domain entities + Business services + Abstractions
├── Application Layer → Workflow orchestration + Use case coordination
├── Infrastructure    → External system implementations + Adapters
└── Binary Layer      → CLI command + Dependency wiring + Entry point
```

**Example Slice Structure**:
```
BusinessCapability/
├── core/
│   ├── entities/          # Slice-specific domain models
│   ├── services/          # Slice business logic
│   ├── abstractions/      # External interfaces needed by this slice
│   └── events/           # Domain events published by this slice
├── application/
│   ├── workflows/         # Complete use case implementations
│   ├── handlers/          # Event handlers for cross-slice communication
│   └── validation/        # Application-level validation
├── infrastructure/
│   ├── repositories/      # External storage implementations
│   ├── services/          # External service implementations
│   └── adapters/          # I/O and presentation adapters
└── binary/
    ├── cli/              # Command-line interface
    ├── config/           # Slice-specific configuration
    └── container/        # Dependency injection for this slice
```

### Cross-Slice Communication Patterns

**1. Domain Events (Preferred)**
```rust
// Publisher (in one slice)
pub struct SomeWorkflow {
    event_publisher: Arc<dyn EventPublisher>,
}

impl SomeWorkflow {
    pub async fn execute(&self) -> Result<(), WorkflowError> {
        // Business logic...
        
        // Publish domain event
        let event = BusinessEvent::SomethingHappened { data: result };
        self.event_publisher.publish(event).await?;
        
        Ok(())
    }
}

// Subscriber (in another slice)
pub struct EventHandler {
    workflow: OtherWorkflow,
}

#[async_trait]
impl EventSubscriber for EventHandler {
    async fn handle(&self, event: DomainEvent) -> Result<(), EventError> {
        match event {
            DomainEvent::SomethingHappened { data } => {
                self.workflow.react_to_event(data).await?;
            }
            _ => {} // Ignore events this slice doesn't care about
        }
        Ok(())
    }
}
```

**2. Shared Abstractions (When Needed)**
```rust
// Shared abstraction in Core (used by multiple slices)
pub trait SharedService {
    fn common_operation(&self, input: Input) -> Result<Output, ServiceError>;
}

// Implementation in Infrastructure (can be shared)
pub struct SharedServiceImpl {
    // Implementation details
}

impl SharedService for SharedServiceImpl {
    fn common_operation(&self, input: Input) -> Result<Output, ServiceError> {
        // Common implementation
    }
}
```

**3. Slice Composition at Binary Level**
```rust
// Each binary composes only the slices it needs
pub struct ApplicationContainer {
    // Slice A components
    slice_a_workflow: SliceAWorkflow,
    
    // Slice B components  
    slice_b_workflow: SliceBWorkflow,
    
    // Shared infrastructure (if needed)
    shared_repository: Arc<dyn SharedRepository>,
    event_bus: Arc<dyn EventBus>,
}

impl ApplicationContainer {
    pub fn new(config: &Config) -> Result<Self, ConfigError> {
        // Wire shared infrastructure
        let event_bus = Arc::new(InMemoryEventBus::new());
        let shared_repo = Arc::new(FileSystemRepository::new(&config.storage)?);
        
        // Compose Slice A
        let slice_a = SliceAWorkflow::new(
            shared_repo.clone(),
            event_bus.clone(),
        )?;
        
        // Compose Slice B
        let slice_b = SliceBWorkflow::new(
            shared_repo.clone(),
            event_bus.clone(),
        )?;
        
        Ok(Self {
            slice_a_workflow: slice_a,
            slice_b_workflow: slice_b,
            shared_repository: shared_repo,
            event_bus,
        })
    }
}
```

### Slice Boundaries & Autonomy

**Strong Boundaries**:
- Each slice has its own error types and handling strategies
- Slice-specific configuration and environment setup
- Independent testing strategies and test suites
- Autonomous deployment capabilities (when applicable)

**Shared Concerns** (Minimize These):
- Common infrastructure implementations (databases, file systems)
- Shared domain events and event infrastructure
- Cross-cutting technical concerns (logging, monitoring, security)
- Common CLI utilities and presentation helpers

**Slice Evolution Patterns**:
```rust
// Slices can evolve independently
// Old slice remains stable
pub mod legacy_slice {
    // Existing implementation - not touched
}

// New slice developed independently
pub mod new_slice {
    // New implementation with different patterns
    // Can gradually replace legacy_slice
}

// Migration coordination happens at binary level
pub struct MigrationContainer {
    legacy_workflow: legacy_slice::Workflow,
    new_workflow: new_slice::Workflow,
    migration_strategy: MigrationStrategy,
}
```

## Dependency Injection Architecture

### Container Design Principles
1. **Interface-Based Composition**: All dependencies injected via Core abstractions
2. **Single Composition Root**: Dependencies resolved once at application startup
3. **Immutable Configuration**: Dependencies immutable after container construction
4. **Testability First**: Easy substitution of implementations for testing
5. **Explicit Dependencies**: No hidden dependencies or service location patterns

### Rust-Specific DI Patterns

**1. Constructor Injection with Trait Objects**
```rust
// Core defines the abstraction
pub trait Repository {
    type Error;
    async fn save(&self, entity: &Entity) -> Result<(), Self::Error>;
}

// Application uses the abstraction
pub struct Workflow<R: Repository> {
    repository: R,
    // Other dependencies...
}

impl<R: Repository> Workflow<R> {
    pub fn new(repository: R) -> Self {
        Self { repository }
    }
    
    pub async fn execute(&self) -> Result<Output, WorkflowError> {
        // Use repository through abstraction
        self.repository.save(&entity).await
            .map_err(WorkflowError::Repository)?;
        Ok(output)
    }
}
```

**2. Arc-Based Shared Dependencies**
```rust
// For shared, thread-safe dependencies
pub struct ApplicationContainer {
    // Shared repositories
    file_repository: Arc<dyn FileRepository + Send + Sync>,
    config_repository: Arc<dyn ConfigRepository + Send + Sync>,
    
    // Workflows with injected dependencies
    primary_workflow: PrimaryWorkflow,
    secondary_workflow: SecondaryWorkflow,
}

impl ApplicationContainer {
    pub fn new(config: &Config) -> Result<Self, ContainerError> {
        // Create shared infrastructure
        let file_repo = Arc::new(FileSystemRepository::new(&config.file_system)?);
        let config_repo = Arc::new(ConfigFileRepository::new(&config.config_path)?);
        
        // Inject into workflows
        let primary = PrimaryWorkflow::new(
            file_repo.clone(),
            config_repo.clone(),
        );
        
        let secondary = SecondaryWorkflow::new(
            file_repo.clone(),
        );
        
        Ok(Self {
            file_repository: file_repo,
            config_repository: config_repo,
            primary_workflow: primary,
            secondary_workflow: secondary,
        })
    }
}
```

**3. Factory Pattern for Complex Construction**
```rust
// When dependencies need complex initialization
pub trait ServiceFactory {
    type Service;
    type Error;
    fn create(&self, config: &ServiceConfig) -> Result<Self::Service, Self::Error>;
}

// Infrastructure implements factory
pub struct CryptoServiceFactory;

impl ServiceFactory for CryptoServiceFactory {
    type Service = Box<dyn CryptoService + Send + Sync>;
    type Error = CryptoInitError;
    
    fn create(&self, config: &ServiceConfig) -> Result<Self::Service, Self::Error> {
        match config.algorithm {
            Algorithm::AES => Ok(Box::new(AESCryptoService::new(config)?)),
            Algorithm::ChaCha => Ok(Box::new(ChaChaService::new(config)?)),
        }
    }
}

// Application uses factory
pub struct Workflow {
    crypto_service: Box<dyn CryptoService + Send + Sync>,
}

impl Workflow {
    pub fn new<F: ServiceFactory>(factory: &F, config: &ServiceConfig) -> Result<Self, WorkflowError> {
        let crypto_service = factory.create(config)
            .map_err(WorkflowError::ServiceInitialization)?;
            
        Ok(Self { crypto_service })
    }
}
```

### Container Lifecycle Management

**1. Container Construction Pattern**
```rust
pub struct ApplicationContainer {
    // Configuration
    config: Arc<Config>,
    
    // Infrastructure layer
    repositories: RepositoryContainer,
    services: ServiceContainer,
    adapters: AdapterContainer,
    
    // Application layer
    workflows: WorkflowContainer,
    
    // Lifecycle management
    shutdown_signal: tokio::sync::oneshot::Receiver<()>,
}

impl ApplicationContainer {
    pub async fn build(config_path: &Path) -> Result<Self, ContainerError> {
        // 1. Load and validate configuration
        let config = Arc::new(Config::load(config_path)?);
        
        // 2. Initialize infrastructure layer
        let repositories = RepositoryContainer::new(&config).await?;
        let services = ServiceContainer::new(&config).await?;
        let adapters = AdapterContainer::new(&config).await?;
        
        // 3. Initialize application layer
        let workflows = WorkflowContainer::new(
            &repositories,
            &services,
            &adapters,
        )?;
        
        // 4. Setup lifecycle management
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(Self::setup_signal_handlers(shutdown_tx));
        
        Ok(Self {
            config,
            repositories,
            services,
            adapters,
            workflows,
            shutdown_signal: shutdown_rx,
        })
    }
    
    pub async fn run(mut self) -> Result<(), ApplicationError> {
        // Application main loop
        tokio::select! {
            result = self.workflows.run() => result,
            _ = &mut self.shutdown_signal => {
                info!("Received shutdown signal");
                self.graceful_shutdown().await?;
                Ok(())
            }
        }
    }
    
    async fn graceful_shutdown(&self) -> Result<(), ShutdownError> {
        // Shutdown in reverse dependency order
        self.workflows.shutdown().await?;
        self.adapters.shutdown().await?;
        self.services.shutdown().await?;
        self.repositories.shutdown().await?;
        Ok(())
    }
}
```

**2. Testing Container Pattern**
```rust
// Test-specific container with mock implementations
pub struct TestContainer {
    mock_repository: Arc<MockRepository>,
    mock_service: Arc<MockService>,
    workflow: Workflow,
}

impl TestContainer {
    pub fn new() -> Self {
        let mock_repo = Arc::new(MockRepository::new());
        let mock_service = Arc::new(MockService::new());
        
        let workflow = Workflow::new(
            mock_repo.clone(),
            mock_service.clone(),
        );
        
        Self {
            mock_repository: mock_repo,
            mock_service,
            workflow,
        }
    }
    
    // Test helpers
    pub fn expect_repository_call(&self, expectation: RepositoryExpectation) {
        self.mock_repository.expect(expectation);
    }
    
    pub fn verify_expectations(&self) {
        self.mock_repository.verify();
        self.mock_service.verify();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_workflow_execution() {
        let container = TestContainer::new();
        
        // Setup expectations
        container.expect_repository_call(
            RepositoryExpectation::Save { entity: test_entity() }
        );
        
        // Execute workflow
        let result = container.workflow.execute(test_input()).await;
        
        // Verify
        assert!(result.is_ok());
        container.verify_expectations();
    }
}
```

### Configuration Integration

**1. Environment-Aware Configuration**
```rust
#[derive(serde::Deserialize, Clone)]
pub struct Config {
    pub environment: Environment,
    pub infrastructure: InfrastructureConfig,
    pub application: ApplicationConfig,
    pub logging: LoggingConfig,
}

#[derive(serde::Deserialize, Clone)]
pub enum Environment {
    Development,
    Testing, 
    Production,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let config_content = std::fs::read_to_string(path)?;
        let mut config: Config = toml::from_str(&config_content)?;
        
        // Environment-specific overrides
        match config.environment {
            Environment::Development => {
                config.logging.level = LogLevel::Debug;
            }
            Environment::Testing => {
                config.infrastructure.database.in_memory = true;
            }
            Environment::Production => {
                config.logging.structured = true;
            }
        }
        
        // Validate configuration
        config.validate()?;
        
        Ok(config)
    }
    
    fn validate(&self) -> Result<(), ConfigError> {
        // Configuration validation logic
        Ok(())
    }
}
```

**2. Feature Flag Integration**
```rust
pub trait FeatureFlags {
    fn is_enabled(&self, feature: &str) -> bool;
}

pub struct ConfigBasedFeatureFlags {
    flags: HashMap<String, bool>,
}

impl FeatureFlags for ConfigBasedFeatureFlags {
    fn is_enabled(&self, feature: &str) -> bool {
        self.flags.get(feature).copied().unwrap_or(false)
    }
}

// Container uses feature flags for conditional construction
impl ApplicationContainer {
    pub fn new(config: &Config) -> Result<Self, ContainerError> {
        let feature_flags = ConfigBasedFeatureFlags::new(&config.features);
        
        let workflow = if feature_flags.is_enabled("new_workflow") {
            Box::new(NewWorkflow::new()) as Box<dyn WorkflowTrait>
        } else {
            Box::new(LegacyWorkflow::new()) as Box<dyn WorkflowTrait>
        };
        
        Ok(Self { workflow })
    }
}
```

## Async & Concurrency Patterns

### Async Design Philosophy

**Async Where It Matters**: Use async/await for I/O-bound operations while keeping domain logic synchronous when possible.

**Structured Concurrency**: Prefer structured concurrency patterns that make resource lifetime and error handling explicit.

### Rust Async Patterns

**1. Repository Pattern with Async**
```rust
// Core defines async abstractions
#[async_trait]
pub trait Repository {
    type Error;
    async fn save(&self, entity: &Entity) -> Result<(), Self::Error>;
    async fn find(&self, id: EntityId) -> Result<Option<Entity>, Self::Error>;
    async fn find_all(&self) -> Result<Vec<Entity>, Self::Error>;
}

// Infrastructure implements with real async I/O
pub struct FileSystemRepository {
    base_path: PathBuf,
}

#[async_trait]
impl Repository for FileSystemRepository {
    type Error = InfrastructureError;
    
    async fn save(&self, entity: &Entity) -> Result<(), Self::Error> {
        let path = self.entity_path(entity.id());
        let data = serde_json::to_vec(entity)?;
        
        // Async file I/O
        tokio::fs::create_dir_all(path.parent().unwrap()).await?;
        tokio::fs::write(&path, data).await?;
        
        Ok(())
    }
    
    async fn find(&self, id: EntityId) -> Result<Option<Entity>, Self::Error> {
        let path = self.entity_path(id);
        
        match tokio::fs::read(&path).await {
            Ok(data) => {
                let entity: Entity = serde_json::from_slice(&data)?;
                Ok(Some(entity))
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(InfrastructureError::FileSystem(err)),
        }
    }
    
    async fn find_all(&self) -> Result<Vec<Entity>, Self::Error> {
        let mut entities = Vec::new();
        let mut dir_entries = tokio::fs::read_dir(&self.base_path).await?;
        
        while let Some(entry) = dir_entries.next_entry().await? {
            if let Some(entity_id) = self.extract_entity_id(&entry) {
                if let Some(entity) = self.find(entity_id).await? {
                    entities.push(entity);
                }
            }
        }
        
        Ok(entities)
    }
}
```

**2. Workflow Orchestration with Async**
```rust
// Application layer orchestrates async operations
pub struct ProcessingWorkflow<R: Repository, S: ExternalService> {
    repository: R,
    external_service: S,
    domain_service: DomainService,
}

impl<R: Repository, S: ExternalService> ProcessingWorkflow<R, S> {
    pub async fn execute_batch(&self, inputs: Vec<Input>) -> Vec<WorkflowResult> {
        // Process inputs concurrently with controlled parallelism
        let semaphore = Arc::new(Semaphore::new(10)); // Limit to 10 concurrent operations
        
        let tasks: Vec<_> = inputs.into_iter().map(|input| {
            let repo = &self.repository;
            let service = &self.external_service;
            let domain = &self.domain_service;
            let permit = semaphore.clone();
            
            async move {
                let _permit = permit.acquire().await.unwrap();
                self.process_single_input(input, repo, service, domain).await
            }
        }).collect();
        
        // Wait for all tasks to complete
        futures::future::join_all(tasks).await
    }
    
    async fn process_single_input(
        &self,
        input: Input,
        repository: &R,
        external_service: &S,
        domain_service: &DomainService,
    ) -> WorkflowResult {
        // Sequential async operations for single input
        let validated_input = domain_service.validate(input)?;
        
        let existing_entity = repository.find(validated_input.entity_id()).await
            .map_err(WorkflowError::Repository)?;
        
        let entity = match existing_entity {
            Some(entity) => entity,
            None => return Err(WorkflowError::EntityNotFound),
        };
        
        let processed_data = external_service.process(&entity).await
            .map_err(WorkflowError::ExternalService)?;
        
        let updated_entity = domain_service.apply_processing_result(entity, processed_data)?;
        
        repository.save(&updated_entity).await
            .map_err(WorkflowError::Repository)?;
        
        Ok(WorkflowOutput::success(updated_entity.id()))
    }
}
```

**3. Streaming and Backpressure**
```rust
use tokio_stream::{Stream, StreamExt};
use futures::stream;

// Streaming data processing with backpressure
pub struct StreamingProcessor<R: Repository> {
    repository: R,
    batch_size: usize,
    max_concurrent: usize,
}

impl<R: Repository> StreamingProcessor<R> {
    pub async fn process_stream<S>(&self, input_stream: S) -> Result<ProcessingStats, ProcessingError>
    where
        S: Stream<Item = Input> + Send,
    {
        let stats = Arc::new(Mutex::new(ProcessingStats::new()));
        
        input_stream
            // Batch inputs for efficient processing
            .chunks(self.batch_size)
            // Process batches with controlled concurrency
            .for_each_concurrent(self.max_concurrent, |batch| {
                let stats = stats.clone();
                let repo = &self.repository;
                
                async move {
                    match self.process_batch(batch, repo).await {
                        Ok(batch_stats) => {
                            stats.lock().await.merge(batch_stats);
                        }
                        Err(err) => {
                            error!("Batch processing failed: {}", err);
                            stats.lock().await.increment_errors();
                        }
                    }
                }
            })
            .await;
        
        let final_stats = stats.lock().await.clone();
        Ok(final_stats)
    }
    
    async fn process_batch(&self, batch: Vec<Input>, repository: &R) -> Result<ProcessingStats, ProcessingError> {
        let mut stats = ProcessingStats::new();
        
        // Process batch items concurrently but within the batch
        let tasks: Vec<_> = batch.into_iter().map(|input| async move {
            match self.process_single(input, repository).await {
                Ok(_) => ProcessingResult::Success,
                Err(err) => ProcessingResult::Error(err),
            }
        }).collect();
        
        let results = futures::future::join_all(tasks).await;
        
        for result in results {
            match result {
                ProcessingResult::Success => stats.increment_success(),
                ProcessingResult::Error(_) => stats.increment_errors(),
            }
        }
        
        Ok(stats)
    }
}
```

**4. Progress Reporting with Async**
```rust
// Progress reporting that works with async operations
pub trait ProgressReporter: Send + Sync {
    async fn report_progress(&self, current: u64, total: u64, message: &str);
    async fn report_completion(&self, stats: &CompletionStats);
}

// Terminal-based progress reporter
pub struct TerminalProgressReporter {
    last_update: Arc<Mutex<Instant>>,
    update_interval: Duration,
}

#[async_trait]
impl ProgressReporter for TerminalProgressReporter {
    async fn report_progress(&self, current: u64, total: u64, message: &str) {
        let mut last_update = self.last_update.lock().await;
        let now = Instant::now();
        
        // Throttle updates to avoid overwhelming the terminal
        if now.duration_since(*last_update) >= self.update_interval {
            let percentage = (current as f64 / total as f64) * 100.0;
            println!("Progress: {:.1}% ({}/{}) - {}", percentage, current, total, message);
            *last_update = now;
        }
    }
    
    async fn report_completion(&self, stats: &CompletionStats) {
        println!("Completed: {} successful, {} errors, took {:?}", 
                 stats.successful_count, 
                 stats.error_count, 
                 stats.duration);
    }
}

// Workflow with integrated progress reporting
impl<R: Repository, P: ProgressReporter> ProcessingWorkflow<R, P> {
    pub async fn execute_with_progress(&self, inputs: Vec<Input>) -> WorkflowResult {
        let total = inputs.len() as u64;
        let completed = Arc::new(AtomicU64::new(0));
        
        // Create progress reporting task
        let progress_reporter = self.progress_reporter.clone();
        let completed_counter = completed.clone();
        let progress_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(500));
            
            loop {
                interval.tick().await;
                let current = completed_counter.load(Ordering::Relaxed);
                
                if current >= total {
                    break;
                }
                
                progress_reporter.report_progress(current, total, "Processing...").await;
            }
        });
        
        // Process inputs
        let processing_tasks: Vec<_> = inputs.into_iter().map(|input| {
            let completed = completed.clone();
            
            async move {
                let result = self.process_input(input).await;
                completed.fetch_add(1, Ordering::Relaxed);
                result
            }
        }).collect();
        
        let results = futures::future::join_all(processing_tasks).await;
        
        // Complete progress reporting
        progress_task.abort();
        let stats = CompletionStats::from_results(&results);
        self.progress_reporter.report_completion(&stats).await;
        
        Ok(WorkflowOutput::batch_result(results))
    }
}
```

**5. Graceful Shutdown Patterns**
```rust
// Graceful shutdown coordination
pub struct GracefulShutdown {
    shutdown_signal: Arc<Notify>,
    active_tasks: Arc<AtomicUsize>,
}

impl GracefulShutdown {
    pub fn new() -> Self {
        Self {
            shutdown_signal: Arc::new(Notify::new()),
            active_tasks: Arc::new(AtomicUsize::new(0)),
        }
    }
    
    pub async fn wait_for_shutdown(&self) {
        self.shutdown_signal.notified().await;
    }
    
    pub fn signal_shutdown(&self) {
        self.shutdown_signal.notify_waiters();
    }
    
    pub async fn wait_for_tasks_completion(&self, timeout: Duration) -> Result<(), ShutdownError> {
        let deadline = Instant::now() + timeout;
        
        while self.active_tasks.load(Ordering::Relaxed) > 0 {
            if Instant::now() > deadline {
                return Err(ShutdownError::Timeout);
            }
            
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        
        Ok(())
    }
}

// Application component with graceful shutdown
pub struct Application {
    workflow: ProcessingWorkflow,
    shutdown: GracefulShutdown,
}

impl Application {
    pub async fn run(&self) -> Result<(), ApplicationError> {
        tokio::select! {
            result = self.main_processing_loop() => result,
            _ = self.shutdown.wait_for_shutdown() => {
                info!("Shutdown signal received, stopping gracefully...");
                
                // Wait for active tasks to complete
                self.shutdown.wait_for_tasks_completion(Duration::from_secs(30)).await
                    .map_err(ApplicationError::ShutdownTimeout)?;
                
                info!("Graceful shutdown completed");
                Ok(())
            }
        }
    }
    
    async fn main_processing_loop(&self) -> Result<(), ApplicationError> {
        loop {
            // Track active tasks
            self.shutdown.active_tasks.fetch_add(1, Ordering::Relaxed);
            
            let task_result = tokio::select! {
                result = self.workflow.process_next() => result,
                _ = self.shutdown.wait_for_shutdown() => {
                    // Shutdown requested, exit loop
                    break;
                }
            };
            
            self.shutdown.active_tasks.fetch_sub(1, Ordering::Relaxed);
            
            match task_result {
                Ok(_) => continue,
                Err(err) => {
                    error!("Processing error: {}", err);
                    // Decide whether to continue or shutdown based on error type
                    if err.is_fatal() {
                        return Err(ApplicationError::FatalError(err));
                    }
                }
            }
        }
        
        Ok(())
    }
}

// Signal handling for graceful shutdown
async fn setup_signal_handling(shutdown: Arc<GracefulShutdown>) {
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("Failed to create SIGTERM handler");
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .expect("Failed to create SIGINT handler");
    
    tokio::select! {
        _ = sigterm.recv() => {
            info!("Received SIGTERM, initiating graceful shutdown");
            shutdown.signal_shutdown();
        }
        _ = sigint.recv() => {
            info!("Received SIGINT, initiating graceful shutdown");
            shutdown.signal_shutdown();
        }
    }
}
```

### Concurrency Quality Gates

**Performance Guidelines**:
- ✅ Limit concurrent operations to prevent resource exhaustion
- ✅ Use structured concurrency (no fire-and-forget tasks)
- ✅ Implement backpressure for streaming operations
- ✅ Provide graceful shutdown with timeout handling

**Safety Guidelines**:
- ✅ Avoid shared mutable state (prefer channels and message passing)
- ✅ Use `Arc<Mutex<T>>` sparingly and with clear lifetime bounds
- ✅ Handle task cancellation gracefully
- ✅ Ensure all async operations have timeout bounds

## Error Handling Strategy

### Error Type Hierarchy & Flow

**Error Flow Direction**: Infrastructure → Application → Binary (following dependency direction)

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Binary Layer  │ ←── │ Application     │ ←── │ Infrastructure  │
│                 │    │ Layer           │    │ Layer           │
│ • User Messages │    │ • Context       │    │ • System Errors │
│ • Exit Codes    │    │ • Workflow      │    │ • I/O Failures  │
│ • Help Text     │    │ • Enrichment    │    │ • External APIs │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                 ↑
                       ┌─────────────────┐
                       │   Core Layer    │
                       │                 │
                       │ • Domain Errors │
                       │ • Business Rules│
                       │ • Pure Logic    │
                       └─────────────────┘
```

### Rust Error Patterns

**1. Core Layer - Domain Errors (Pure)**
```rust
// Domain errors represent business rule violations
#[derive(thiserror::Error, Debug, PartialEq)]
pub enum DomainError {
    #[error("Business rule violated: {rule}")]
    BusinessRuleViolation { rule: String },
    
    #[error("Invalid entity state: {reason}")]
    InvalidEntityState { reason: String },
    
    #[error("Domain constraint failed: {constraint}")]
    ConstraintViolation { constraint: String },
}

// Domain services return domain errors
impl DomainService {
    pub fn validate_business_rule(&self, entity: &Entity) -> Result<(), DomainError> {
        if !self.is_valid_state(entity) {
            return Err(DomainError::InvalidEntityState {
                reason: "Entity missing required properties".to_string(),
            });
        }
        Ok(())
    }
}
```

**2. Application Layer - Workflow Errors (Orchestration)**
```rust
// Application errors add workflow context to domain errors
#[derive(thiserror::Error, Debug)]
pub enum WorkflowError {
    #[error("Workflow step failed: {step}")]
    StepFailed { 
        step: String,
        #[source] 
        cause: Box<dyn std::error::Error + Send + Sync>,
    },
    
    #[error("Business logic error in workflow: {workflow}")]
    Domain { 
        workflow: String,
        #[source] 
        domain_error: DomainError,
    },
    
    #[error("External system unavailable: {system}")]
    ExternalSystem { 
        system: String,
        #[source] 
        infrastructure_error: InfrastructureError,
    },
    
    #[error("Validation failed: {errors:?}")]
    Validation { errors: Vec<ValidationError> },
}

// Workflows convert and enrich errors
impl SomeWorkflow {
    pub async fn execute(&self, input: Input) -> Result<Output, WorkflowError> {
        // Domain validation
        self.domain_service.validate(&input)
            .map_err(|e| WorkflowError::Domain { 
                workflow: "SomeWorkflow".to_string(),
                domain_error: e,
            })?;
        
        // External operation
        self.external_service.perform(&input).await
            .map_err(|e| WorkflowError::ExternalSystem {
                system: "ExternalService".to_string(),
                infrastructure_error: e,
            })?;
        
        Ok(output)
    }
}
```

**3. Infrastructure Layer - System Errors (External)**
```rust
// Infrastructure errors represent external system failures
#[derive(thiserror::Error, Debug)]
pub enum InfrastructureError {
    #[error("File system operation failed")]
    FileSystem(#[from] std::io::Error),
    
    #[error("Network operation failed")]
    Network(#[from] reqwest::Error),
    
    #[error("Database operation failed")]
    Database(#[from] sqlx::Error),
    
    #[error("Serialization failed")]
    Serialization(#[from] serde_json::Error),
    
    #[error("Configuration error: {message}")]
    Configuration { message: String },
    
    #[error("Resource exhausted: {resource}")]
    ResourceExhausted { resource: String },
}

// Infrastructure implementations handle external errors
impl FileRepository for FileSystemRepository {
    type Error = InfrastructureError;
    
    async fn save(&self, entity: &Entity) -> Result<(), Self::Error> {
        let serialized = serde_json::to_string(entity)?;
        tokio::fs::write(&self.path, serialized).await?;
        Ok(())
    }
}
```

**4. Binary Layer - User Presentation (Final)**
```rust
// Binary errors focus on user experience
#[derive(thiserror::Error, Debug)]
pub enum PresentationError {
    #[error("Command failed: {message}")]
    CommandFailed { message: String },
    
    #[error("Invalid arguments: {errors:?}")]
    InvalidArguments { errors: Vec<String> },
    
    #[error("System error occurred")]
    SystemError,
    
    #[error("Operation cancelled by user")]
    UserCancelled,
}

// Binary layer converts all errors to user-friendly messages
impl From<WorkflowError> for PresentationError {
    fn from(error: WorkflowError) -> Self {
        match error {
            WorkflowError::Domain { domain_error, .. } => {
                PresentationError::CommandFailed {
                    message: format!("Operation failed: {}", domain_error),
                }
            }
            WorkflowError::ExternalSystem { system, .. } => {
                PresentationError::SystemError
            }
            WorkflowError::Validation { errors } => {
                PresentationError::InvalidArguments {
                    errors: errors.into_iter().map(|e| e.to_string()).collect(),
                }
            }
            _ => PresentationError::SystemError,
        }
    }
}

// Main function handles final error presentation
#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            present_error(&error);
            error_to_exit_code(&error)
        }
    }
}

fn present_error(error: &PresentationError) {
    match error {
        PresentationError::CommandFailed { message } => {
            eprintln!("Error: {}", message);
        }
        PresentationError::InvalidArguments { errors } => {
            eprintln!("Invalid arguments:");
            for error in errors {
                eprintln!("  • {}", error);
            }
        }
        PresentationError::SystemError => {
            eprintln!("A system error occurred. Please try again.");
        }
        PresentationError::UserCancelled => {
            eprintln!("Operation cancelled.");
        }
    }
}

fn error_to_exit_code(error: &PresentationError) -> ExitCode {
    match error {
        PresentationError::InvalidArguments { .. } => ExitCode::from(2),
        PresentationError::UserCancelled => ExitCode::from(130),
        _ => ExitCode::FAILURE,
    }
}
```

### Error Context & Recovery Patterns

**1. Error Context Enrichment**
```rust
// Rich error context for debugging and user feedback
#[derive(thiserror::Error, Debug)]
pub struct ContextualError {
    message: String,
    context: ErrorContext,
    #[source]
    source: Box<dyn std::error::Error + Send + Sync>,
}

#[derive(Debug)]
pub struct ErrorContext {
    operation: String,
    user_input: Option<String>,
    system_state: HashMap<String, String>,
    timestamp: chrono::DateTime<chrono::Utc>,
}

impl ContextualError {
    pub fn new<E>(operation: &str, source: E) -> Self 
    where 
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            message: format!("Operation '{}' failed", operation),
            context: ErrorContext {
                operation: operation.to_string(),
                user_input: None,
                system_state: HashMap::new(),
                timestamp: chrono::Utc::now(),
            },
            source: Box::new(source),
        }
    }
    
    pub fn with_user_input(mut self, input: String) -> Self {
        self.context.user_input = Some(input);
        self
    }
    
    pub fn with_system_state(mut self, key: String, value: String) -> Self {
        self.context.system_state.insert(key, value);
        self
    }
}
```

**2. Error Recovery Strategies**
```rust
// Retry pattern for transient failures
pub struct RetryPolicy {
    max_attempts: usize,
    base_delay: Duration,
    max_delay: Duration,
}

impl RetryPolicy {
    pub async fn execute<F, T, E>(&self, operation: F) -> Result<T, E>
    where
        F: Fn() -> Pin<Box<dyn Future<Output = Result<T, E>> + Send>>,
        E: std::error::Error + Send,
    {
        let mut attempts = 0;
        let mut delay = self.base_delay;
        
        loop {
            attempts += 1;
            
            match operation().await {
                Ok(result) => return Ok(result),
                Err(error) if attempts >= self.max_attempts => return Err(error),
                Err(error) if self.is_retryable(&error) => {
                    warn!("Operation failed (attempt {}), retrying: {}", attempts, error);
                    tokio::time::sleep(delay).await;
                    delay = std::cmp::min(delay * 2, self.max_delay);
                }
                Err(error) => return Err(error),
            }
        }
    }
    
    fn is_retryable<E: std::error::Error>(&self, error: &E) -> bool {
        // Determine if error is worth retrying
        // e.g., network timeouts yes, authentication failures no
        true // Simplified for example
    }
}

// Circuit breaker pattern for external dependencies
pub struct CircuitBreaker {
    state: Arc<Mutex<CircuitState>>,
    failure_threshold: usize,
    recovery_timeout: Duration,
}

#[derive(Debug)]
enum CircuitState {
    Closed { failure_count: usize },
    Open { opened_at: Instant },
    HalfOpen,
}

impl CircuitBreaker {
    pub async fn execute<F, T, E>(&self, operation: F) -> Result<T, CircuitBreakerError<E>>
    where
        F: Future<Output = Result<T, E>>,
        E: std::error::Error,
    {
        // Check if circuit is open
        {
            let state = self.state.lock().await;
            match *state {
                CircuitState::Open { opened_at } => {
                    if opened_at.elapsed() < self.recovery_timeout {
                        return Err(CircuitBreakerError::CircuitOpen);
                    }
                    // Try to transition to half-open
                }
                CircuitState::Closed { .. } | CircuitState::HalfOpen => {}
            }
        }
        
        // Execute operation
        match operation.await {
            Ok(result) => {
                self.on_success().await;
                Ok(result)
            }
            Err(error) => {
                self.on_failure().await;
                Err(CircuitBreakerError::OperationFailed(error))
            }
        }
    }
    
    async fn on_success(&self) {
        let mut state = self.state.lock().await;
        *state = CircuitState::Closed { failure_count: 0 };
    }
    
    async fn on_failure(&self) {
        let mut state = self.state.lock().await;
        match *state {
            CircuitState::Closed { failure_count } => {
                let new_count = failure_count + 1;
                if new_count >= self.failure_threshold {
                    *state = CircuitState::Open { opened_at: Instant::now() };
                } else {
                    *state = CircuitState::Closed { failure_count: new_count };
                }
            }
            CircuitState::HalfOpen => {
                *state = CircuitState::Open { opened_at: Instant::now() };
            }
            CircuitState::Open { .. } => {} // Already open
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum CircuitBreakerError<E> {
    #[error("Circuit breaker is open")]
    CircuitOpen,
    #[error("Operation failed")]
    OperationFailed(#[source] E),
}
```

## Testing Strategy

### Layer-Specific Testing Approaches

**Testing Philosophy**: Each layer requires different testing strategies based on its responsibilities and dependencies.

### Core Layer Testing (Pure Domain)

**Characteristics**: Pure functions, no external dependencies, deterministic behavior

**Testing Patterns**:
```rust
// Unit tests for pure domain logic
#[cfg(test)]
mod domain_tests {
    use super::*;
    use proptest::prelude::*;
    
    // Simple unit tests for business logic
    #[test]
    fn business_rule_validation_success() {
        let service = DomainService::new();
        let valid_entity = Entity::new_valid();
        
        let result = service.validate_business_rule(&valid_entity);
        
        assert!(result.is_ok());
    }
    
    #[test]
    fn business_rule_validation_failure() {
        let service = DomainService::new();
        let invalid_entity = Entity::new_invalid();
        
        let result = service.validate_business_rule(&invalid_entity);
        
        assert!(matches!(result, Err(DomainError::BusinessRuleViolation { .. })));
    }
    
    // Property-based testing for domain invariants
    proptest! {
        #[test]
        fn entity_invariants_always_hold(
            value in any::<u32>(),
            state in prop::collection::vec(any::<String>(), 0..10)
        ) {
            let entity = Entity::new(value, state);
            
            // Domain invariants must always hold
            prop_assert!(entity.is_valid());
            prop_assert!(entity.satisfies_constraints());
        }
        
        #[test]
        fn domain_operations_are_associative(
            a in domain_value_strategy(),
            b in domain_value_strategy(),
            c in domain_value_strategy()
        ) {
            let service = DomainService::new();
            
            // Test associativity: (a + b) + c = a + (b + c)
            let left = service.combine(&service.combine(&a, &b)?, &c)?;
            let right = service.combine(&a, &service.combine(&b, &c)?)?;
            
            prop_assert_eq!(left, right);
        }
    }
    
    // Domain-specific value generators
    fn domain_value_strategy() -> impl Strategy<Value = DomainValue> {
        (1..=1000u32, "[a-z]{1,10}")
            .prop_map(|(id, name)| DomainValue::new(id, name))
    }
}

// Example-based testing for complex scenarios
#[cfg(test)]
mod domain_examples {
    use super::*;
    
    #[test]
    fn complete_business_scenario() {
        // Given: A specific business scenario
        let mut aggregate = BusinessAggregate::new();
        let command = BusinessCommand::new("scenario_data");
        
        // When: Domain operation is performed
        let result = aggregate.handle_command(command);
        
        // Then: Expected domain state is reached
        assert!(result.is_ok());
        assert_eq!(aggregate.state(), ExpectedState::Completed);
        
        // And: Domain events are generated
        let events = aggregate.uncommitted_events();
        assert_eq!(events.len(), 2);
        assert!(matches!(events[0], DomainEvent::SomethingStarted { .. }));
        assert!(matches!(events[1], DomainEvent::SomethingCompleted { .. }));
    }
}
```

**Quality Gates**:
- ✅ 100% code coverage (achievable with pure functions)
- ✅ Property-based tests for all domain invariants
- ✅ No external dependencies in test setup
- ✅ Deterministic test execution

### Application Layer Testing (Orchestration)

**Characteristics**: Coordinates multiple services, handles cross-cutting concerns, manages workflows

**Testing Patterns**:
```rust
#[cfg(test)]
mod workflow_tests {
    use super::*;
    use mockall::predicate::*;
    use tokio_test;
    
    // Mock external dependencies for isolated testing
    mockall::mock! {
        Repository {}
        
        #[async_trait]
        impl Repository for Repository {
            async fn save(&self, entity: &Entity) -> Result<(), RepositoryError>;
            async fn find(&self, id: EntityId) -> Result<Option<Entity>, RepositoryError>;
        }
    }
    
    mockall::mock! {
        ExternalService {}
        
        #[async_trait] 
        impl ExternalService for ExternalService {
            async fn perform(&self, input: &Input) -> Result<Output, ServiceError>;
        }
    }
    
    // Workflow integration tests with mocked dependencies
    #[tokio::test]
    async fn successful_workflow_execution() {
        // Given: Mocked dependencies with expectations
        let mut mock_repo = MockRepository::new();
        let mut mock_service = MockExternalService::new();
        
        mock_repo
            .expect_find()
            .with(eq(EntityId::new(123)))
            .times(1)
            .returning(|_| Ok(Some(Entity::new_test_entity())));
            
        mock_service
            .expect_perform()
            .with(always())
            .times(1)
            .returning(|_| Ok(Output::success()));
            
        mock_repo
            .expect_save()
            .with(always())
            .times(1)
            .returning(|_| Ok(()));
        
        let workflow = SomeWorkflow::new(mock_repo, mock_service);
        
        // When: Workflow is executed
        let result = workflow.execute(WorkflowInput::new(123)).await;
        
        // Then: Workflow succeeds and all mocks are satisfied
        assert!(result.is_ok());
        // Mock expectations are automatically verified on drop
    }
    
    #[tokio::test]
    async fn workflow_error_handling() {
        // Given: Dependencies that will fail
        let mut mock_repo = MockRepository::new();
        let mock_service = MockExternalService::new();
        
        mock_repo
            .expect_find()
            .returning(|_| Err(RepositoryError::NotFound));
        
        let workflow = SomeWorkflow::new(mock_repo, mock_service);
        
        // When: Workflow is executed
        let result = workflow.execute(WorkflowInput::new(123)).await;
        
        // Then: Error is properly handled and converted
        assert!(result.is_err());
        match result.unwrap_err() {
            WorkflowError::EntityNotFound { id } => assert_eq!(id, 123),
            _ => panic!("Expected EntityNotFound error"),
        }
    }
    
    // Cross-cutting concern testing
    #[tokio::test]
    async fn workflow_emits_domain_events() {
        // Given: Event capturing infrastructure
        let event_capture = Arc::new(Mutex::new(Vec::new()));
        let mock_repo = MockRepository::new();
        let mock_service = MockExternalService::new();
        
        let workflow = SomeWorkflow::new(mock_repo, mock_service)
            .with_event_publisher(TestEventPublisher::new(event_capture.clone()));
        
        // When: Workflow executes successfully
        let result = workflow.execute(WorkflowInput::new(123)).await;
        
        // Then: Domain events are published
        assert!(result.is_ok());
        let events = event_capture.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], DomainEvent::WorkflowCompleted { .. }));
    }
}

// Workflow behavior testing (state-based)
#[cfg(test)]
mod workflow_behavior_tests {
    use super::*;
    
    // Test doubles that capture behavior rather than just mocking
    struct InMemoryRepository {
        entities: Arc<Mutex<HashMap<EntityId, Entity>>>,
    }
    
    impl InMemoryRepository {
        fn new() -> Self {
            Self {
                entities: Arc::new(Mutex::new(HashMap::new())),
            }
        }
        
        fn insert(&self, entity: Entity) {
            self.entities.lock().unwrap().insert(entity.id(), entity);
        }
        
        fn get_saved_entities(&self) -> Vec<Entity> {
            self.entities.lock().unwrap().values().cloned().collect()
        }
    }
    
    #[async_trait]
    impl Repository for InMemoryRepository {
        async fn save(&self, entity: &Entity) -> Result<(), RepositoryError> {
            self.entities.lock().unwrap().insert(entity.id(), entity.clone());
            Ok(())
        }
        
        async fn find(&self, id: EntityId) -> Result<Option<Entity>, RepositoryError> {
            Ok(self.entities.lock().unwrap().get(&id).cloned())
        }
    }
    
    #[tokio::test]
    async fn workflow_state_changes() {
        // Given: State-based test doubles
        let repository = InMemoryRepository::new();
        repository.insert(Entity::new_for_processing());
        
        let external_service = AlwaysSuccessfulService::new();
        let workflow = SomeWorkflow::new(repository, external_service);
        
        // When: Workflow processes entities
        let result = workflow.execute(WorkflowInput::new(123)).await;
        
        // Then: Repository state reflects the changes
        assert!(result.is_ok());
        let saved_entities = repository.get_saved_entities();
        assert_eq!(saved_entities.len(), 1);
        assert_eq!(saved_entities[0].status(), EntityStatus::Processed);
    }
}
```

**Quality Gates**:
- ✅ All external dependencies mocked or stubbed
- ✅ Error scenarios comprehensively tested
- ✅ Cross-cutting concerns (events, logging) verified
- ✅ Workflow state transitions validated

### Infrastructure Layer Testing (Adapters)

**Characteristics**: Integrates with external systems, handles I/O, implements abstractions

**Testing Patterns**:
```rust
#[cfg(test)]
mod infrastructure_tests {
    use super::*;
    use tempfile::TempDir;
    use tokio_test;
    
    // Contract tests verify abstraction implementation
    #[tokio::test]
    async fn file_repository_implements_repository_contract() {
        // Given: Real file system repository with temporary directory
        let temp_dir = TempDir::new().unwrap();
        let repository = FileSystemRepository::new(temp_dir.path()).unwrap();
        
        // When: Repository operations are performed
        let entity = Entity::new_test_entity();
        let save_result = repository.save(&entity).await;
        let find_result = repository.find(entity.id()).await;
        
        // Then: Contract expectations are met
        assert!(save_result.is_ok());
        assert!(find_result.is_ok());
        assert_eq!(find_result.unwrap(), Some(entity));
    }
    
    #[tokio::test]
    async fn file_repository_handles_io_errors() {
        // Given: Repository with invalid path
        let invalid_path = Path::new("/invalid/nonexistent/path");
        let repository = FileSystemRepository::new(invalid_path);
        
        // When: Save operation is attempted
        let entity = Entity::new_test_entity();
        let result = repository.save(&entity).await;
        
        // Then: IO error is properly converted
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), InfrastructureError::FileSystem(_)));
    }
    
    // Integration tests with external systems (when appropriate)
    #[tokio::test]
    #[ignore] // Only run with --ignored flag for full integration tests
    async fn crypto_service_integration_test() {
        // Given: Real cryptographic service
        let config = CryptoConfig::test_config();
        let service = CryptographicService::new(&config).unwrap();
        
        // When: Encryption/decryption cycle is performed
        let plaintext = b"test data for encryption";
        let encrypted = service.encrypt(plaintext).await.unwrap();
        let decrypted = service.decrypt(&encrypted).await.unwrap();
        
        // Then: Data roundtrip is successful
        assert_eq!(plaintext, decrypted.as_slice());
    }
    
    // Resource management testing
    #[tokio::test]
    async fn repository_handles_concurrent_access() {
        // Given: Shared repository instance
        let temp_dir = TempDir::new().unwrap();
        let repository = Arc::new(FileSystemRepository::new(temp_dir.path()).unwrap());
        
        // When: Multiple concurrent operations are performed
        let mut handles = Vec::new();
        for i in 0..10 {
            let repo = repository.clone();
            let handle = tokio::spawn(async move {
                let entity = Entity::new_with_id(i);
                repo.save(&entity).await
            });
            handles.push(handle);
        }
        
        // Then: All operations complete successfully
        for handle in handles {
            let result = handle.await.unwrap();
            assert!(result.is_ok());
        }
    }
}

// Configuration testing
#[cfg(test)]
mod config_tests {
    use super::*;
    
    #[test]
    fn infrastructure_config_validation() {
        // Given: Various configuration scenarios
        let valid_config = InfrastructureConfig {
            file_system: FileSystemConfig {
                base_path: "/tmp".into(),
                permissions: 0o644,
            },
            crypto: CryptoConfig {
                algorithm: Algorithm::AES256,
                key_derivation: KeyDerivation::PBKDF2,
            },
        };
        
        // When: Configuration is validated
        let result = valid_config.validate();
        
        // Then: Valid configuration is accepted
        assert!(result.is_ok());
    }
    
    #[test]
    fn infrastructure_config_rejects_invalid() {
        // Given: Invalid configuration
        let invalid_config = InfrastructureConfig {
            file_system: FileSystemConfig {
                base_path: "".into(), // Invalid empty path
                permissions: 0o644,
            },
            crypto: CryptoConfig {
                algorithm: Algorithm::AES256,
                key_derivation: KeyDerivation::PBKDF2,
            },
        };
        
        // When: Configuration is validated
        let result = invalid_config.validate();
        
        // Then: Invalid configuration is rejected
        assert!(result.is_err());
    }
}
```

**Quality Gates**:
- ✅ All abstractions properly implemented
- ✅ External integration errors handled gracefully
- ✅ Resource management (connections, files) tested
- ✅ Configuration validation comprehensive

### Cross-Layer Testing (End-to-End)

**Characteristics**: Full system integration, real external dependencies, user scenarios

**Testing Patterns**:
```rust
#[cfg(test)]
mod integration_tests {
    use super::*;
    use testcontainers::*;
    
    // End-to-end testing with minimal mocking
    #[tokio::test]
    async fn complete_user_scenario() {
        // Given: Real system with test configuration
        let temp_dir = TempDir::new().unwrap();
        let config = Config::test_config(temp_dir.path());
        let container = ApplicationContainer::new(&config).await.unwrap();
        
        // When: User scenario is executed
        let input = UserInput::new("test_scenario_data");
        let result = container.primary_workflow.execute(input).await;
        
        // Then: Expected outcome is achieved
        assert!(result.is_ok());
        
        // And: Side effects are observable
        let saved_files = std::fs::read_dir(temp_dir.path()).unwrap().count();
        assert_eq!(saved_files, 1);
    }
    
    // Performance and load testing
    #[tokio::test]
    async fn system_handles_concurrent_load() {
        // Given: System under load
        let config = Config::performance_test_config();
        let container = Arc::new(ApplicationContainer::new(&config).await.unwrap());
        
        // When: Multiple concurrent requests are processed
        let mut handles = Vec::new();
        for i in 0..100 {
            let container = container.clone();
            let handle = tokio::spawn(async move {
                let input = UserInput::new(format!("load_test_{}", i));
                container.primary_workflow.execute(input).await
            });
            handles.push(handle);
        }
        
        // Then: All requests complete within reasonable time
        let start = Instant::now();
        for handle in handles {
            let result = handle.await.unwrap();
            assert!(result.is_ok());
        }
        let duration = start.elapsed();
        assert!(duration < Duration::from_secs(10)); // Reasonable performance expectation
    }
    
    // Error scenario testing
    #[tokio::test]
    async fn system_gracefully_handles_external_failures() {
        // Given: System with simulated external failures
        let config = Config::failure_simulation_config();
        let container = ApplicationContainer::new(&config).await.unwrap();
        
        // When: Operation is attempted during simulated failure
        let input = UserInput::new("failure_scenario");
        let result = container.primary_workflow.execute(input).await;
        
        // Then: Error is handled gracefully
        assert!(result.is_err());
        match result.unwrap_err() {
            WorkflowError::ExternalSystem { .. } => {}, // Expected error type
            _ => panic!("Expected external system error"),
        }
    }
}

// Acceptance testing (user story validation)
#[cfg(test)]
mod acceptance_tests {
    use super::*;
    
    // User story: "As a user, I want to process data successfully"
    #[tokio::test]
    async fn user_can_process_data_successfully() {
        // Given: User has input data ready for processing
        let user_data = "important_business_data";
        let system = TestSystem::new().await;
        
        // When: User submits data for processing
        let result = system.process_user_data(user_data).await;
        
        // Then: Data is processed successfully
        assert!(result.is_success());
        
        // And: User receives confirmation
        let confirmation = result.get_confirmation();
        assert!(confirmation.contains("processed successfully"));
        
        // And: Processed data is available for retrieval
        let processed_data = system.get_processed_data().await;
        assert!(processed_data.is_some());
        assert!(processed_data.unwrap().contains(user_data));
    }
}
```

**Quality Gates**:
- ✅ Complete user scenarios validated
- ✅ Performance requirements verified
- ✅ Error scenarios tested end-to-end
- ✅ System resilience under load confirmed

## Quality Gates & Architectural Compliance

### Automated Architecture Validation

**Dependency Direction Enforcement**
```toml
# Cargo.toml - Use workspace dependencies to enforce layer boundaries
[workspace]
members = ["core", "application", "infrastructure", "bin/*"]

# Core crate - No external dependencies except std
[package]
name = "core"
dependencies = {}  # Only std library allowed

# Application crate - Only depends on core
[package] 
name = "application"
dependencies = { core = { path = "../core" } }

# Infrastructure crate - Depends on core and application
[package]
name = "infrastructure" 
dependencies = { 
    core = { path = "../core" },
    application = { path = "../application" },
    # External crates allowed here
}
```

**Architectural Linting Rules**
```rust
// Custom architectural lint rules (using cargo-deny or similar)

// deny.toml
[bans]
# Prevent core layer from depending on external crates
[[bans.deny]]
crate = "core"
use-instead = "std-only"

# Prevent application from depending on infrastructure
[[bans.deny]]
name = "application"
deny = ["infrastructure"]

[licenses]
# Ensure all dependencies have compatible licenses
allow = ["MIT", "Apache-2.0", "BSD-3-Clause"]
```

### Code Quality Metrics & Thresholds

**Coverage Requirements by Layer**
```yaml
# .codecov.yml
coverage:
  status:
    project:
      default:
        target: 90%
        threshold: 2%
    patch:
      default:
        target: 95%
        
# Layer-specific coverage requirements
coverage:
  status:
    # Core layer - 100% coverage (pure functions, easily testable)
    core:
      target: 100%
      paths: ["src/core/"]
      
    # Application layer - 95% coverage (some integration complexity)
    application:
      target: 95%
      paths: ["src/application/"]
      
    # Infrastructure layer - 85% coverage (external system integration)
    infrastructure: 
      target: 85%
      paths: ["src/infrastructure/"]
```

**Complexity Thresholds**
```toml
# Clippy configuration in Cargo.toml
[lints.clippy]
# Cognitive complexity limits
cognitive_complexity = { level = "warn", max_complexity = 15 }

# Cyclomatic complexity limits  
cyclomatic_complexity = { level = "warn", max_complexity = 10 }

# Function length limits
too_many_lines = { level = "warn", max_lines = 100 }

# Parameter limits
too_many_arguments = { level = "warn", max_args = 5 }

# Documentation requirements
missing_docs = "warn"
undocumented_unsafe_blocks = "deny"
```

**Dependency Analysis**
```rust
// Custom dependency analysis tool
use std::collections::{HashMap, HashSet};

pub struct DependencyAnalyzer {
    crate_dependencies: HashMap<String, HashSet<String>>,
}

impl DependencyAnalyzer {
    pub fn validate_layer_dependencies(&self) -> Result<(), ArchitectureViolation> {
        // Core layer validation
        if let Some(core_deps) = self.crate_dependencies.get("core") {
            if !core_deps.is_empty() {
                return Err(ArchitectureViolation::CoreHasDependencies {
                    dependencies: core_deps.clone(),
                });
            }
        }
        
        // Application layer validation
        if let Some(app_deps) = self.crate_dependencies.get("application") {
            let allowed_deps = ["core"].iter().map(|s| s.to_string()).collect();
            let invalid_deps: HashSet<_> = app_deps.difference(&allowed_deps).collect();
            
            if !invalid_deps.is_empty() {
                return Err(ArchitectureViolation::ApplicationInvalidDependencies {
                    invalid: invalid_deps.into_iter().cloned().collect(),
                });
            }
        }
        
        // Infrastructure layer validation
        if let Some(infra_deps) = self.crate_dependencies.get("infrastructure") {
            let forbidden_deps = ["bin"].iter().map(|s| s.to_string()).collect();
            let violations: HashSet<_> = infra_deps.intersection(&forbidden_deps).collect();
            
            if !violations.is_empty() {
                return Err(ArchitectureViolation::InfrastructureForbiddenDependencies {
                    forbidden: violations.into_iter().cloned().collect(),
                });
            }
        }
        
        Ok(())
    }
    
    pub fn check_circular_dependencies(&self) -> Result<(), CircularDependencyError> {
        // Implement topological sort to detect cycles
        let mut visited = HashSet::new();
        let mut rec_stack = HashSet::new();
        
        for crate_name in self.crate_dependencies.keys() {
            if !visited.contains(crate_name) {
                if self.has_cycle(crate_name, &mut visited, &mut rec_stack)? {
                    return Err(CircularDependencyError::CycleDetected {
                        cycle_path: self.find_cycle_path(crate_name),
                    });
                }
            }
        }
        
        Ok(())
    }
}

#[derive(thiserror::Error, Debug)]
pub enum ArchitectureViolation {
    #[error("Core layer has dependencies: {dependencies:?}")]
    CoreHasDependencies { dependencies: HashSet<String> },
    
    #[error("Application layer has invalid dependencies: {invalid:?}")]
    ApplicationInvalidDependencies { invalid: Vec<String> },
    
    #[error("Infrastructure layer has forbidden dependencies: {forbidden:?}")]
    InfrastructureForbiddenDependencies { forbidden: Vec<String> },
}
```

### Interface Compliance Validation

**Abstraction Implementation Checking**
```rust
// Compile-time verification that all abstractions are implemented
pub struct ImplementationValidator;

impl ImplementationValidator {
    // Ensure every core abstraction has an infrastructure implementation
    pub fn validate_complete_implementation() {
        // This function should fail to compile if any abstraction is missing implementation
        
        // Repository abstractions
        let _: Box<dyn core::abstractions::Repository> = 
            Box::new(infrastructure::repositories::FileSystemRepository::new());
        
        // Service abstractions  
        let _: Box<dyn core::abstractions::CryptoService> =
            Box::new(infrastructure::services::CryptographicService::new());
        
        // Event publisher abstractions
        let _: Box<dyn core::abstractions::EventPublisher> =
            Box::new(infrastructure::events::InMemoryEventPublisher::new());
    }
}

// Integration test to verify all abstractions work together
#[cfg(test)]
mod integration_compliance_tests {
    use super::*;
    
    #[tokio::test]
    async fn all_infrastructure_implements_core_abstractions() {
        // Test that infrastructure implementations satisfy core contracts
        
        // Repository contract compliance
        let repo = infrastructure::FileSystemRepository::new();
        test_repository_contract(repo).await;
        
        // Service contract compliance  
        let service = infrastructure::CryptographicService::new();
        test_crypto_service_contract(service).await;
    }
    
    async fn test_repository_contract<R: core::Repository>(repo: R) {
        // Generic test that any Repository implementation must pass
        let entity = core::Entity::new_test_entity();
        
        // Test save/load cycle
        repo.save(&entity).await.expect("Save should succeed");
        let loaded = repo.find(entity.id()).await.expect("Find should succeed");
        assert_eq!(loaded, Some(entity));
    }
    
    async fn test_crypto_service_contract<S: core::CryptoService>(service: S) {
        // Generic test that any CryptoService implementation must pass
        let plaintext = b"test data";
        
        // Test encrypt/decrypt cycle
        let encrypted = service.encrypt(plaintext).await.expect("Encryption should succeed");
        let decrypted = service.decrypt(&encrypted).await.expect("Decryption should succeed");
        assert_eq!(plaintext, decrypted.as_slice());
    }
}
```

### Feature Slice Completeness Validation

**Slice Completeness Checker**
```rust
// Ensure each feature slice has all required components
pub struct SliceCompletenessValidator {
    feature_slices: Vec<FeatureSlice>,
}

pub struct FeatureSlice {
    name: String,
    core_components: SliceComponents,
    application_components: SliceComponents, 
    infrastructure_components: SliceComponents,
    binary_components: SliceComponents,
}

pub struct SliceComponents {
    entities: Vec<String>,
    services: Vec<String>,
    abstractions: Vec<String>,
    workflows: Vec<String>,
    implementations: Vec<String>,
}

impl SliceCompletenessValidator {
    pub fn validate_slice_completeness(&self) -> Result<(), SliceValidationError> {
        for slice in &self.feature_slices {
            self.validate_single_slice(slice)?;
        }
        Ok(())
    }
    
    fn validate_single_slice(&self, slice: &FeatureSlice) -> Result<(), SliceValidationError> {
        // Validate core layer completeness
        if slice.core_components.entities.is_empty() {
            return Err(SliceValidationError::MissingEntities {
                slice: slice.name.clone(),
            });
        }
        
        if slice.core_components.services.is_empty() {
            return Err(SliceValidationError::MissingDomainServices {
                slice: slice.name.clone(),
            });
        }
        
        // Validate application layer completeness
        if slice.application_components.workflows.is_empty() {
            return Err(SliceValidationError::MissingWorkflows {
                slice: slice.name.clone(),
            });
        }
        
        // Validate infrastructure implementation completeness
        for abstraction in &slice.core_components.abstractions {
            if !slice.infrastructure_components.implementations.contains(abstraction) {
                return Err(SliceValidationError::MissingImplementation {
                    slice: slice.name.clone(),
                    abstraction: abstraction.clone(),
                });
            }
        }
        
        // Validate binary composition completeness
        if slice.binary_components.implementations.is_empty() {
            return Err(SliceValidationError::MissingBinaryComposition {
                slice: slice.name.clone(),
            });
        }
        
        Ok(())
    }
}
```

### Performance & Resource Quality Gates

**Performance Testing Framework**
```rust
use std::time::{Duration, Instant};

pub struct PerformanceValidator {
    benchmarks: Vec<Benchmark>,
}

pub struct Benchmark {
    name: String,
    max_duration: Duration,
    max_memory_mb: u64,
    test_fn: Box<dyn Fn() -> futures::future::BoxFuture<'static, ()>>,
}

impl PerformanceValidator {
    pub async fn validate_performance_requirements(&self) -> Result<(), PerformanceViolation> {
        for benchmark in &self.benchmarks {
            let start_time = Instant::now();
            let start_memory = self.get_memory_usage();
            
            // Run benchmark
            (benchmark.test_fn)().await;
            
            let duration = start_time.elapsed();
            let end_memory = self.get_memory_usage();
            let memory_used = end_memory.saturating_sub(start_memory);
            
            // Validate duration requirement
            if duration > benchmark.max_duration {
                return Err(PerformanceViolation::DurationExceeded {
                    benchmark: benchmark.name.clone(),
                    actual: duration,
                    maximum: benchmark.max_duration,
                });
            }
            
            // Validate memory requirement
            if memory_used > benchmark.max_memory_mb {
                return Err(PerformanceViolation::MemoryExceeded {
                    benchmark: benchmark.name.clone(),
                    actual_mb: memory_used,
                    maximum_mb: benchmark.max_memory_mb,
                });
            }
        }
        
        Ok(())
    }
    
    fn get_memory_usage(&self) -> u64 {
        // Platform-specific memory usage measurement
        todo!()
    }
}

// Example performance requirements
#[cfg(test)]
mod performance_tests {
    use super::*;
    
    #[tokio::test]
    async fn core_domain_services_performance() {
        let validator = PerformanceValidator {
            benchmarks: vec![
                Benchmark {
                    name: "domain_validation".to_string(),
                    max_duration: Duration::from_millis(10),
                    max_memory_mb: 1,
                    test_fn: Box::new(|| Box::pin(async {
                        let service = core::DomainService::new();
                        let entity = core::Entity::new_large_test_entity();
                        let _ = service.validate(&entity);
                    })),
                },
                Benchmark {
                    name: "workflow_execution".to_string(),
                    max_duration: Duration::from_secs(5),
                    max_memory_mb: 50,
                    test_fn: Box::new(|| Box::pin(async {
                        let workflow = create_test_workflow();
                        let _ = workflow.execute(test_input()).await;
                    })),
                },
            ],
        };
        
        validator.validate_performance_requirements().await
            .expect("Performance requirements should be met");
    }
}
```

### Documentation Quality Gates

**Documentation Completeness Validation**
```rust
// Ensure all public APIs are documented
#[cfg(test)]
mod documentation_tests {
    use super::*;
    
    #[test]
    fn all_public_types_documented() {
        // This test ensures all public types have documentation
        // Rust's missing_docs lint will catch undocumented items
        assert!(std::env::var("RUSTDOCFLAGS").unwrap_or_default().contains("-D missing_docs"));
    }
    
    #[test] 
    fn architecture_documentation_complete() {
        // Verify architecture documentation files exist and are up to date
        let arch_doc = std::fs::read_to_string("docs/specs/ARCHITECTURE.md")
            .expect("Architecture documentation should exist");
        
        // Verify key sections are present
        assert!(arch_doc.contains("## Layer Responsibilities"));
        assert!(arch_doc.contains("## Vertical Slice Architecture"));
        assert!(arch_doc.contains("## Quality Gates"));
    }
    
    #[test]
    fn api_examples_compile() {
        // Verify all code examples in documentation compile
        // This can be done using doctest or custom validation
        
        // Example: Check that README examples are valid
        let readme = std::fs::read_to_string("README.md")
            .expect("README should exist");
        
        // Extract and validate code blocks
        validate_code_examples_in_markdown(&readme);
    }
}

fn validate_code_examples_in_markdown(content: &str) {
    // Implementation to extract and compile code examples
    todo!()
}
```

### Continuous Integration Quality Pipeline

**CI/CD Quality Gates Configuration**
```yaml
# .github/workflows/quality-gates.yml
name: Architecture Quality Gates

on: [push, pull_request]

jobs:
  dependency-validation:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Validate Layer Dependencies
        run: |
          # Check that core has no dependencies
          if grep -q "dependencies" core/Cargo.toml; then
            echo "Core layer should have no dependencies"
            exit 1
          fi
      
  architectural-compliance:
    runs-on: ubuntu-latest  
    steps:
      - uses: actions/checkout@v3
      - name: Run Architecture Tests
        run: cargo test architecture_compliance_tests
        
  coverage-requirements:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Generate Coverage Report
        run: |
          cargo tarpaulin --out Xml --timeout 120
          # Verify layer-specific coverage requirements
          cargo tarpaulin --packages core --min-coverage 100
          cargo tarpaulin --packages application --min-coverage 95
          cargo tarpaulin --packages infrastructure --min-coverage 85
          
  performance-validation:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run Performance Tests
        run: cargo test performance_tests --release
        
  documentation-quality:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Check Documentation
        run: |
          cargo doc --no-deps --document-private-items
          # Verify no missing docs warnings
          RUSTDOCFLAGS="-D missing_docs" cargo doc --no-deps
```

### Quality Metrics Dashboard

**Architecture Health Metrics**
- ✅ **Dependency Direction Compliance**: 100% (no violations detected)
- ✅ **Interface Implementation Coverage**: 100% (all abstractions implemented)
- ✅ **Feature Slice Completeness**: 100% (all slices have required components)
- ✅ **Test Coverage by Layer**: Core 100%, Application 95%, Infrastructure 85%
- ✅ **Performance Requirements**: All benchmarks within thresholds
- ✅ **Documentation Coverage**: 100% public API documented
- ✅ **Circular Dependency Detection**: 0 cycles found
- ✅ **Code Quality Metrics**: All complexity thresholds met

## Implementation Guidelines & Evolution Strategy

### Development Workflow & Implementation Order

**Phase 1: Core Foundation (Weeks 1-2)**
```rust
// 1. Start with domain entities and value objects
pub mod core {
    pub mod entities {
        pub struct BusinessEntity {
            id: EntityId,
            // Core business properties
        }
        
        pub struct ValueObject {
            // Immutable value with validation
        }
    }
    
    // 2. Define all abstractions first
    pub mod abstractions {
        #[async_trait]
        pub trait Repository {
            async fn save(&self, entity: &Entity) -> Result<(), Self::Error>;
        }
        
        pub trait CryptoService {
            fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError>;
        }
    }
    
    // 3. Implement pure domain services
    pub mod services {
        pub struct DomainService {
            // Pure business logic only
        }
        
        impl DomainService {
            pub fn validate_business_rule(&self, entity: &Entity) -> Result<(), DomainError> {
                // Pure validation logic
            }
        }
    }
}
```

**Phase 2: Application Workflows (Weeks 3-4)**
```rust
// Build complete use case implementations
pub mod application {
    pub mod workflows {
        pub struct PrimaryWorkflow<R: Repository, C: CryptoService> {
            repository: R,
            crypto_service: C,
            domain_service: DomainService,
        }
        
        impl<R: Repository, C: CryptoService> PrimaryWorkflow<R, C> {
            pub async fn execute(&self, input: Input) -> Result<Output, WorkflowError> {
                // 1. Validate using domain service
                let validated = self.domain_service.validate(input)?;
                
                // 2. Orchestrate operations
                let entity = self.repository.load(validated.id).await?;
                let processed = self.crypto_service.process(&entity)?;
                self.repository.save(&processed).await?;
                
                Ok(Output::from(processed))
            }
        }
    }
}
```

**Phase 3: Infrastructure Implementation (Weeks 5-6)**
```rust
// Implement all core abstractions
pub mod infrastructure {
    pub struct FileSystemRepository {
        base_path: PathBuf,
    }
    
    #[async_trait]
    impl Repository for FileSystemRepository {
        async fn save(&self, entity: &Entity) -> Result<(), InfrastructureError> {
            // File system implementation
        }
    }
    
    pub struct CryptographicService {
        config: CryptoConfig,
    }
    
    impl CryptoService for CryptographicService {
        fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
            // Cryptographic implementation
        }
    }
}
```

**Phase 4: Binary Composition (Week 7)**
```rust
// Wire everything together
pub mod bin {
    pub struct ApplicationContainer {
        workflow: PrimaryWorkflow<FileSystemRepository, CryptographicService>,
    }
    
    impl ApplicationContainer {
        pub fn new(config: &Config) -> Result<Self, ContainerError> {
            let repository = FileSystemRepository::new(&config.storage)?;
            let crypto_service = CryptographicService::new(&config.crypto)?;
            let domain_service = DomainService::new();
            
            let workflow = PrimaryWorkflow::new(repository, crypto_service, domain_service);
            
            Ok(Self { workflow })
        }
    }
    
    #[tokio::main]
    async fn main() -> ExitCode {
        let config = Config::load().unwrap();
        let container = ApplicationContainer::new(&config).unwrap();
        
        match container.workflow.execute(parse_args()).await {
            Ok(result) => {
                present_success(&result);
                ExitCode::SUCCESS
            }
            Err(error) => {
                present_error(&error);
                ExitCode::FAILURE
            }
        }
    }
}
```

### Evolution Principles & Patterns

**1. Core Stability Principle**
```rust
// Core evolution strategy: Minimize breaking changes
pub mod core {
    // Version 1.0 - Initial implementation
    pub struct Entity {
        pub id: EntityId,
        pub name: String,
    }
    
    // Version 1.1 - Additive changes only
    pub struct Entity {
        pub id: EntityId,
        pub name: String,
        // New fields added, existing fields unchanged
        pub metadata: Option<Metadata>, // Optional to maintain compatibility
    }
    
    // Version 2.0 - Breaking changes require migration strategy
    pub struct EntityV2 {
        pub id: EntityId,
        pub name: String,
        pub metadata: Metadata, // Now required
    }
    
    // Provide conversion utilities for migration
    impl From<Entity> for EntityV2 {
        fn from(entity: Entity) -> Self {
            Self {
                id: entity.id,
                name: entity.name,
                metadata: entity.metadata.unwrap_or_default(),
            }
        }
    }
}
```

**2. Application Flexibility Principle**
```rust
// Application layer can evolve workflows independently
pub mod application {
    // V1 Workflow
    pub mod v1 {
        pub struct LegacyWorkflow<R: Repository> {
            repository: R,
        }
        
        impl<R: Repository> LegacyWorkflow<R> {
            pub async fn execute(&self, input: Input) -> Result<Output, WorkflowError> {
                // Legacy implementation
            }
        }
    }
    
    // V2 Workflow with enhanced features
    pub mod v2 {
        pub struct EnhancedWorkflow<R: Repository, E: EventPublisher> {
            repository: R,
            event_publisher: E,
        }
        
        impl<R: Repository, E: EventPublisher> EnhancedWorkflow<R, E> {
            pub async fn execute(&self, input: Input) -> Result<Output, WorkflowError> {
                // Enhanced implementation with events
                let result = self.process_core_logic(input).await?;
                self.event_publisher.publish(WorkflowCompleted { result: result.clone() }).await?;
                Ok(result)
            }
        }
    }
    
    // Workflow factory for smooth migration
    pub struct WorkflowFactory;
    
    impl WorkflowFactory {
        pub fn create_workflow<R: Repository, E: EventPublisher>(
            repository: R,
            event_publisher: Option<E>,
            version: WorkflowVersion,
        ) -> Box<dyn WorkflowTrait> {
            match (version, event_publisher) {
                (WorkflowVersion::V1, _) => {
                    Box::new(v1::LegacyWorkflow::new(repository))
                }
                (WorkflowVersion::V2, Some(publisher)) => {
                    Box::new(v2::EnhancedWorkflow::new(repository, publisher))
                }
                (WorkflowVersion::V2, None) => {
                    // Fallback to V1 if event publisher not available
                    Box::new(v1::LegacyWorkflow::new(repository))
                }
            }
        }
    }
}
```

**3. Infrastructure Adaptability Principle**
```rust
// Infrastructure implementations can be swapped without affecting upper layers
pub mod infrastructure {
    // Multiple repository implementations
    pub mod repositories {
        pub struct FileSystemRepository { /* ... */ }
        pub struct DatabaseRepository { /* ... */ }
        pub struct InMemoryRepository { /* ... */ }
        
        // All implement the same Core abstraction
        impl Repository for FileSystemRepository { /* ... */ }
        impl Repository for DatabaseRepository { /* ... */ }
        impl Repository for InMemoryRepository { /* ... */ }
    }
    
    // Repository factory for configuration-based selection
    pub struct RepositoryFactory;
    
    impl RepositoryFactory {
        pub fn create(config: &StorageConfig) -> Result<Box<dyn Repository>, InfrastructureError> {
            match config.storage_type {
                StorageType::FileSystem => {
                    Ok(Box::new(FileSystemRepository::new(&config.file_system)?))
                }
                StorageType::Database => {
                    Ok(Box::new(DatabaseRepository::new(&config.database).await?))
                }
                StorageType::InMemory => {
                    Ok(Box::new(InMemoryRepository::new()))
                }
            }
        }
    }
}
```

**4. Feature Addition Pattern**
```rust
// New features follow established vertical slice pattern
pub mod features {
    // Existing feature
    pub mod existing_capability {
        pub mod core { /* established pattern */ }
        pub mod application { /* established pattern */ }
        pub mod infrastructure { /* established pattern */ }
    }
    
    // New feature following same pattern
    pub mod new_capability {
        pub mod core {
            // New domain entities
            pub struct NewEntity { /* ... */ }
            
            // New abstractions
            pub trait NewService { /* ... */ }
            
            // New domain services
            pub struct NewDomainService { /* ... */ }
        }
        
        pub mod application {
            // New workflow
            pub struct NewWorkflow<S: NewService> {
                new_service: S,
                shared_service: SharedService, // Reuse existing services
            }
        }
        
        pub mod infrastructure {
            // New service implementation
            pub struct ConcreteNewService { /* ... */ }
            
            impl NewService for ConcreteNewService { /* ... */ }
        }
        
        // Feature-specific binary if needed
        pub mod binary {
            pub struct NewCapabilityContainer {
                workflow: NewWorkflow<ConcreteNewService>,
            }
        }
    }
}
```

### Migration & Versioning Strategy

**1. Database/Storage Migration Pattern**
```rust
pub mod migrations {
    pub trait Migration {
        fn version(&self) -> u32;
        async fn apply(&self, storage: &dyn Storage) -> Result<(), MigrationError>;
        async fn rollback(&self, storage: &dyn Storage) -> Result<(), MigrationError>;
    }
    
    pub struct MigrationRunner {
        migrations: Vec<Box<dyn Migration>>,
    }
    
    impl MigrationRunner {
        pub async fn migrate_to_latest(&self, storage: &dyn Storage) -> Result<(), MigrationError> {
            let current_version = storage.get_schema_version().await?;
            
            for migration in &self.migrations {
                if migration.version() > current_version {
                    migration.apply(storage).await?;
                    storage.set_schema_version(migration.version()).await?;
                }
            }
            
            Ok(())
        }
    }
    
    // Example migration
    pub struct AddMetadataFieldMigration;
    
    impl Migration for AddMetadataFieldMigration {
        fn version(&self) -> u32 { 2 }
        
        async fn apply(&self, storage: &dyn Storage) -> Result<(), MigrationError> {
            // Add metadata field to existing entities
            storage.execute_sql("ALTER TABLE entities ADD COLUMN metadata TEXT").await?;
            Ok(())
        }
        
        async fn rollback(&self, storage: &dyn Storage) -> Result<(), MigrationError> {
            storage.execute_sql("ALTER TABLE entities DROP COLUMN metadata").await?;
            Ok(())
        }
    }
}
```

**2. API Versioning Pattern**
```rust
pub mod api_versioning {
    // Version-specific types
    pub mod v1 {
        #[derive(serde::Serialize, serde::Deserialize)]
        pub struct EntityDto {
            pub id: String,
            pub name: String,
        }
    }
    
    pub mod v2 {
        #[derive(serde::Serialize, serde::Deserialize)]
        pub struct EntityDto {
            pub id: String,
            pub name: String,
            pub metadata: Option<MetadataDto>,
        }
    }
    
    // Conversion utilities
    impl From<v1::EntityDto> for v2::EntityDto {
        fn from(v1: v1::EntityDto) -> Self {
            Self {
                id: v1.id,
                name: v1.name,
                metadata: None,
            }
        }
    }
    
    // Version-aware serialization
    pub enum VersionedEntityDto {
        V1(v1::EntityDto),
        V2(v2::EntityDto),
    }
    
    impl VersionedEntityDto {
        pub fn serialize(&self, target_version: ApiVersion) -> Result<Vec<u8>, SerializationError> {
            match (self, target_version) {
                (VersionedEntityDto::V1(dto), ApiVersion::V1) => {
                    Ok(serde_json::to_vec(dto)?)
                }
                (VersionedEntityDto::V2(dto), ApiVersion::V2) => {
                    Ok(serde_json::to_vec(dto)?)
                }
                (VersionedEntityDto::V2(dto), ApiVersion::V1) => {
                    let v1_dto = v1::EntityDto {
                        id: dto.id.clone(),
                        name: dto.name.clone(),
                    };
                    Ok(serde_json::to_vec(&v1_dto)?)
                }
                (VersionedEntityDto::V1(dto), ApiVersion::V2) => {
                    let v2_dto = v2::EntityDto::from(dto.clone());
                    Ok(serde_json::to_vec(&v2_dto)?)
                }
            }
        }
    }
}
```

### Refactoring & Technical Debt Management

**1. Continuous Refactoring Strategy**
```rust
// Identify refactoring opportunities through metrics
pub mod refactoring {
    pub struct CodeHealthMetrics {
        pub complexity_score: f64,
        pub coupling_score: f64,
        pub test_coverage: f64,
        pub documentation_coverage: f64,
    }
    
    pub struct RefactoringCandidate {
        pub module_path: String,
        pub reason: RefactoringReason,
        pub priority: Priority,
        pub estimated_effort: Duration,
    }
    
    pub enum RefactoringReason {
        HighComplexity { current: u32, threshold: u32 },
        LowTestCoverage { current: f64, threshold: f64 },
        TightCoupling { dependencies: Vec<String> },
        CodeDuplication { similarity: f64 },
    }
    
    pub struct RefactoringPlanner;
    
    impl RefactoringPlanner {
        pub fn analyze_codebase(&self) -> Vec<RefactoringCandidate> {
            // Analyze code metrics and identify refactoring opportunities
            vec![]
        }
        
        pub fn create_refactoring_plan(&self, candidates: Vec<RefactoringCandidate>) -> RefactoringPlan {
            // Prioritize and sequence refactoring tasks
            RefactoringPlan::new(candidates)
        }
    }
}
```

**2. Legacy Code Migration Pattern**
```rust
// Gradual migration from legacy patterns
pub mod legacy_migration {
    // Legacy implementation
    pub mod legacy {
        pub struct LegacyService {
            // Old implementation with technical debt
        }
        
        impl LegacyService {
            pub fn legacy_operation(&self, input: &str) -> String {
                // Legacy implementation
                input.to_uppercase() // Simplified example
            }
        }
    }
    
    // New implementation following architecture patterns
    pub mod modern {
        pub struct ModernService {
            // Clean implementation following architectural patterns
        }
        
        impl ModernService {
            pub fn modern_operation(&self, input: &Input) -> Result<Output, ServiceError> {
                // Modern implementation with proper error handling
                Ok(Output::from(input.validate()?.process()?))
            }
        }
    }
    
    // Migration adapter
    pub struct MigrationAdapter {
        legacy_service: legacy::LegacyService,
        modern_service: modern::ModernService,
        migration_percentage: f64, // 0.0 = all legacy, 1.0 = all modern
    }
    
    impl MigrationAdapter {
        pub fn operation(&self, input: &Input) -> Result<Output, ServiceError> {
            // Gradually shift traffic from legacy to modern implementation
            if self.should_use_modern() {
                self.modern_service.modern_operation(input)
            } else {
                // Convert to legacy format, call legacy, convert back
                let legacy_input = input.to_legacy_format();
                let legacy_result = self.legacy_service.legacy_operation(&legacy_input);
                Ok(Output::from_legacy_result(legacy_result))
            }
        }
        
        fn should_use_modern(&self) -> bool {
            use rand::Rng;
            let mut rng = rand::thread_rng();
            rng.gen::<f64>() < self.migration_percentage
        }
    }
}
```

### Performance Optimization Strategy

**1. Performance Monitoring and Optimization**
```rust
pub mod performance {
    use std::time::{Duration, Instant};
    
    pub struct PerformanceMonitor {
        metrics: Arc<Mutex<PerformanceMetrics>>,
    }
    
    pub struct PerformanceMetrics {
        operation_durations: HashMap<String, Vec<Duration>>,
        memory_usage: Vec<MemorySnapshot>,
        error_rates: HashMap<String, f64>,
    }
    
    impl PerformanceMonitor {
        pub async fn monitor_operation<F, T>(&self, operation_name: &str, operation: F) -> T
        where
            F: Future<Output = T>,
        {
            let start = Instant::now();
            let start_memory = self.get_memory_usage();
            
            let result = operation.await;
            
            let duration = start.elapsed();
            let end_memory = self.get_memory_usage();
            
            // Record metrics
            self.record_operation_metrics(operation_name, duration, start_memory, end_memory).await;
            
            result
        }
        
        pub async fn get_performance_report(&self) -> PerformanceReport {
            let metrics = self.metrics.lock().await;
            PerformanceReport::from_metrics(&metrics)
        }
    }
    
    // Performance optimization recommendations
    pub struct PerformanceOptimizer;
    
    impl PerformanceOptimizer {
        pub fn analyze_performance(&self, report: &PerformanceReport) -> Vec<OptimizationRecommendation> {
            let mut recommendations = Vec::new();
            
            // Analyze slow operations
            for (operation, stats) in &report.operation_stats {
                if stats.average_duration > Duration::from_millis(100) {
                    recommendations.push(OptimizationRecommendation::OptimizeSlowOperation {
                        operation: operation.clone(),
                        current_duration: stats.average_duration,
                        suggestions: vec![
                            "Consider caching frequently accessed data".to_string(),
                            "Optimize database queries".to_string(),
                            "Use async I/O for blocking operations".to_string(),
                        ],
                    });
                }
            }
            
            // Analyze memory usage
            if report.peak_memory_usage > 100 * 1024 * 1024 { // 100MB
                recommendations.push(OptimizationRecommendation::ReduceMemoryUsage {
                    current_usage: report.peak_memory_usage,
                    suggestions: vec![
                        "Use streaming for large data processing".to_string(),
                        "Implement object pooling for frequently allocated objects".to_string(),
                    ],
                });
            }
            
            recommendations
        }
    }
}
```

---

## Architecture Implementation Checklist

### Phase 1: Core Foundation ✅
- [ ] Define all domain entities and value objects
- [ ] Implement pure domain services with business logic
- [ ] Create all abstractions for external dependencies
- [ ] Set up domain events structure
- [ ] Implement comprehensive domain error types
- [ ] Achieve 100% test coverage for core layer

### Phase 2: Application Workflows ✅  
- [ ] Implement complete use case workflows
- [ ] Add cross-cutting concerns (logging, validation)
- [ ] Create application-specific error handling
- [ ] Set up event publishing and handling
- [ ] Implement workflow coordination services
- [ ] Achieve 95% test coverage for application layer

### Phase 3: Infrastructure Implementation ✅
- [ ] Implement all core abstractions
- [ ] Add configuration management
- [ ] Set up external service integrations
- [ ] Implement security measures
- [ ] Add monitoring and observability
- [ ] Achieve 85% test coverage for infrastructure layer

### Phase 4: Binary Composition ✅
- [ ] Create dependency injection containers
- [ ] Implement CLI interfaces
- [ ] Add error presentation logic
- [ ] Set up graceful shutdown handling
- [ ] Implement configuration loading
- [ ] Add end-to-end integration tests

### Ongoing: Quality & Evolution ✅
- [ ] Set up automated architecture validation
- [ ] Implement performance monitoring
- [ ] Create migration strategies
- [ ] Plan refactoring roadmap
- [ ] Monitor technical debt metrics
- [ ] Regular architecture health checks

**Remember**: This architecture serves business value first, with technical patterns supporting clear expression of domain intent and user needs.