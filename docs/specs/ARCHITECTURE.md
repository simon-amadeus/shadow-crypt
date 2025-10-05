# Shadow Architecture Specification

> **Vision**: A screaming architecture that makes the system's intent immediately visible while maintaining clean separation of concerns through both horizontal layers and vertical feature slices.

## Architecture Overview

Shadow implements a **3-Layer + Vertical Slicing** architecture that combines the benefits of horizontal layer separation with feature-driven vertical organization.

**Dependency Flow** (Outermost to Innermost):
```
Binaries → Infrastructure → Application → Core
```

Each layer depends only on inner layers, with all abstractions defined in the Core layer.

```
┌─────────────────────────────────────────────────────────────┐
│                     Binary Entry Points                     │ 
│                   (shadow, unshadow, etc.)                  │
│                  Dependency Injection & Wiring              │
└─────────────────────────────────────────────────────────────┘
                                │
┌─────────────────────────────────────────────────────────────┐
│                 Infrastructure Layer                        │
│          External System Implementations                    │
│   ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐│
│   │  File System    │ │   Cryptography  │ │   Terminal I/O  ││
│   │  Repository     │ │  Implementation │ │  Implementation ││
│   └─────────────────┘ └─────────────────┘ └─────────────────┘│
└─────────────────────────────────────────────────────────────┘
                                │
┌─────────────────────────────────────────────────────────────┐
│                   Application Layer                         │
│              Workflow Orchestration & Use Cases             │
│   ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐│
│   │   Encryption    │ │   Decryption    │ │    Listing      ││
│   │   Workflow      │ │   Workflow      │ │   Workflow      ││
│   └─────────────────┘ └─────────────────┘ └─────────────────┘│
└─────────────────────────────────────────────────────────────┘
                                │
┌─────────────────────────────────────────────────────────────┐
│                      Core Layer                             │
│      Pure Business Logic, Entities & All Abstractions      │
│   ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐│
│   │    Entities     │ │    Services     │ │ ALL Abstractions││
│   │   (Models)      │ │ (Pure Logic)    │ │ (Interfaces)    ││
│   └─────────────────┘ └─────────────────┘ └─────────────────┘│
└─────────────────────────────────────────────────────────────┘
```

## Layer Responsibilities

### Core Layer (Pure Domain)
**Purpose**: Contains pure business logic with zero external dependencies and ALL abstractions.

**Responsibilities**:
- **Entities**: Core business models and value objects
- **Services**: Pure business logic and domain rules  
- **ALL Abstractions**: Every interface that outer layers implement (repositories, crypto services, progress reporting, etc.)
- **Domain Events**: Business events for cross-cutting concerns

**Dependencies**: None (dependency-free)
**Dependency Rule**: Core layer depends on nothing external and defines ALL interfaces

**Module Structure**:
```
core/
├── entities/           # Business models and value objects
├── services/          # Pure business logic
├── abstractions/      # ALL interfaces (repos, crypto, progress, etc.)
├── events/           # Domain events
└── errors/           # Domain-specific errors
```

### Application Layer (Orchestration)
**Purpose**: Orchestrates core services to implement complete use cases.

**Responsibilities**:
- **Workflows**: Complete user workflows and use cases
- **Cross-cutting Concerns**: Logging, metrics, validation
- **Transaction Coordination**: Ensuring consistency across operations
- **Error Handling**: Converting domain errors to user-friendly responses

**Dependencies**: Core Layer only
**Dependency Rule**: Application depends only on Core abstractions

**Module Structure**:
```
application/
├── workflows/         # Complete use case implementations
├── services/         # Application-level coordination services
├── containers/       # Dependency injection configuration
└── errors/          # Application-specific errors
```

### Infrastructure Layer (External Adapters)
**Purpose**: Implements ALL core abstractions using external systems.

**Responsibilities**:
- **Repository Implementations**: File system, database adapters
- **Service Implementations**: Crypto libraries, terminal I/O, progress reporting
- **Configuration**: System configuration and environment setup
- **Logging**: Infrastructure-level logging implementation

**Dependencies**: Core and Application layers
**Dependency Rule**: Infrastructure implements Core abstractions and depends on Application workflows

**Module Structure**:
```
infrastructure/
├── repositories/     # File system, database implementations
├── crypto/          # Cryptographic implementations
├── terminal/        # Terminal I/O implementations
├── progress/        # Progress reporting implementations
└── config/          # System configuration
```

### Binary Layer (Composition Root)
**Purpose**: Wire dependencies and provide entry points.

**Responsibilities**:
- **Dependency Injection**: Configure and wire all dependencies
- **Entry Points**: Main functions for each binary
- **Environment Setup**: Initialize system configuration
- **Error Presentation**: Convert application errors to user output

**Dependencies**: All layers (Infrastructure, Application, Core)
**Dependency Rule**: Binaries depend on all layers for composition

## Vertical Slicing Integration

### Feature-Driven Organization
Each major user capability is organized as a **vertical slice** that spans all three layers:

```
Feature: File Encryption
├── Core Layer        → EncryptionService + CryptoProvider abstraction + FileRepository abstraction
├── Application Layer → EncryptionWorkflow  
├── Infrastructure    → ConcreteCryptoProvider + ConcreteFileRepository
└── Binary           → Dependency wiring + CLI entry point

Feature: File Decryption  
├── Core Layer        → DecryptionService + ValidationService + abstractions
├── Application Layer → DecryptionWorkflow
├── Infrastructure    → Implementation of core abstractions
└── Binary           → Dependency wiring + CLI entry point

Feature: Shadow Listing
├── Core Layer        → ListingService + ShadowMetadata + abstractions
├── Application Layer → ListingWorkflow  
├── Infrastructure    → MetadataProvider + FileRepository implementations
└── Binary           → Dependency wiring + CLI entry point
```

### Slice Boundaries
**Primary Slices** (Complete user capabilities):
- **Encryption**: Transform plaintext files to encrypted shadows
- **Decryption**: Transform encrypted shadows back to plaintext
- **Listing**: Display shadow metadata and information
- **Migration**: Upgrade/migrate shadow file formats

**Supporting Slices** (Shared infrastructure):
- **Cryptography**: Core crypto operations and algorithms
- **File Management**: File I/O and metadata operations
- **Progress Reporting**: User feedback and progress indication

### Cross-Slice Communication
- **Within Core**: Direct service dependencies are allowed
- **Across Application**: Workflows can orchestrate multiple core services
- **Event-Driven**: Domain events for loose coupling between slices
- **Dependency Flow**: Always follows Binaries → Infrastructure → Application → Core

## Dependency Injection Architecture

### Container Design Principles
1. **Interface-Based**: All dependencies injected via Core abstractions
2. **Composition Root**: Single location for dependency wiring in binaries
3. **Immutable**: Dependencies resolved once at startup
4. **Testable**: Easy substitution for testing
5. **Dependency Flow**: Respects Binaries → Infrastructure → Application → Core

### Injection Patterns

#### Constructor Injection (Primary)
All dependencies are injected through constructor parameters using Core abstractions. Workflows receive their required services (crypto, file repository, progress reporter) as interface parameters, ensuring loose coupling and testability.

#### Factory Pattern (For Complex Construction)  
When object construction becomes complex, factory interfaces defined in Core allow Infrastructure to provide sophisticated construction logic while keeping the Application layer simple.

#### Container Interface
The dependency container provides access to all services through Core abstractions. It separates service creation from service usage, making the system highly modular and testable.

## Module Organization Principles

### Naming Conventions
- **Layers**: `core/`, `application/`, `infrastructure/`
- **Features**: Clear business capability names (`encryption/`, `decryption/`, `listing/`)
- **Components**: Descriptive names reflecting responsibility (`FileRepository`, `CryptoService`)

### File Organization
```
shadow/
├── core/
│   ├── encryption/         # Encryption domain slice
│   │   ├── entities.rs     # EncryptedFile, CryptoSession
│   │   ├── services.rs     # EncryptionService
│   │   └── abstractions.rs # CryptoProvider interface
│   ├── decryption/         # Decryption domain slice
│   ├── listing/            # Listing domain slice
│   └── shared/             # Cross-cutting domain concerns
├── application/
│   ├── encryption/         # Encryption workflows
│   ├── decryption/         # Decryption workflows
│   ├── listing/            # Listing workflows
│   └── shared/             # Cross-cutting application concerns
├── infrastructure/
│   ├── crypto/             # Cryptographic implementations
│   ├── filesystem/         # File system implementations
│   ├── terminal/           # Terminal I/O implementations
│   └── progress/           # Progress reporting implementations
└── bin/
    ├── shadow.rs           # Encryption binary
    ├── unshadow.rs         # Decryption binary
    ├── shadows.rs          # Listing binary
    └── shadowmigrate.rs    # Migration binary
```

### Module Visibility
- **Public APIs**: Only expose what other layers need
- **Internal Implementation**: Keep implementation details private
- **Cross-Layer**: Only Application and Infrastructure depend on Core

## Error Handling Strategy

### Error Type Hierarchy

**Core Layer - Domain-Specific Errors**
Pure business rule violations and domain constraint failures. These errors represent fundamental business logic problems independent of external systems.

**Application Layer - Workflow Errors**  
Orchestration failures and cross-cutting concerns. These errors wrap Core errors with additional context about which workflow failed and why.

**Infrastructure Layer - External System Errors**
File system failures, network issues, and external library errors. These represent problems with external dependencies and system resources.

### Error Conversion Strategy
- **Upward Flow**: Infrastructure → Application → Binary (following dependency direction)
- **Context Addition**: Each layer adds relevant context without losing original information
- **User-Friendly**: Final presentation suitable for end users with actionable guidance

## Testing Strategy

### Layer-Specific Testing

#### Core Layer Testing
- **Unit Tests**: Pure business logic testing
- **Property-Based Tests**: Domain invariants and rules
- **No Mocking**: Pure functions with no external dependencies

#### Application Layer Testing  
- **Workflow Tests**: Complete use case validation
- **Mock Infrastructure**: Test with mock implementations
- **Integration Tests**: Real core services, mocked infrastructure

#### Infrastructure Layer Testing
- **Adapter Tests**: Interface implementation correctness
- **External Integration**: Real external system testing
- **Contract Tests**: Verify adherence to core abstractions

### Cross-Layer Testing
- **End-to-End Tests**: Full system validation with real components
- **Acceptance Tests**: User story validation
- **Performance Tests**: Non-functional requirement validation

## Quality Gates & Validation

### Architectural Compliance
1. **Dependency Direction**: Verify inward-pointing dependencies
2. **Layer Isolation**: Ensure no layer bypassing
3. **Interface Compliance**: Verify infrastructure implements abstractions
4. **Slice Cohesion**: Validate feature slice completeness

### Code Quality Metrics
- **Test Coverage**: Minimum 90% coverage per layer
- **Cyclomatic Complexity**: Maximum complexity thresholds
- **Dependencies**: No circular dependencies between modules
- **Documentation**: Public APIs must be documented

## Implementation Guidelines

### Getting Started
1. **Start with Core**: Define entities and services first
2. **Add Abstractions**: Define interfaces for external concerns  
3. **Build Application**: Implement workflows using core services
4. **Add Infrastructure**: Implement abstractions with real adapters
5. **Wire Together**: Configure dependency injection in binaries

### Evolution Principles
- **Core Stability**: Minimize changes to core domain
- **Application Flexibility**: Workflows can evolve with user needs
- **Infrastructure Adaptability**: Easy to swap implementations
- **Feature Addition**: New slices follow established patterns

---

**Remember**: This architecture serves the business domain first, with technical concerns adapting to support clear expression of business intent.