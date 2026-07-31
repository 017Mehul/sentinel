package rbac

// Repository stores role and permission persistence operations.
type Repository struct{}

// Service contains RBAC business logic.
type Service struct{}

// Handler exposes RBAC HTTP handlers.
type Handler struct{}

func NewRepository() *Repository { return &Repository{} }

func NewService() *Service { return &Service{} }

func NewHandler() *Handler { return &Handler{} }

