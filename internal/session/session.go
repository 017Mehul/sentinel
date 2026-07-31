package session

// RedisStore stores sessions in Redis.
type RedisStore struct{}

// PGStore stores sessions in Postgres.
type PGStore struct{}

// Service coordinates session lifecycle operations.
type Service struct{}

// Handler exposes session HTTP handlers.
type Handler struct{}

func NewRedisStore() *RedisStore { return &RedisStore{} }

func NewPGStore() *PGStore { return &PGStore{} }

func NewService() *Service { return &Service{} }

func NewHandler() *Handler { return &Handler{} }

