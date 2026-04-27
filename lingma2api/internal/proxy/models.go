package proxy

import (
	"context"
	"sort"
	"sync"
	"time"
)

type remoteModelFetcher interface {
	ListModels(context.Context, CredentialSnapshot) ([]RemoteModel, error)
}

type credentialReader interface {
	Current(context.Context) (CredentialSnapshot, error)
}

type ModelService struct {
	mu          sync.RWMutex
	transport   remoteModelFetcher
	credentials credentialReader
	aliases     map[string]string
	modelsByKey map[string]RemoteModel
	fetchedAt   time.Time
	lastError   string
	now         func() time.Time
}

func NewModelService(transport remoteModelFetcher, credentials credentialReader, aliases map[string]string, now func() time.Time) *ModelService {
	if now == nil {
		now = time.Now
	}
	if aliases == nil {
		aliases = DefaultAliases()
	}
	return &ModelService{
		transport:   transport,
		credentials: credentials,
		aliases:     aliases,
		modelsByKey: make(map[string]RemoteModel),
		now:         now,
	}
}

func (service *ModelService) ResolveChatModel(ctx context.Context, requested string) (string, error) {
	if requested == "" || requested == "auto" {
		return "", nil
	}
	if mapped, ok := service.aliases[requested]; ok {
		return mapped, nil
	}

	service.mu.RLock()
	_, cached := service.modelsByKey[requested]
	cachedCount := len(service.modelsByKey)
	service.mu.RUnlock()
	if cached {
		return requested, nil
	}

	if cachedCount == 0 {
		_ = service.Refresh(ctx)
	}

	service.mu.RLock()
	defer service.mu.RUnlock()
	if _, ok := service.modelsByKey[requested]; ok {
		return requested, nil
	}
	if len(service.modelsByKey) == 0 {
		return requested, nil
	}
	return "", ErrUnknownModel
}

func (service *ModelService) ListModels(ctx context.Context) ([]OpenAIModel, error) {
	service.mu.RLock()
	hasCache := len(service.modelsByKey) > 0
	service.mu.RUnlock()
	if !hasCache {
		if err := service.Refresh(ctx); err != nil {
			return nil, err
		}
	}

	service.mu.RLock()
	defer service.mu.RUnlock()
	return service.buildOpenAIModelsLocked(), nil
}

func (service *ModelService) Refresh(ctx context.Context) error {
	if service.transport == nil || service.credentials == nil {
		return nil
	}

	credential, err := service.credentials.Current(ctx)
	if err != nil {
		service.recordError(err.Error())
		return err
	}
	models, err := service.transport.ListModels(ctx, credential)
	if err != nil {
		service.recordError(err.Error())
		return err
	}

	service.mu.Lock()
	defer service.mu.Unlock()
	service.modelsByKey = make(map[string]RemoteModel, len(models))
	for _, model := range models {
		if model.Key == "" {
			continue
		}
		service.modelsByKey[model.Key] = model
	}
	service.fetchedAt = service.now()
	service.lastError = ""
	return nil
}

func (service *ModelService) Status() ModelStatus {
	service.mu.RLock()
	defer service.mu.RUnlock()

	return ModelStatus{
		FetchedAt: service.fetchedAt,
		Cached:    len(service.modelsByKey) > 0,
		Count:     len(service.modelsByKey),
		LastError: service.lastError,
	}
}

func (service *ModelService) recordError(message string) {
	service.mu.Lock()
	defer service.mu.Unlock()
	service.lastError = message
}

func (service *ModelService) buildOpenAIModelsLocked() []OpenAIModel {
	keys := make([]string, 0, len(service.modelsByKey))
	for key := range service.modelsByKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	models := make([]OpenAIModel, 0, len(keys)+len(service.aliases))
	for _, key := range keys {
		models = append(models, OpenAIModel{
			ID:      key,
			Object:  "model",
			OwnedBy: "lingma",
		})
	}

	aliasKeys := make([]string, 0, len(service.aliases))
	for alias := range service.aliases {
		aliasKeys = append(aliasKeys, alias)
	}
	sort.Strings(aliasKeys)
	for _, alias := range aliasKeys {
		models = append(models, OpenAIModel{
			ID:      alias,
			Object:  "model",
			OwnedBy: "lingma-alias",
		})
	}
	return models
}
