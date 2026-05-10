# Lingma2API Project Auth Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 将 `lingma2api` 改造成“运行态仅使用项目内认证文件”的 OpenAI 兼容代理，并新增一次性本地回调授权 bootstrap。

**Architecture:** 认证链拆成两段：`cmd/lingma-auth-bootstrap` 负责用户交互、回调接收、交换与项目文件落盘；主服务只读取 `auth/credentials.json` 并继续复用现有签名、模型、SSE、HTTP handler 能力。所有 `.lingma` 读取从运行态主路径移除，只保留到独立测试或迁移工具边界。

**Tech Stack:** Go 标准库、`curl` 子进程、`httptest`、本地临时 HTTP 回调监听、项目内 JSON 认证文件。

---

### Task 1: 重写认证配置边界

**Files:**
- Modify: `lingma2api/internal/config/config.go`
- Modify: `lingma2api/config.yaml`
- Modify: `lingma2api/README.md`
- Create: `lingma2api/auth/credentials.example.json`
- Test: `lingma2api/internal/config/config_test.go`

**Step 1: Write the failing test**

```go
func TestLoadConfigUsesProjectAuthFile(t *testing.T) {
	cfgPath := writeTempFile(t, `
credential:
  auth_file: "./auth/credentials.json"
`)

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Credential.AuthFile != "./auth/credentials.json" {
		t.Fatalf("expected auth file path, got %q", cfg.Credential.AuthFile)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `cd lingma2api && GOCACHE=/tmp/go-build GOMODCACHE=/tmp/go-mod-cache go test ./internal/config -run TestLoadConfigUsesProjectAuthFile -v`
Expected: FAIL because `AuthFile` does not exist yet.

**Step 3: Write minimal implementation**

```go
type CredentialConfig struct {
	AuthFile string
}
```

同时：

1. 从配置结构删除 `lingma_dir`
2. 从配置结构删除 `portable_config`
3. 在 `config.yaml` 中新增 `credential.auth_file`
4. 在 `README.md` 中把运行态认证来源改成项目内文件

**Step 4: Run test to verify it passes**

Run: `cd lingma2api && GOCACHE=/tmp/go-build GOMODCACHE=/tmp/go-mod-cache go test ./internal/config -run TestLoadConfigUsesProjectAuthFile -v`
Expected: PASS

### Task 2: 将运行态凭据层改成只读项目文件

**Files:**
- Modify: `lingma2api/internal/proxy/credentials.go`
- Modify: `lingma2api/internal/proxy/types.go`
- Modify: `lingma2api/internal/proxy/credentials_test.go`
- Delete or Move: `lingma2api/internal/proxy/local_credential_integration_test.go`

**Step 1: Write the failing tests**

```go
func TestCredentialManagerReadsProjectCredentialFile(t *testing.T) {
	path := writeCredentialFile(t, `{
	  "schema_version": 1,
	  "source": "project_bootstrap",
	  "auth": {
	    "cosy_key": "k",
	    "encrypt_user_info": "info",
	    "user_id": "u",
	    "machine_id": "m"
	  }
	}`)

	manager := NewCredentialManager(config.CredentialConfig{AuthFile: path}, fixedNow)
	snapshot, err := manager.Current(context.Background())
	if err != nil {
		t.Fatalf("Current() error = %v", err)
	}
	if snapshot.Source != "project_bootstrap" {
		t.Fatalf("expected source project_bootstrap, got %q", snapshot.Source)
	}
}

func TestCredentialManagerRejectsMissingProjectCredentialFields(t *testing.T) {
	path := writeCredentialFile(t, `{"schema_version":1,"auth":{"cosy_key":"k"}}`)
	manager := NewCredentialManager(config.CredentialConfig{AuthFile: path}, fixedNow)

	_, err := manager.Current(context.Background())
	if err == nil {
		t.Fatal("expected validation error")
	}
}
```

**Step 2: Run tests to verify they fail**

Run: `cd lingma2api && GOCACHE=/tmp/go-build GOMODCACHE=/tmp/go-mod-cache go test ./internal/proxy -run 'TestCredentialManagerReadsProjectCredentialFile|TestCredentialManagerRejectsMissingProjectCredentialFields' -v`
Expected: FAIL because the manager still reads `.lingma`-style sources.

**Step 3: Write minimal implementation**

```go
type StoredCredentialFile struct {
	SchemaVersion   int
	Source          string
	ObtainedAt      string
	UpdatedAt       string
	TokenExpireTime string
	Auth            StoredAuthFields
	OAuth           StoredOAuthFields
}
```

实现：

1. `CredentialManager` 只从 `cfg.AuthFile` 读取 JSON
2. 删除 `.lingma`、日志回退、`portable_config` 运行态路径
3. `validateSnapshot` 基于项目文件字段校验
4. 保留 `CredentialSnapshot` 供签名层复用

**Step 4: Run tests to verify they pass**

Run: `cd lingma2api && GOCACHE=/tmp/go-build GOMODCACHE=/tmp/go-mod-cache go test ./internal/proxy -run 'TestCredentialManagerReadsProjectCredentialFile|TestCredentialManagerRejectsMissingProjectCredentialFields' -v`
Expected: PASS

### Task 3: 新增一次性授权 bootstrap 命令

**Files:**
- Create: `lingma2api/cmd/lingma-auth-bootstrap/main.go`
- Create: `lingma2api/internal/auth/bootstrap.go`
- Create: `lingma2api/internal/auth/pkce.go`
- Create: `lingma2api/internal/auth/store.go`
- Create: `lingma2api/internal/auth/types.go`
- Test: `lingma2api/internal/auth/bootstrap_test.go`
- Test: `lingma2api/internal/auth/store_test.go`

**Step 1: Write the failing tests**

```go
func TestBuildAuthorizeURLIncludesStateAndChallenge(t *testing.T) {
	url, state, verifier, err := BuildAuthorizeURL(Config{
		ClientID: "client",
		RedirectURL: "http://127.0.0.1:38080/callback",
	})
	if err != nil {
		t.Fatalf("BuildAuthorizeURL() error = %v", err)
	}
	if state == "" || verifier == "" || !strings.Contains(url, "code_challenge=") {
		t.Fatalf("unexpected authorize result: %s", url)
	}
}

func TestStoreWritesProjectCredentialFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	err := SaveCredentialFile(path, StoredCredentialFile{
		SchemaVersion: 1,
		Source: "project_bootstrap",
		Auth: StoredAuthFields{CosyKey: "k", EncryptUserInfo: "i", UserID: "u", MachineID: "m"},
	})
	if err != nil {
		t.Fatalf("SaveCredentialFile() error = %v", err)
	}
}
```

**Step 2: Run tests to verify they fail**

Run: `cd lingma2api && GOCACHE=/tmp/go-build GOMODCACHE=/tmp/go-mod-cache go test ./internal/auth -run 'TestBuildAuthorizeURLIncludesStateAndChallenge|TestStoreWritesProjectCredentialFile' -v`
Expected: FAIL because the auth package does not exist yet.

**Step 3: Write minimal implementation**

```go
type BootstrapConfig struct {
	ListenAddr string
	OutputPath string
}
```

实现：

1. 生成 `state`、PKCE verifier/challenge
2. 生成浏览器链接
3. 启动一次性本地回调监听
4. 解析回调参数
5. 将结果写成项目认证文件

注意：

1. 首期允许把“后续交换”留成明确 TODO 或独立方法，只要边界清晰
2. 不得在 bootstrap 内偷偷读取 `~/.lingma/*`

**Step 4: Run tests to verify they pass**

Run: `cd lingma2api && GOCACHE=/tmp/go-build GOMODCACHE=/tmp/go-mod-cache go test ./internal/auth -run 'TestBuildAuthorizeURLIncludesStateAndChallenge|TestStoreWritesProjectCredentialFile' -v`
Expected: PASS

### Task 4: 让主服务与管理接口切到项目文件认证

**Files:**
- Modify: `lingma2api/main.go`
- Modify: `lingma2api/internal/api/server.go`
- Modify: `lingma2api/internal/api/server_test.go`
- Modify: `lingma2api/internal/proxy/signature.go`

**Step 1: Write the failing tests**

```go
func TestAdminRefreshReturnsClearErrorWhenNoRefreshFlowImplemented(t *testing.T) {
	server := newServerWithProjectCredentials(t)
	req := httptest.NewRequest(http.MethodPost, "/admin/refresh", nil)
	rec := httptest.NewRecorder()

	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501, got %d", rec.Code)
	}
}
```

**Step 2: Run tests to verify they fail**

Run: `cd lingma2api && GOCACHE=/tmp/go-build GOMODCACHE=/tmp/go-mod-cache go test ./internal/api -run TestAdminRefreshReturnsClearErrorWhenNoRefreshFlowImplemented -v`
Expected: FAIL because refresh still assumes generic credential reload.

**Step 3: Write minimal implementation**

```go
func (server *Server) handleAdminRefresh(...) {
	writeOpenAIError(writer, http.StatusNotImplemented, "project credential refresh is not implemented; rerun lingma-auth-bootstrap")
}
```

同时：

1. `main.go` 改为传入项目认证文件路径
2. 所有 handler 继续复用 `CredentialSnapshot`
3. 如果后续确认 refresh 契约，再替换为真实刷新实现

**Step 4: Run tests to verify they pass**

Run: `cd lingma2api && GOCACHE=/tmp/go-build GOMODCACHE=/tmp/go-mod-cache go test ./internal/api -run TestAdminRefreshReturnsClearErrorWhenNoRefreshFlowImplemented -v`
Expected: PASS

### Task 5: 清理旧方案残留与回归

**Files:**
- Modify: `lingma2api/README.md`
- Modify: `docs/plans/2026-04-27-lingma2api.md`
- Modify: `docs/superpowers/specs/2026-04-26-lingma2api-design.md`

**Step 1: Remove obsolete runtime claims**

从文档中移除或标记失效：

1. `portable_config.json` 作为运行态来源
2. `cache/user + cache/id` 作为运行态来源
3. 任何“主服务会读取 ~/.lingma”表述

**Step 2: Run focused tests**

Run: `cd lingma2api && GOCACHE=/tmp/go-build GOMODCACHE=/tmp/go-mod-cache go test ./internal/config ./internal/proxy ./internal/auth ./internal/api -v`
Expected: PASS

**Step 3: Run module-wide tests**

Run: `cd lingma2api && GOCACHE=/tmp/go-build GOMODCACHE=/tmp/go-mod-cache go test ./... -v`
Expected: PASS

**Step 4: Format sources**

Run: `cd lingma2api && gofmt -w .`
Expected: no output

**Step 5: Note current constraint**

在文档中明确：

1. 运行态只支持项目内认证文件
2. 若 bootstrap 尚未实现完整刷新，则需要人工重新执行
3. `.lingma` 只允许出现在测试/研究工具中
