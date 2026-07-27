package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/charmbracelet/soft-serve/pkg/backend"
	"github.com/charmbracelet/soft-serve/pkg/config"
	"github.com/charmbracelet/soft-serve/pkg/db"
	"github.com/charmbracelet/soft-serve/pkg/db/migrate"
	"github.com/charmbracelet/soft-serve/pkg/proto"
	"github.com/charmbracelet/soft-serve/pkg/store"
	"github.com/charmbracelet/soft-serve/pkg/store/database"
	"github.com/golang-jwt/jwt/v5"
)

func TestJWTCommandAsUser(t *testing.T) {
	ctx, admin, user := jwtTestContext(t)
	var out bytes.Buffer
	cmd := JWTCommand()
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--as", user.Username(), "owner/repository"})

	if err := cmd.ExecuteContext(proto.WithUserContext(ctx, admin)); err != nil {
		t.Fatal(err)
	}

	claims := &jwt.RegisteredClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(
		strings.TrimSpace(out.String()),
		claims,
	); err != nil {
		t.Fatal(err)
	}
	if got, want := claims.Subject, "target#"+userID(user); got != want {
		t.Fatalf("subject = %q, want %q", got, want)
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != "owner/repository" {
		t.Fatalf("audience = %v, want [owner/repository]", claims.Audience)
	}
}

func TestJWTCommandAsUserRequiresAdmin(t *testing.T) {
	ctx, _, user := jwtTestContext(t)
	cmd := JWTCommand()
	cmd.SetArgs([]string{"--as", "target", "owner/repository"})

	err := cmd.ExecuteContext(proto.WithUserContext(ctx, user))
	if !errors.Is(err, proto.ErrUnauthorized) {
		t.Fatalf("error = %v, want %v", err, proto.ErrUnauthorized)
	}
}

func jwtTestContext(t *testing.T) (context.Context, proto.User, proto.User) {
	t.Helper()

	dataPath := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.DataPath = dataPath
	cfg.SSH.KeyPath = filepath.Join(dataPath, "ssh_host_ed25519")
	cfg.DB.Driver = "sqlite"
	cfg.DB.DataSource = filepath.Join(dataPath, "test.db")

	ctx := config.WithContext(context.Background(), cfg)
	dbx, err := db.Open(ctx, cfg.DB.Driver, cfg.DB.DataSource)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dbx.Close() })

	if err := migrate.Migrate(ctx, dbx); err != nil {
		t.Fatal(err)
	}
	dbstore := database.New(ctx, dbx)
	ctx = store.WithContext(ctx, dbstore)
	be := backend.New(ctx, cfg, dbx, dbstore)
	ctx = backend.WithContext(ctx, be)

	admin, err := be.CreateUser(ctx, "issuer", proto.UserOptions{Admin: true})
	if err != nil {
		t.Fatal(err)
	}
	user, err := be.CreateUser(ctx, "target", proto.UserOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return ctx, admin, user
}

func userID(user proto.User) string {
	return fmt.Sprintf("%d", user.ID())
}
