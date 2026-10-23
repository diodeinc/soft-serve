package backend

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	gitm "github.com/aymanbagabas/git-module"
	"github.com/charmbracelet/soft-serve/pkg/db"
	"github.com/charmbracelet/soft-serve/pkg/proto"
	"github.com/matryer/is"
)

// TestCreateRepositoryAnonymousOwner verifies that a repository created with
// a nil user (an anon-access/allow-keyless override) is owned by the
// lowest-ID admin rather than failing the NOT NULL repos.user_id constraint.
func TestCreateRepositoryAnonymousOwner(t *testing.T) {
	is := is.New(t)
	be, _ := newTestBackend(t)
	ctx := context.Background()

	admin, err := be.User(ctx, "admin")
	is.NoErr(err)

	repo, err := be.CreateRepository(ctx, "anon-repo", nil, proto.RepositoryOptions{})
	is.NoErr(err)
	is.Equal(repo.UserID(), admin.ID())
}

// TestDefaultAdminUserIDNoAdmin verifies that defaultAdminUserID surfaces an
// error rather than silently returning a zero user ID (which would violate
// the NOT NULL repos.user_id constraint) when the database has no admin.
func TestDefaultAdminUserIDNoAdmin(t *testing.T) {
	is := is.New(t)
	be, _ := newTestBackend(t)
	ctx := context.Background()

	err := be.db.TransactionContext(ctx, func(tx *db.Tx) error {
		if _, err := tx.ExecContext(ctx, "UPDATE users SET admin = false"); err != nil {
			return err
		}

		_, err := be.defaultAdminUserID(ctx, tx)
		return err
	})
	is.True(err != nil)
}

// TestValidateImportRemote verifies that import remotes pointing at private,
// internal, or non-network destinations are rejected, and that accepted
// remotes carry the git environment that keeps the validation honest.
func TestValidateImportRemote(t *testing.T) {
	tests := []struct {
		name    string
		remote  string
		wantErr bool
	}{
		{"public https", "https://1.1.1.1/x.git", false},
		{"public git", "git://1.1.1.1/x.git", false},
		{"ssh", "ssh://git@10.0.0.1/x.git", false},

		{"loopback", "http://127.0.0.1/x.git", true},
		{"localhost", "http://localhost:8080/x.git", true},
		{"private network", "http://10.0.0.1/x.git", true},
		{"cloud metadata", "http://169.254.169.254/latest/meta-data/", true},
		{"git scheme private", "git://10.0.0.1/x.git", true},
		{"octal loopback", "http://0177.0.0.1/x.git", true},
		{"local path", "/data/repos/secret.git", true},
		{"file scheme", "file:///etc/passwd", true},
		{"empty", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			env, err := validateImportRemote(tt.remote)

			if tt.wantErr {
				is.True(err != nil)
				is.True(errors.Is(err, proto.ErrInvalidRemote))
				return
			}

			is.NoErr(err)
			// Redirect following must be off, or a public remote can hand
			// off to an internal one after validation has passed.
			is.True(slices.Contains(env, "GIT_CONFIG_VALUE_0=false"))
			is.True(slices.Contains(env, "GIT_CONFIG_KEY_0=http.followRedirects"))
		})
	}
}

// TestImportRepositoryRaceKeepsOtherRepo verifies that an import racing with
// another repository created at the same name never removes that repository,
// whether the import's clone fails or its claim on the name fails.
func TestImportRepositoryRaceKeepsOtherRepo(t *testing.T) {
	for _, cloneErr := range []error{errors.New("clone failed"), nil} {
		t.Run(fmt.Sprint(cloneErr), func(t *testing.T) {
			is := is.New(t)
			be, cfg := newTestBackend(t)
			ctx := context.Background()

			var other proto.Repository
			orig := gitClone
			t.Cleanup(func() { gitClone = orig })
			gitClone = func(_, dst string, _ ...gitm.CloneOptions) error {
				if err := gitm.Init(dst, gitm.InitOptions{Bare: true}); err != nil {
					return err
				}
				// Another user creates the same name while the clone runs.
				var err error
				other, err = be.CreateRepository(ctx, "race", nil, proto.RepositoryOptions{})
				is.NoErr(err)
				return cloneErr
			}

			_, err := be.ImportRepository(ctx, "race", nil, "https://1.1.1.1/x.git", proto.RepositoryOptions{})
			is.True(err != nil)

			r, err := be.Repository(ctx, "race")
			is.NoErr(err)
			is.Equal(r.ID(), other.ID())
			_, err = r.Open()
			is.NoErr(err)

			// The import's staging clone is gone too.
			entries, err := os.ReadDir(filepath.Join(cfg.DataPath, "repos"))
			is.NoErr(err)
			is.Equal(len(entries), 1)
		})
	}
}
