package cmd

import (
	"fmt"
	"time"

	"github.com/charmbracelet/soft-serve/pkg/backend"
	"github.com/charmbracelet/soft-serve/pkg/config"
	"github.com/charmbracelet/soft-serve/pkg/jwk"
	"github.com/charmbracelet/soft-serve/pkg/proto"
	"github.com/golang-jwt/jwt/v5"
	"github.com/spf13/cobra"
)

// JWTCommand returns a command that generates a JSON Web Token.
func JWTCommand() *cobra.Command {
	var asUsername string
	cmd := &cobra.Command{
		Use:   "jwt [repository1 repository2...]",
		Short: "Generate a JSON Web Token",
		Args:  cobra.MinimumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			cfg := config.FromContext(ctx)
			kp, err := jwk.NewPair(cfg)
			if err != nil {
				return err
			}

			user := proto.UserFromContext(ctx)
			if user == nil {
				return proto.ErrUserNotFound
			}
			if asUsername != "" {
				if !user.IsAdmin() {
					return proto.ErrUnauthorized
				}
				user, err = backend.FromContext(ctx).User(ctx, asUsername)
				if err != nil {
					return err
				}
			}

			now := time.Now()
			expiresAt := now.Add(time.Hour)
			claims := jwt.RegisteredClaims{
				Subject:   fmt.Sprintf("%s#%d", user.Username(), user.ID()),
				ExpiresAt: jwt.NewNumericDate(expiresAt), // expire in an hour
				NotBefore: jwt.NewNumericDate(now),
				IssuedAt:  jwt.NewNumericDate(now),
				Issuer:    cfg.HTTP.PublicURL,
				Audience:  args,
			}

			token := jwt.NewWithClaims(jwk.SigningMethod, claims)
			token.Header["kid"] = kp.JWK().KeyID
			j, err := token.SignedString(kp.PrivateKey())
			if err != nil {
				return err
			}

			cmd.Println(j)
			return nil
		},
	}
	cmd.Flags().StringVar(&asUsername, "as", "", "generate the token as another user (admin only)")

	return cmd
}
