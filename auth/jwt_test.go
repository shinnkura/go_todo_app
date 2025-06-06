package auth

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/shinnkura/go_todo_app/clock"
	"github.com/shinnkura/go_todo_app/entity"
	"github.com/shinnkura/go_todo_app/testutil/fixture"
)

func TestEmbed(t *testing.T) {
	want := []byte("-----BEGIN PUBLIC KEY-----")
	if !bytes.Equal(rawPubKey, want) {
		t.Errorf("want %s, but got %s", want, rawPubKey)
	}
	want = []byte("-----BEGIN PRIVATE KEY-----")
	if !bytes.Equal(rawPrivKey, want) {
		t.Errorf("want %s, but got %s", want, rawPrivKey)
	}
}

func TestJWTer_GenerateToken(t *testing.T) {
	ctx := context.Background()
	moq := &StoreMock{}
	wantID := entity.UserID(20)
	u := fixture.User(&entity.User{ID: wantID})
	moq.SaveFunc = func(ctx context.Context, key string, userID entity.UserID) error {
		if userID != wantID {
			t.Errorf("SaveFunc: want %d, but got %d", wantID, userID)
		}
		return nil
	}
	sut, err := NewJWTer(moq, clock.RealClocker{})
	if err != nil {
		t.Fatalf("NewJWTer: %v", err)
	}
	got, err := sut.GenerateToken(ctx, *u)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if len(got) == 0 {
		t.Errorf("token is empty")
	}
}

// func TestJWTer_GetToken(t *testing.T) {
// 	t.Parallel()

// 	c := clock.FixedClocker{}
// 	want, err := jwt.NewBuilder().
// 		JwtID(uuid.New().String()).
// 		Issuer(`github.com/shinnkura/go_todo_app`).
// 		Subject("access_token").
// 		IssuedAt(c.Now()).
// 		Expiration(c.Now().Add(30*time.Minute)).
// 		Claim(RoleKey, "test").
// 		Claim(UserNameKey, "test_user").
// 		Build()
// 	if err != nil {
// 		t.Fatalf("NewBuilder: %v", err)
// 	}
// 	pkey, err := jwk.ParseKey(rawPrivKey, jwk.WithPEM(true))
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	signed, err := jwt.Sign(want, jwt.WithKey(jwa.RS256, pkey))
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	userID := entity.UserID(20)

// 	ctx := context.Background()

// 	moq := &StoreMock{}
// 	moq.LoadFunc = func(ctx context.Context, key string) (entity.UserID, error) {
// 		return entity.UserID(10), nil
// 	}
// }
