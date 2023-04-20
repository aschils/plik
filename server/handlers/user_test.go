package handlers

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"testing"

	"github.com/stretchr/testify/require"

	"github.com/root-gg/plik/server/common"
	"github.com/root-gg/plik/server/context"
	"github.com/root-gg/utils"
)

var userOK = &struct {
	ID       string `json:"id,omitempty"`
	Provider string `json:"provider"`
	Login    string `json:"login,omitempty"`
	Password string `json:"password"` // Needed here because
	Name     string `json:"name,omitempty"`
	Email    string `json:"email,omitempty"`
	IsAdmin  bool   `json:"admin"`

	MaxFileSize int64 `json:"maxFileSize"`
	MaxTTL      int   `json:"maxTTL"`
}{
	ID:          "nope",
	Provider:    "local",
	Login:       "user",
	Password:    "password",
	Email:       "user@root.gg",
	Name:        "user",
	MaxFileSize: 1234,
	MaxTTL:      1234,
	IsAdmin:     true,
}

func TestCreateUser(t *testing.T) {
	ctx := newTestingContext(common.NewConfiguration())
	ctx.SetUser(&common.User{IsAdmin: true})

	user := *userOK
	userJson, err := utils.ToJsonString(user)
	require.NoError(t, err)

	req, err := http.NewRequest("GET", "/me", bytes.NewBufferString(userJson))
	require.NoError(t, err, "unable to create new request")

	rr := ctx.NewRecorder(req)
	CreateUser(ctx, rr, req)

	// Check the status code is what we expect.
	context.TestOK(t, rr)

	respBody, err := ioutil.ReadAll(rr.Body)
	require.NoError(t, err, "unable to read response body")

	var userResult *common.User
	err = json.Unmarshal(respBody, &userResult)
	require.NoError(t, err, "unable to unmarshal response body")
	require.NotNil(t, userResult)
	require.Equal(t, "local:user", userResult.ID, "invalid user id")
	require.Equal(t, user.Provider, userResult.Provider, "invalid user provider")
	require.Equal(t, user.Name, userResult.Name, "invalid user name")
	require.Equal(t, user.Email, userResult.Email, "invalid user email")
	require.Equal(t, user.Login, userResult.Login, "invalid user login")
	require.Empty(t, userResult.Password, "user password returned")
	require.Equal(t, user.MaxTTL, userResult.MaxTTL, "invalid user login")
	require.Equal(t, user.MaxFileSize, userResult.MaxFileSize, "invalid user login")

	userResult, err = ctx.GetMetadataBackend().GetUser("local:user")
	require.NoError(t, err)
	require.NotNil(t, userResult)
	require.Equal(t, "local:user", userResult.ID, "invalid user id")
	require.Equal(t, user.Provider, userResult.Provider, "invalid user provider")
	require.Equal(t, user.Name, userResult.Name, "invalid user name")
	require.Equal(t, user.Email, userResult.Email, "invalid user email")
	require.Equal(t, user.Login, userResult.Login, "invalid user login")
	require.NotEmpty(t, userResult.Password, "invalid user password")
	require.NotEqual(t, user.Password, userResult.Password, "invalid user password")
	require.Equal(t, user.MaxTTL, userResult.MaxTTL, "invalid user login")
	require.Equal(t, user.MaxFileSize, userResult.MaxFileSize, "invalid user login")
}

func TestCreateUser_Unauthorized(t *testing.T) {
	ctx := newTestingContext(common.NewConfiguration())

	req, err := http.NewRequest("GET", "/me", bytes.NewBuffer([]byte{}))
	require.NoError(t, err, "unable to create new request")

	rr := ctx.NewRecorder(req)
	CreateUser(ctx, rr, req)

	context.TestUnauthorized(t, rr, "missing user, please login first")
}

func TestCreateUser_InvalidUserJson(t *testing.T) {
	ctx := newTestingContext(common.NewConfiguration())
	ctx.SetUser(&common.User{IsAdmin: true})

	req, err := http.NewRequest("GET", "/me", bytes.NewBufferString(""))
	require.NoError(t, err, "unable to create new request")

	rr := ctx.NewRecorder(req)
	CreateUser(ctx, rr, req)
	context.TestBadRequest(t, rr, "unable to deserialize user : missing")

	req, err = http.NewRequest("GET", "/me", bytes.NewBufferString("invalid"))
	require.NoError(t, err, "unable to create new request")

	rr = ctx.NewRecorder(req)
	CreateUser(ctx, rr, req)
	context.TestBadRequest(t, rr, "unable to deserialize user")

	req, err = http.NewRequest("GET", "/me", bytes.NewBufferString("{\"password\": 1}"))
	require.NoError(t, err, "unable to create new request")

	rr = ctx.NewRecorder(req)
	CreateUser(ctx, rr, req)
	context.TestBadRequest(t, rr, "unable to deserialize password")
}

func TestCreateUser_InvalidUserParams(t *testing.T) {
	ctx := newTestingContext(common.NewConfiguration())
	ctx.SetUser(&common.User{IsAdmin: true})

	req, err := http.NewRequest("GET", "/me", bytes.NewBufferString("{}"))
	require.NoError(t, err, "unable to create new request")

	rr := ctx.NewRecorder(req)
	CreateUser(ctx, rr, req)
	context.TestBadRequest(t, rr, "unable to create user")
}

func TestCreateUser_DuplicateUser(t *testing.T) {
	ctx := newTestingContext(common.NewConfiguration())
	ctx.SetUser(&common.User{IsAdmin: true})

	err := ctx.GetMetadataBackend().CreateUser(&common.User{ID: "local:user"})
	require.NoError(t, err)

	userJson, err := utils.ToJsonString(userOK)
	require.NoError(t, err)

	req, err := http.NewRequest("GET", "/me", bytes.NewBufferString(userJson))
	require.NoError(t, err, "unable to create new request")

	rr := ctx.NewRecorder(req)
	CreateUser(ctx, rr, req)
	context.TestInternalServerError(t, rr, "unable to save user")
}

func TestUpdateUser(t *testing.T) {
	ctx := newTestingContext(common.NewConfiguration())
	ctx.SetUser(&common.User{IsAdmin: true})

	user := *userOK
	userJson, err := utils.ToJsonString(user)
	require.NoError(t, err)

	req, err := http.NewRequest("GET", "/me", bytes.NewBufferString(userJson))
	require.NoError(t, err, "unable to update new request")

	rr := ctx.NewRecorder(req)
	UpdateUser(ctx, rr, req)

	// Check the status code is what we expect.
	context.TestOK(t, rr)

	respBody, err := ioutil.ReadAll(rr.Body)
	require.NoError(t, err, "unable to read response body")

	var userResult *common.User
	err = json.Unmarshal(respBody, &userResult)
	require.NoError(t, err, "unable to unmarshal response body")
	require.NotNil(t, userResult)
	require.Equal(t, "local:user", userResult.ID, "invalid user id")
	require.Equal(t, user.Provider, userResult.Provider, "invalid user provider")
	require.Equal(t, user.Name, userResult.Name, "invalid user name")
	require.Equal(t, user.Email, userResult.Email, "invalid user email")
	require.Equal(t, user.Login, userResult.Login, "invalid user login")
	require.Empty(t, userResult.Password, "user password returned")
	require.Equal(t, user.MaxTTL, userResult.MaxTTL, "invalid user login")
	require.Equal(t, user.MaxFileSize, userResult.MaxFileSize, "invalid user login")

	userResult, err = ctx.GetMetadataBackend().GetUser("local:user")
	require.NoError(t, err)
	require.NotNil(t, userResult)
	require.Equal(t, "local:user", userResult.ID, "invalid user id")
	require.Equal(t, user.Provider, userResult.Provider, "invalid user provider")
	require.Equal(t, user.Name, userResult.Name, "invalid user name")
	require.Equal(t, user.Email, userResult.Email, "invalid user email")
	require.Equal(t, user.Login, userResult.Login, "invalid user login")
	require.NotEmpty(t, userResult.Password, "invalid user password")
	require.NotEqual(t, user.Password, userResult.Password, "invalid user password")
	require.Equal(t, user.MaxTTL, userResult.MaxTTL, "invalid user login")
	require.Equal(t, user.MaxFileSize, userResult.MaxFileSize, "invalid user login")
}

func TestUpdateUser_Unauthorized(t *testing.T) {
	ctx := newTestingContext(common.NewConfiguration())

	req, err := http.NewRequest("GET", "/me", bytes.NewBuffer([]byte{}))
	require.NoError(t, err, "unable to update new request")

	rr := ctx.NewRecorder(req)
	UpdateUser(ctx, rr, req)

	context.TestUnauthorized(t, rr, "missing user, please login first")
}

func TestUpdateUser_InvalidUserJson(t *testing.T) {
	ctx := newTestingContext(common.NewConfiguration())
	ctx.SetUser(&common.User{IsAdmin: true})

	req, err := http.NewRequest("GET", "/me", bytes.NewBufferString(""))
	require.NoError(t, err, "unable to update new request")

	rr := ctx.NewRecorder(req)
	UpdateUser(ctx, rr, req)
	context.TestBadRequest(t, rr, "unable to deserialize user : missing")

	req, err = http.NewRequest("GET", "/me", bytes.NewBufferString("invalid"))
	require.NoError(t, err, "unable to update new request")

	rr = ctx.NewRecorder(req)
	UpdateUser(ctx, rr, req)
	context.TestBadRequest(t, rr, "unable to deserialize user")

	req, err = http.NewRequest("GET", "/me", bytes.NewBufferString("{\"password\": 1}"))
	require.NoError(t, err, "unable to update new request")

	rr = ctx.NewRecorder(req)
	UpdateUser(ctx, rr, req)
	context.TestBadRequest(t, rr, "unable to deserialize password")
}

func TestUpdateUser_InvalidUserParams(t *testing.T) {
	ctx := newTestingContext(common.NewConfiguration())
	ctx.SetUser(&common.User{IsAdmin: true})

	req, err := http.NewRequest("GET", "/me", bytes.NewBufferString("{}"))
	require.NoError(t, err, "unable to update new request")

	rr := ctx.NewRecorder(req)
	UpdateUser(ctx, rr, req)
	context.TestBadRequest(t, rr, "unable to update user")
}

func TestUpdateUser_DuplicateUser(t *testing.T) {
	ctx := newTestingContext(common.NewConfiguration())
	ctx.SetUser(&common.User{IsAdmin: true})

	err := ctx.GetMetadataBackend().UpdateUser(&common.User{ID: "local:user"})
	require.NoError(t, err)

	userJson, err := utils.ToJsonString(userOK)
	require.NoError(t, err)

	req, err := http.NewRequest("GET", "/me", bytes.NewBufferString(userJson))
	require.NoError(t, err, "unable to update new request")

	rr := ctx.NewRecorder(req)
	UpdateUser(ctx, rr, req)
	context.TestInternalServerError(t, rr, "unable to save user")
}
