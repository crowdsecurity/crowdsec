# JWT Middleware for Gin Framework

[![GitHub tag](https://img.shields.io/github/tag/appleboy/gin-jwt.svg)](https://github.com/appleboy/gin-jwt/releases)
[![GoDoc](https://godoc.org/github.com/appleboy/gin-jwt?status.svg)](https://godoc.org/github.com/appleboy/gin-jwt)
[![Build Status](https://cloud.drone.io/api/badges/appleboy/gin-jwt/status.svg)](https://cloud.drone.io/appleboy/gin-jwt)
[![Go Report Card](https://goreportcard.com/badge/github.com/appleboy/gin-jwt)](https://goreportcard.com/report/github.com/appleboy/gin-jwt)
[![codecov](https://codecov.io/gh/appleboy/gin-jwt/branch/master/graph/badge.svg)](https://codecov.io/gh/appleboy/gin-jwt)
[![codebeat badge](https://codebeat.co/badges/c4015f07-df23-4c7c-95ba-9193a12e14b1)](https://codebeat.co/projects/github-com-appleboy-gin-jwt)
[![Sourcegraph](https://sourcegraph.com/github.com/appleboy/gin-jwt/-/badge.svg)](https://sourcegraph.com/github.com/appleboy/gin-jwt?badge)

This is a middleware for [Gin](https://github.com/gin-gonic/gin) framework.

It uses [jwt-go](https://github.com/dgrijalva/jwt-go) to provide a jwt authentication middleware. It provides additional handler functions to provide the `login` api that will generate the token and an additional `refresh` handler that can be used to refresh tokens.

## Usage

Download and install using [go module](https://blog.golang.org/using-go-modules):

```sh
export GO111MODULE=on
go get github.com/appleboy/gin-jwt/v2
```

Import it in your code:

```go
import "github.com/appleboy/gin-jwt/v2"
```

Download and install without using [go module](https://blog.golang.org/using-go-modules):

```sh
go get github.com/appleboy/gin-jwt
```

Import it in your code:

```go
import "github.com/appleboy/gin-jwt"
```

## Example

Please see [the example file](_example/basic/server.go) and you can use `ExtractClaims` to fetch user data.

[embedmd]:# (_example/basic/server.go go)
```go
package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"
)

type login struct {
	Username string `form:"username" json:"username" binding:"required"`
	Password string `form:"password" json:"password" binding:"required"`
}

var identityKey = "id"

func helloHandler(c *gin.Context) {
	claims := jwt.ExtractClaims(c)
	user, _ := c.Get(identityKey)
	c.JSON(200, gin.H{
		"userID":   claims[identityKey],
		"userName": user.(*User).UserName,
		"text":     "Hello World.",
	})
}

// User demo
type User struct {
	UserName  string
	FirstName string
	LastName  string
}

func main() {
	port := os.Getenv("PORT")
	r := gin.New()
	r.Use(gin.Logger())
	r.Use(gin.Recovery())

	if port == "" {
		port = "8000"
	}

	// the jwt middleware
	authMiddleware, err := jwt.New(&jwt.GinJWTMiddleware{
		Realm:       "test zone",
		Key:         []byte("secret key"),
		Timeout:     time.Hour,
		MaxRefresh:  time.Hour,
		IdentityKey: identityKey,
		PayloadFunc: func(data interface{}) jwt.MapClaims {
			if v, ok := data.(*User); ok {
				return jwt.MapClaims{
					identityKey: v.UserName,
				}
			}
			return jwt.MapClaims{}
		},
		IdentityHandler: func(c *gin.Context) interface{} {
			claims := jwt.ExtractClaims(c)
			return &User{
				UserName: claims[identityKey].(string),
			}
		},
		Authenticator: func(c *gin.Context) (interface{}, error) {
			var loginVals login
			if err := c.ShouldBind(&loginVals); err != nil {
				return "", jwt.ErrMissingLoginValues
			}
			userID := loginVals.Username
			password := loginVals.Password

			if (userID == "admin" && password == "admin") || (userID == "test" && password == "test") {
				return &User{
					UserName:  userID,
					LastName:  "Bo-Yi",
					FirstName: "Wu",
				}, nil
			}

			return nil, jwt.ErrFailedAuthentication
		},
		Authorizator: func(data interface{}, c *gin.Context) bool {
			if v, ok := data.(*User); ok && v.UserName == "admin" {
				return true
			}

			return false
		},
		Unauthorized: func(c *gin.Context, code int, message string) {
			c.JSON(code, gin.H{
				"code":    code,
				"message": message,
			})
		},
		// TokenLookup is a string in the form of "<source>:<name>" that is used
		// to extract token from the request.
		// Optional. Default value "header:Authorization".
		// Possible values:
		// - "header:<name>"
		// - "query:<name>"
		// - "cookie:<name>"
		// - "param:<name>"
		TokenLookup: "header: Authorization, query: token, cookie: jwt",
		// TokenLookup: "query:token",
		// TokenLookup: "cookie:token",

		// TokenHeadName is a string in the header. Default value is "Bearer"
		TokenHeadName: "Bearer",

		// TimeFunc provides the current time. You can override it to use another time value. This is useful for testing or if your server uses a different time zone than your tokens.
		TimeFunc: time.Now,
	})

	if err != nil {
		log.Fatal("JWT Error:" + err.Error())
	}

	r.POST("/login", authMiddleware.LoginHandler)

	r.NoRoute(authMiddleware.MiddlewareFunc(), func(c *gin.Context) {
		claims := jwt.ExtractClaims(c)
		log.Printf("NoRoute claims: %#v\n", claims)
		c.JSON(404, gin.H{"code": "PAGE_NOT_FOUND", "message": "Page not found"})
	})

	auth := r.Group("/auth")
	// Refresh time can be longer than token timeout
	auth.GET("/refresh_token", authMiddleware.RefreshHandler)
	auth.Use(authMiddleware.MiddlewareFunc())
	{
		auth.GET("/hello", helloHandler)
	}

	if err := http.ListenAndServe(":"+port, r); err != nil {
		log.Fatal(err)
	}
}
```

## Demo

Please run _example/server.go file and listen `8000` port.

```sh
go run _example/server.go
```

Download and install [httpie](https://github.com/jkbrzt/httpie) CLI HTTP client.

### Login API

```sh
http -v --json POST localhost:8000/login username=admin password=admin
```

Output screenshot

![api screenshot](screenshot/login.png)

### Refresh token API

```bash
http -v -f GET localhost:8000/auth/refresh_token "Authorization:Bearer xxxxxxxxx"  "Content-Type: application/json"
```

Output screenshot

![api screenshot](screenshot/refresh_token.png)

### Hello world

Please login as `admin` and password as `admin`

```bash
http -f GET localhost:8000/auth/hello "Authorization:Bearer xxxxxxxxx"  "Content-Type: application/json"
```

Response message `200 OK`:

```sh
HTTP/1.1 200 OK
Content-Length: 24
Content-Type: application/json; charset=utf-8
Date: Sat, 19 Mar 2016 03:02:57 GMT

{
  "text": "Hello World.",
  "userID": "admin"
}
```

### Authorization

Please login as `test` and password as `test`

```bash
http -f GET localhost:8000/auth/hello "Authorization:Bearer xxxxxxxxx"  "Content-Type: application/json"
```

Response message `403 Forbidden`:

```sh
HTTP/1.1 403 Forbidden
Content-Length: 62
Content-Type: application/json; charset=utf-8
Date: Sat, 19 Mar 2016 03:05:40 GMT
Www-Authenticate: JWT realm=test zone

{
  "code": 403,
  "message": "You don't have permission to access."
}
```

### Cookie Token

Use these options for setting the JWT in a cookie. See the Mozilla [documentation](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#Secure_and_HttpOnly_cookies) for more information on these options.

```go
	SendCookie:       true,
	SecureCookie:     false, //non HTTPS dev environments
	CookieHTTPOnly:   true,  // JS can't modify
	CookieDomain:     "localhost:8080",
	CookieName:       "token", // default jwt
	TokenLookup:      "cookie:token",
```

### Login request flow (using the LoginHandler)

1. PROVIDED: `LoginHandler`

	This is a provided function to be called on any login endpoint, which will trigger the flow described below.

2. REQUIRED: `Authenticator`
	This function should verify the user credentials given the gin context (i.e. password matches hashed password for a given user email, and any other authentication logic). Then the authenticator should return a struct or map that contains the user data that will be embedded in the jwt token. This might be something like an account id, role, is_verified, etc. After having successfully authenticated, the data returned from the authenticator is passed in as a parameter into the `PayloadFunc`, which is used to embed the user identifiers mentioned above into the jwt token. If an error is returned, the `Unauthorized` function is used (explained below).

3. OPTIONAL: `PayloadFunc` 

	This function is called after having successfully authenticated (logged in). It should take whatever was returned from `Authenticator` and convert it into `MapClaims` (i.e. map[string]interface{}). A typical use case of this function is for when `Authenticator` returns a struct which holds the user identifiers, and that struct needs to be converted into a map. `MapClaims` should include one element that is [`IdentityKey` (default is "identity"): some_user_identity]. The elements of `MapClaims` returned in `PayloadFunc` will be embedded within the jwt token (as token claims). When users pass in their token on subsequent requests, you can get these claims back by using `ExtractClaims`.

4. OPTIONAL: `LoginResponse`

	After having successfully authenticated with `Authenticator`, created the jwt token using the identifiers from map returned from `PayloadFunc`, and set it as a cookie if `SendCookie` is enabled, this function is called. It is used to handle any post-login logic. This might look something like using the gin context to return a JSON of the token back to the user.

### Subsequent requests on endpoints requiring jwt token (using MiddlewareFunc).

1. PROVIDED: `MiddlewareFunc`

	This is gin middleware that should be used within any endpoints that require the jwt token to be present. This middleware will parse the request headers for the token if it exists, and check that the jwt token is valid (not expired, correct signature). Then it will call `IdentityHandler` followed by `Authorizator`. If `Authorizator` passes and all of the previous token validity checks passed, the middleware will continue the request. If any of these checks fail, the `Unauthorized` function is used (explained below).

2. OPTIONAL: `IdentityHandler`

	The default of this function is likely sufficient for your needs. The purpose of this function is to fetch the user identity from claims embedded within the jwt token, and pass this identity value to `Authorizator`. This function assummes [`IdentityKey`: some_user_identity] is one of the attributes embedded within the claims of the jwt token (determined by `PayloadFunc`).

3. OPTIONAL: `Authorizator`

	Given the user identity value (`data` parameter) and the gin context, this function should check if the user is authorized to be reaching this endpoint (on the endpoints where the `MiddlewareFunc` applies). This function should likely use `ExtractClaims` to check if the user has the sufficient permissions to reach this endpoint, as opposed to hitting the database on every request. This function should return true if the user is authorized to continue through with the request, or false if they are not authorized (where `Unauthorized` will be called).

### Logout Request flow (using LogoutHandler)

1. PROVIDED: `LogoutHandler`

	This is a provided function to be called on any logout endpoint, which will clear any cookies if `SendCookie` is set, and then call `LogoutResponse`.

2. OPTIONAL: `LogoutResposne`

	This should likely just return back to the user the http status code, if logout was successful or not.

### Refresh Request flow (using RefreshHandler)

1. PROVIDED: `RefreshHandler`:

	This is a provided function to be called on any refresh token endpoint. If the token passed in is was issued within the `MaxRefreshTime` time frame, then this handler will create/set a new token similar to the `LoginHandler`, and pass this token into `RefreshResponse`

2. OPTIONAL: `RefreshResposne`:

	This should likely return a JSON of the token back to the user, similar to `LoginResponse`


### Failures with logging in, bad tokens, or lacking privileges

1. OPTIONAL `Unauthorized`: 

	On any error logging in, authorizing the user, or when there was no token or a invalid token passed in with the request, the following will happen. The gin context will be aborted depending on `DisabledAbort`, then `HTTPStatusMessageFunc` is called which by default converts the error into a string. Finally the `Unauthorized` function will be called. This function should likely return a JSON containing the http error code and error message to the user.
