## 0.5.0

- BREAKING CHANGE: Changed function signature of middleware functions.
- Added a new check function interceptor and a [http.Handler](https://pkg.go.dev/net/http#Handler) 
  middleware with basic logging functionality.
- Added a new basic authentication middleware that reduces the exposed health information in case of 
  failed authentication.
- Added a new middleware FullDetailsOnQueryParam was added that hides details by default and only shows 
  them when a configured query parameter name was provided in the HTTP request.
- Added new Checker configuration option WithInterceptors, that will be applied to every check function.
