<div align="center">
    <h1>Health</h1>
</div>

<p align="center">
A simple and flexible health check library for Go.
</p>
<div align="center">

[![Build](https://github.com/alexliesenfeld/health/actions/workflows/build.yml/badge.svg)](https://github.com/alexliesenfeld/health/actions/workflows/build.yml)
[![codecov](https://codecov.io/gh/alexliesenfeld/health/branch/main/graph/badge.svg?token=V2mVh8RvYE)](https://codecov.io/gh/alexliesenfeld/health)
[![Go Report Card](https://goreportcard.com/badge/github.com/alexliesenfeld/health)](https://goreportcard.com/report/github.com/alexliesenfeld/health)
[![GolangCI](https://golangci.com/badges/github.com/alexliesenfeld/health.svg)](https://golangci.com/r/github.com/alexliesenfeld/health)
[![FOSSA Status](https://app.fossa.com/api/projects/custom%2B26405%2Fgithub.com%2Falexliesenfeld%2Fhealth.svg?type=shield)](https://app.fossa.com/projects/custom%2B26405%2Fgithub.com%2Falexliesenfeld%2Fhealth?ref=badge_shield)

</div>

<p align="center">
    <a href="https://pkg.go.dev/github.com/alexliesenfeld/health">Documentation</a>
    ·
    <a href="https://github.com/alexliesenfeld/health/issues">Report Bug</a>
    ·
    <a href="https://github.com/alexliesenfeld/health/issues">Request Feature</a>
</p>

## Table of Contents
1. [Getting started](#getting-started)
1. [Synchronous vs. Asynchronous Checks](#synchronous-vs-asynchronous-checks)
1. [Caching](#caching)
1. [Listening to Status Changes](#listening-to-status-changes)
1. [Middleware and Interceptors](#middleware-and-interceptors)
1. [Compatibility With Other Libraries](#compatibility-with-other-libraries)
1. [License](#license)

## Getting Started

This library provides a [http.Handler](https://pkg.go.dev/net/http#Handler) that acts as a health endpoint. It can be 
used by [cloud infrastructure](https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/) 
or other services to determine the availability of an application.

Rather than simply returning a response with HTTP status code 200, this library allows building health checks 
that test the availability of all required dependencies. The HTTP response contains the aggregated health result and 
details about the health status of each component.

### Example
```go
package main

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/alexliesenfeld/health"
	_ "github.com/mattn/go-sqlite3"
	"log"
	"net/http"
	"time"
)

// This is a very simple example that shows the basic features of this library.
func main() {
	db, _ := sql.Open("sqlite3", "simple.sqlite")
	defer db.Close()

	// Create a new Checker.
	checker := health.NewChecker(

		// Set the time-to-live for our cache to 1 second (default).
		health.WithCacheDuration(1*time.Second),

		// Configure a global timeout that will be applied to all checks.
		health.WithTimeout(10*time.Second),

		// A check configuration to see if our database connection is up.
		// The check function will be executed for each HTTP request.
		health.WithCheck(health.Check{
			Name:    "database",      // A unique check name.
			Timeout: 2 * time.Second, // A check specific timeout.
			Check:   db.PingContext,
		}),

		// The following check will be executed periodically every 15 seconds
		// started with an initial delay of 3 seconds. The check function will NOT
		// be executed for each HTTP request.
		health.WithPeriodicCheck(15*time.Second, 3*time.Second, health.Check{
			Name: "search",
			// The check function checks the health of a component. If an error is
			// returned, the component is considered unavailable (or "down").
			// The context contains a deadline according to the configured timeouts.
			Check: func(ctx context.Context) error {
				return fmt.Errorf("this makes the check fail")
			},
		}),

		// Set a status listener that will be invoked when the health status changes.
		// More powerful hooks are also available (see docs).
		health.WithStatusListener(func(ctx context.Context, state health.CheckerState) {
			log.Println(fmt.Sprintf("health status changed to %s", state.Status))
		}),
	)

	// Create a new health check http.Handler that returns the health status
	// serialized as a JSON string. You can pass pass further configuration
	// options to NewHandler to modify default configuration.
	http.Handle("/health", health.NewHandler(checker))
	log.Fatalln(http.ListenAndServe(":3000", nil))
}

```

Because our search component is down, the request `curl -u username:password http://localhost:3000/health`
would yield a response with HTTP status code `503 (Service Unavailable)`, and the following JSON response body:

```json
{
  "status": "down",
  "details": {
    "database": {
      "status": "up",
      "timestamp": "2021-07-01T08:05:14.603364Z"
    },
    "search": {
      "status": "down",
      "timestamp": "2021-07-01T08:05:08.522685Z",
      "error": "this makes the check fail"
    }
  }
}
```

[This example](https://github.com/alexliesenfeld/health/blob/main/examples/showcase/main.go)
shows **all features** of this library.

## Synchronous vs. Asynchronous Checks

With "synchronous" health checks we mean that every HTTP request initiates a health check and waits until all check
functions complete before returning an aggregated health result. You can configure synchronous checks
using the `WithCheck` configuration option (see [example above](#getting-started)).

Synchronous checks can be sufficient for smaller applications but might not scale well for more involved applications. 
Sometimes an application needs to read a large amount of data, can experience latency issues or make an expensive 
calculation to tell something about its health. With synchronous health checks the application will not be able 
to respond quickly to health check requests
(see [here](https://loft.sh/blog/kubernetes-readiness-probes-examples-common-pitfalls/) 
why this is necessary to avoid service disruptions in modern cloud infrastructure).

Rather than executing health check functions on every HTTP request, periodic (or "asynchronous")
health checks execute the check function on a fixed schedule. With this approach, the health status is always read from
a local cache that is regularly updated in the background. This allows responding to HTTP requests instantly without
waiting for check functions to complete.

Periodic checks can be configured using the `WithPeriodicCheck` configuration option
(see [example above](#getting-started)).

**This library allows you to mix synchronous and asynchronous check functions**, so you can start out simple and easily
transition into a more scalable and robust health check implementation later.

## Caching

Health check results are cached to avoid sending too many request to the services that your program checks and to
mitigate "denial of service" attacks. The [TTL](https://en.wikipedia.org/wiki/Time_to_live) is set to 1 second by
default. If you do not want to use caching altogether, you can disable it using the `health.WithDisabledCache()`
configuration option.

## Listening to Status Changes

It can be useful to react to health status changes. For example, you might want to log status changes or adjust some
metrics, so you can easier correlate logs during root cause analysis or perform actions to mitigate the impact 
of an unhealthy component.

This library allows you to configure listener functions that will be called when either the overall/aggregated health
status changes, or that of a specific component.

### Example

```go
health.WithPeriodicCheck(5*time.Second, 0, health.Check{
    Name:   "search",
    Check:  myCheckFunc,
    StatusListener: func (ctx context.Context, name string, state CheckState) ) {
	    log.Printf("status of component '%s' changed to %s", name, state.Status)
    },
}),

health.WithStatusListener(func (ctx context.Context, state CheckerState)) {
    log.Printf("overall system health status changed to %s", state.Status)
}),
```

## Middleware and Interceptors

It can be useful to hook into the checking lifecycle to do some processing before and after a health check. For example,
you might want to add some tracing information to the [Context](https://pkg.go.dev/context#Context) before the check
function executes, do some logging or modify the check result before sending the HTTP response
(e.g., removing details on failed authentication).

This library provides two mechanisms that allow you to hook into processing:

* [Middleware](https://pkg.go.dev/github.com/alexliesenfeld/health#MiddlewareFunc) gives you the possibility to
  intercept all calls of [Checker.Check](https://pkg.go.dev/github.com/alexliesenfeld/health#Checker), which corresponds
  to every incoming HTTP request. In contrary to the usually used
  [middleware pattern](https://drstearns.github.io/tutorials/gomiddleware/), this middleware allows you to access check
  related information and post-process a check result before sending it in an HTTP response.

  | Middleware              | Description                                                                                                 |
    | ----------------------- |:------------------------------------------------------------------------------------------------------------|
  | [BasicAuth](https://pkg.go.dev/github.com/alexliesenfeld/health/middleware#BasicAuth)               | Reduces exposed health details based on authentication success. Uses [basic auth](https://en.wikipedia.org/wiki/Basic_access_authentication) for authentication.         |
  | [CustomAuth](https://pkg.go.dev/github.com/alexliesenfeld/health/middleware#BasicAuth)              | Same as BasicAuth middleware, but allows using an arbitrary function for authentication.                    |
  | [FullDetailsOnQueryParam](https://pkg.go.dev/github.com/alexliesenfeld/health/middleware#FullDetailsOnQueryParam) | Disables health details unless the request contains a previously configured query parameter name.          |
  | [BasicLogger](https://pkg.go.dev/github.com/alexliesenfeld/health/middleware#BasicLogger)             | Basic request-oriented logging functionality.                                                               |

* [Interceptors](https://pkg.go.dev/github.com/alexliesenfeld/health#InterceptorFunc) make it possible to intercept all
  calls to a check function. This is useful if you have cross-functional code that needs to be reusable and should have
  access to check state information.

  | Interceptor   | Description                                            |
    | ------------- |:-------------------------------------------------------|
  | [BasicLogger](https://pkg.go.dev/github.com/alexliesenfeld/health/interceptors#BasicLogger)   | Basic component check function logging functionality   |

## Compatibility With Other Libraries

Most existing Go health check libraries come with their own implementations of tool specific check functions
(such as for Redis, memcached, Postgres, etc.). Rather than reinventing the wheel and come up with yet another library
specific implementation of check functions, the goal was to design this library in a way that makes it easy to reuse
existing solutions. The following (non-exhaustive) list of health check implementations should work with this library
without or minimal adjustments:

* [github.com/hellofresh/health-go](https://github.com/hellofresh/health-go/tree/master/checks)
  (
  see [full example here](https://github.com/alexliesenfeld/health/blob/main/examples/compatibiltiy/hellofresh/main.go))
  ```go
  import httpCheck "github.com/hellofresh/health-go/v4/checks/http"
  ...
  health.WithCheck(health.Check{
     Name:    "google",
     Check:   httpCheck.New(httpCheck.Config{
        URL: "https://www.google.com",
     }),
  }),
  ```
* [github.com/etherlabsio/healthcheck](https://github.com/etherlabsio/healthcheck/tree/master/checkers)
  (
  see [full example here](https://github.com/alexliesenfeld/health/blob/main/examples/compatibiltiy/etherlabsio/main.go))
    ```go
  import "github.com/etherlabsio/healthcheck/v2/checkers"
  ...
  health.WithCheck(health.Check{
      Name:    "database",
      Check:   checkers.DiskSpace("/var/log", 90).Check,
  })
  ```
* [github.com/heptiolabs/healthcheck](https://github.com/heptiolabs/healthcheck/blob/master/checks.go)
  (
  see [full example here](https://github.com/alexliesenfeld/health/blob/main/examples/compatibiltiy/heptiolabs/main.go))
  ```go
  import "github.com/heptiolabs/healthcheck"
  ...
  health.WithCheck(health.Check{
      Name: "google",
      Check: func(ctx context.Context) error {
         deadline, _ := ctx.Deadline()
         timeout := time.Now().Sub(deadline)
         return healthcheck.HTTPGetCheck("https://www.google.com", timeout)()
      },
  }),
  ```
* [github.com/InVisionApp/go-health](https://github.com/InVisionApp/go-health/tree/master/checkers)
  (
  see [full example here](https://github.com/alexliesenfeld/health/blob/main/examples/compatibiltiy/invisionapp/main.go))
  ```go
    import "github.com/InVisionApp/go-health/checkers"
    ...
    // Create check as usual (no error checking for brevity)
    googleURL, err := url.Parse("https://www.google.com")
    check, err := checkers.NewHTTP(&checkers.HTTPConfig{
        URL: googleURL,
    })
    ...
    // Add the check in the Checker configuration.
    health.WithCheck(health.Check{
        Name: "google",
        Check: func(_ context.Context) error {
            _, err := check.Status() 
            return err
        },
    })
  ```

## License

`health` is free software: you can redistribute it and/or modify it under the terms of the MIT Public License.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the MIT Public License for more details.

[![FOSSA Status](https://app.fossa.com/api/projects/custom%2B26405%2Fgithub.com%2Falexliesenfeld%2Fhealth.svg?type=large)](https://app.fossa.com/projects/custom%2B26405%2Fgithub.com%2Falexliesenfeld%2Fhealth?ref=badge_large)

