# Expr 
[![test](https://github.com/antonmedv/expr/actions/workflows/test.yml/badge.svg)](https://github.com/antonmedv/expr/actions/workflows/test.yml) 
[![Go Report Card](https://goreportcard.com/badge/github.com/antonmedv/expr)](https://goreportcard.com/report/github.com/antonmedv/expr) 
[![GoDoc](https://godoc.org/github.com/antonmedv/expr?status.svg)](https://godoc.org/github.com/antonmedv/expr)

<img src="https://expr.medv.io/img/logo-small.png" width="150" alt="expr logo" align="right"/>

**Expr** package provides an engine that can compile and evaluate expressions. 
An expression is a one-liner that returns a value (mostly, but not limited to, booleans).
It is designed for simplicity, speed and safety.

The purpose of the package is to allow users to use expressions inside configuration for more complex logic. 
It is a perfect candidate for the foundation of a _business rule engine_. 
The idea is to let configure things in a dynamic way without recompile of a program:

```coffeescript
# Get the special price if
user.Group in ["good_customers", "collaborator"]

# Promote article to the homepage when
len(article.Comments) > 100 and article.Category not in ["misc"]

# Send an alert when
product.Stock < 15
```

## Features

* Seamless integration with Go (no need to redefine types)
* Static typing ([example](https://godoc.org/github.com/antonmedv/expr#example-Env)).
  ```go
  out, err := expr.Compile(`name + age`)
  // err: invalid operation + (mismatched types string and int)
  // | name + age
  // | .....^
  ```
* User-friendly error messages.
* Reasonable set of basic operators.
* Builtins `all`, `none`, `any`, `one`, `filter`, `map`.
  ```coffeescript
  all(Tweets, {.Size <= 280})
  ```
* Fast ([benchmarks](https://github.com/antonmedv/golang-expression-evaluation-comparison#readme)): uses bytecode virtual machine and optimizing compiler.

## Install

```
go get github.com/antonmedv/expr
```

## Documentation

* See [Getting Started](https://expr.medv.io/docs/Getting-Started) page for developer documentation.
* See [Language Definition](https://expr.medv.io/docs/Language-Definition) page to learn the syntax.

## Expr Code Editor

<a href="https://bit.ly/expr-code-editor">
  <img src="https://antonmedv.github.io/expr/ogimage.png" align="center" alt="Expr Code Editor" width="1200"/>
</a>

Also, I have an embeddable code editor written in JavaScript which allows editing expressions with syntax highlighting and autocomplete based on your types declaration.

[Learn more →](https://antonmedv.github.io/expr/)

## Examples

[Play Online](https://play.golang.org/p/z7T8ytJ1T1d)

```go
package main

import (
	"fmt"
	"github.com/antonmedv/expr"
)

func main() {
	env := map[string]interface{}{
		"greet":   "Hello, %v!",
		"names":   []string{"world", "you"},
		"sprintf": fmt.Sprintf,
	}

	code := `sprintf(greet, names[0])`

	program, err := expr.Compile(code, expr.Env(env))
	if err != nil {
		panic(err)
	}

	output, err := expr.Run(program, env)
	if err != nil {
		panic(err)
	}

	fmt.Println(output)
}
```

[Play Online](https://play.golang.org/p/4S4brsIvU4i)

```go
package main

import (
	"fmt"
	"github.com/antonmedv/expr"
)

type Tweet struct {
	Len int
}

type Env struct {
	Tweets []Tweet
}

func main() {
	code := `all(Tweets, {.Len <= 240})`

	program, err := expr.Compile(code, expr.Env(Env{}))
	if err != nil {
		panic(err)
	}

	env := Env{
		Tweets: []Tweet{{42}, {98}, {69}},
	}
	output, err := expr.Run(program, env)
	if err != nil {
		panic(err)
	}

	fmt.Println(output)
}
```

## Who uses Expr?

* [Aviasales](https://aviasales.ru) uses Expr as a business rule engine for our flight search engine.
* [Wish.com](https://www.wish.com) uses Expr for decision-making rule engine in the Wish Assistant.
* [Argo](https://argoproj.github.io) uses Expr in Argo Rollouts and Argo Workflows for Kubernetes.
* [Crowdsec](https://crowdsec.net) uses Expr in a security automation tool.
* [FACEIT](https://www.faceit.com) uses Expr to allow customization of its eSports matchmaking algorithm.
* [qiniu](https://www.qiniu.com) uses Expr in trade systems.
* [Junglee Games](https://www.jungleegames.com/) uses Expr for an in house marketing retention tool [Project Audience](https://www.linkedin.com/pulse/meet-project-audience-our-no-code-swiss-army-knife-product-bharti).
* [OpenTelemetry](https://opentelemetry.io) uses Expr in the OpenTelemetry Collector.
* [Philips Labs](https://github.com/philips-labs/tabia) uses Expr in Tabia, a tool for collecting insights on the characteristics of our code bases.
* [CoreDNS](https://coredns.io) uses Expr in CoreDNS, a DNS server.
* [Chaos Mesh](https://chaos-mesh.org) uses Expr in Chaos Mesh, a cloud-native Chaos Engineering platform.
* [Milvus](https://milvus.io) uses Expr in Milvus, an open-source vector database.
* [Visually.io](https://visually.io) uses Expr as a business rule engine for our personalization targeting algorithm.
* [Akvorado](https://github.com/akvorado/akvorado) uses Expr to classify exporters and interfaces in network flows.

[Add your company too](https://github.com/antonmedv/expr/edit/master/README.md)

## License

[MIT](https://github.com/antonmedv/expr/blob/master/LICENSE)
