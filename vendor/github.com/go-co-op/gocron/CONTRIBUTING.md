# Contributing to gocron

Thank you for coming to contribute to gocron! We welcome new ideas, PRs and general feedback.

## Reporting Bugs

If you find a bug then please let the project know by opening an issue after doing the following:

- Do a quick search of the existing issues to make sure the bug isn't already reported
- Try and make a minimal list of steps that can reliably reproduce the bug you are experiencing
- Collect as much information as you can to help identify what the issue is (project version, configuration files, etc)

## Suggesting Enhancements

If you have a use case that you don't see a way to support yet, we would welcome the feedback in an issue. Before opening the issue, please consider:

- Is this a common use case?
- Is it simple to understand?

You can help us out by doing the following before raising a new issue:

- Check that the feature hasn't been requested already by searching existing issues
- Try and reduce your enhancement into a single, concise and deliverable request, rather than a general idea
- Explain your own use cases as the basis of the request

## Adding Features

Pull requests are always welcome. However, before going through the trouble of implementing a change it's worth creating a bug or feature request issue.
This allows us to discuss the changes and make sure they are a good fit for the project.

Please always make sure a pull request has been:

- Unit tested with `make test`
- Linted with `make lint`
- Vetted with `make vet`
- Formatted with `make fmt` or validated with `make check-fmt`

## Writing Tests

Tests should follow the [table driven test pattern](https://dave.cheney.net/2013/06/09/writing-table-driven-tests-in-go). See other tests in the code base for additional examples.
