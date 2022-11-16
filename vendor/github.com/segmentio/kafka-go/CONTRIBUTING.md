# Contributing to kafka-go

kafka-go is an open source project.  We welcome contributions to kafka-go of any kind including documentation,
organization, tutorials, bug reports, issues, feature requests, feature implementations, pull requests, etc.

## Table of Contents

* [Reporting Issues](#reporting-issues)
* [Submitting Patches](#submitting-patches)
  * [Code Contribution Guidelines](#code-contribution-guidelines)
  * [Git Commit Message Guidelines](#git-commit-message-guidelines)
  * [Fetching the Source From GitHub](#fetching-the-sources-from-github)
  * [Building kafka-go with Your Changes](#building-kakfa-go-with-your-changes)

## Reporting Issues

If you believe you have found a defect in kafka-go, use the GitHub issue tracker to report
the problem to the maintainers.  
When reporting the issue, please provide the version of kafka-go, what version(s) of Kafka 
are you testing against, and your operating system.

 - [kafka-go Issues segmentio/kafka-go](https://github.com/segmentio/kafka-go/issues)

## Submitting Patches

kafka-go project welcomes all contributors and contributions regardless of skill or experience levels.  If you are
interested in helping with the project, we will help you with your contribution.

### Code Contribution

To make contributions as seamless as possible, we ask the following:

* Go ahead and fork the project and make your changes.  We encourage pull requests to allow for review and discussion of code changes.
* When you’re ready to create a pull request, be sure to:
    * Have test cases for the new code. If you have questions about how to do this, please ask in your pull request.
    * Run `go fmt`.
    * Squash your commits into a single commit. `git rebase -i`. It’s okay to force update your pull request with `git push -f`.
    * Follow the **Git Commit Message Guidelines** below.

### Git Commit Message Guidelines

This [blog article](http://chris.beams.io/posts/git-commit/) is a good resource for learning how to write good commit messages,
the most important part being that each commit message should have a title/subject in imperative mood starting with a capital letter and no trailing period:
*"Return error on wrong use of the Reader"*, **NOT** *"returning some error."*

Also, if your commit references one or more GitHub issues, always end your commit message body with *See #1234* or *Fixes #1234*.
Replace *1234* with the GitHub issue ID. The last example will close the issue when the commit is merged into *master*.

Please use a short and descriptive branch name, e.g. NOT "patch-1". It's very common but creates a naming conflict each
time when a submission is pulled for a review.

An example:

```text
Add Code of Conduct and Code Contribution Guidelines

Add a full Code of Conduct and Code Contribution Guidelines document. 
Provide description on how best to retrieve code, fork, checkout, and commit changes.

Fixes #688
```

### Fetching the Sources From GitHub

We use Go Modules support built into Go 1.11 to build.  The easiest way is to clone kafka-go into a directory outside of
`GOPATH`, as in the following example:

```bash
mkdir $HOME/src
cd $HOME/src
git clone https://github.com/segmentio/kafka-go.git
cd kafka-go
go build ./...
```

To make changes to kafka-go's source:

1. Create a new branch for your changes (the branch name is arbitrary):

    ```bash
    git checkout -b branch1234
    ```

1. After making your changes, commit them to your new branch:

    ```bash
    git commit -a -v
    ```

1. Fork kafka-go in GitHub

1. Add your fork as a new remote (the remote name, "upstream" in this example, is arbitrary):

    ```bash
    git remote add upstream git@github.com:USERNAME/kafka-go.git
    ```

1. Push your branch (the remote name, "upstream" in this example, is arbitrary):

   ```bash
   git push upstream  
   ```

1. You are now ready to submit a PR based upon the new branch in your forked repository.

### Using the forked library

To replace the original version of kafka-go library with a forked version is accomplished this way.

1. Make sure your application already has a go.mod entry depending on kafka-go

    ```bash
    module github.com/myusername/myapp

    require (
        ...
        github.com/segmentio/kafka-go v1.2.3
        ...
    )
    ```

1. Add the following entry to the beginning of the modules file.

    ```bash
    module github.com/myusername/myapp

    replace github.com/segmentio/kafka-go v1.2.3 => ../local/directory

    require (
        ...
        github.com/segmentio/kafka-go v1.2.3
        ...
    )
    ```
1. Depending on if you are using `vendor`ing or not you might need to run the following command to pull in the new bits.

    ```bash
    > go mod vendor
    ```
