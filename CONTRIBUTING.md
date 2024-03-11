# Contributing

> This guide is for internal Snyk contributors with write access to this repository. If you are an external contributor, before working on any contributions, please first [contact support](https://support.snyk.io) to discuss the issue or feature request with us.

## Prerequisites

You will need the following software installed:

- Git
- Go
    - Use whichever version is in [`go.mod`](./go.mod).

Open a terminal and make sure they are available.

```sh
git --version
go version
```

## Setting up

Clone this repository with git.

```sh
git clone git@github.com:snyk/code-client-go.git
cd code-client-go
```

You will now be on our `main` branch. You should never commit to this branch, but you should keep it up-to-date to ensure you have the latest changes.

```sh
git fetch
git pull --ff-only
```

## Running tests

To run the tests run:

```sh
make test
```

## Code ownership

For current ownership assignments, see: [CODEOWNERS](./.github/CODEOWNERS).

To avoid mixing ownership into a single file, move team-specific logic into separate files. To reduce blockers and save time, design with ownership in mind.

## Code formatting

To ensure your changes follow formatting guidelines, you can run the linter.

```
make lint
```

To fix various issues automatically you can run the following:

```
make format
```

You will need to fix any remaining issues manually.

## Creating a branch

Create a new branch before making any changes. Make sure to give it a descriptive name so that you can find it later.

```sh
git checkout -b type/topic
```

For example:

```sh
git checkout -b docs/contributing
```

## Creating commits

Each commit must provide some benefit on its own without breaking the release pipeline.

For larger changes, break down each step into multiple commits so that it's easy to review in pull requests and git history.

Commits must follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) structure:

```
type: summary of your changes

reasoning behind your changes
```

For example:

```
docs: update contributing guide

We often get questions on how to contribute to this repo. What versions to use, what the workflow is, and so on. This change updates our CONTRIBUTING guide to answer those types of questions.
```

### Commit types

The commit type is used to summarize intent and to automate various steps.

| Type       | Description                                     |
| ---------- | ----------------------------------------------- |
| `feat`     | A new user-facing feature.                      |
| `fix`      | A bug fix for an existing feature.              |
| `refactor` | Changes which do not affect existing features.  |
| `test`     | Changes to tests for existing features.         |
| `docs`     | Changes to documentation for existing features. |
| `chore`    | Build, workflow and pipeline changes.           |
| `revert`   | Reverting a previous commit.                    |

## Pushing changes

Once you have committed your changes, review them locally, then push them to GitHub.

```
git push
```

Do not hold onto your changes for too long. Commit and push frequently and create a pull request as soon as possible for backup and visibility.