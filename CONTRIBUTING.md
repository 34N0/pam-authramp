<!-- omit in toc -->
# Contributing to pam-authramp

First off, thanks for taking the time to contribute! ❤️

> If you like the project, but just don't have time to contribute, that's fine. There are other easy ways to support the project and show your appreciation, which we would also be very happy about:
> - Star the project
> - Tweet about it
> - Refer this project in your project's readmelibpam_authramp
> - Mention the project at local meetups and tell your friends/colleagues

<!-- omit in toc -->
## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [I Have a Question](#i-have-a-question)
- [I Want To Contribute](#i-want-to-contribute)
  - [Your First Code Contribution](#your-first-code-contribution)
  - [Pull Requests](#💫-pull-requests)


## Code of Conduct

This project and everyone participating in it is governed by the
[pam-authramp Code of Conduct](https://github.com/34N0/pam-authrampblob/master/CODE_OF_CONDUCT.md).
By participating, you are expected to uphold this code. Please report unacceptable behavior
to <34n0@immerda.ch>.


## I Have a Question

> If you want to ask a question, we assume that you have read the available [Documentation]().

Before you ask a question, it is best to search for existing [Issues](https://github.com/34N0/pam-authramp/issues) that might help you. In case you have found a suitable issue and still need clarification, you can write your question in this issue. It is also advisable to search the internet for answers first.

If you then still feel the need to ask a question and need clarification, we recommend the following:

- Open an [Issue](https://github.com/34N0/pam-authramp/issues/new).
- Provide as much context as you can about what you're running into.
- Provide project and platform versions (nodejs, npm, etc), depending on what seems relevant.

We will then take care of the issue as soon as possible.

## I Want To Contribute

> ### Legal Notice <!-- omit in toc -->
> When contributing to this project, you must agree that you have authored 100% of the content, that you have the necessary rights to the content and that the content you contribute may be provided under the project license.

### Your First Code Contribution
This module is developed and tested in a fedora 38 distrobox.
### prerequisites
The following packages need to be installed:
```console
sudo dnf install pam-devel clang-devel
```
### testing
#### Unit testings
All modules are unit tested. Run unit tests:
```console
cargo test -- --lib
```
#### Integration testing
Edit the values in the `.env` file to a user on your system. The test will build the library and use the systems pam service to test authentication. The test will run with evelated privileges. Run the integration tests:
```console
cargo xtask pam-test
```
### Linting
fix:
```console
cargo xtask fix
```
### Pull Requests

#### Before Submitting a Pull Request

A good pull request should be ready for review before it is even created. For all pull requests, ensure:

- Your changes are in a single commit
- You have no unnecessary changes, including and especially whitespace changes
- You're code is covered.
- For substantive changes, you include evidence of proper functionality in the pull request in addition to the build results.