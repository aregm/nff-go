# Contributing to NFF-GO

NFF-GO is an open source project licensed under the BSD-style license which can be found in the LICENSE file.

## Coding Style

NFF-GO follows the standard formatting recommendations and language idioms set out
in the [Effective Go](https://golang.org/doc/effective_go.html) guide. It's
definitely worth reading - but the relevant sections are
[formatting](https://golang.org/doc/effective_go.html#formatting)
and [names](https://golang.org/doc/effective_go.html#names).

## Certificate of Origin

In order to get a clear contribution chain of trust we use the [signed-off-by language](https://01.org/community/signed-process)
used by the Linux kernel project.

## Patch format

Beside the signed-off-by footer, we expect each patch to comply with the following format:

```
<component>: Change summary

More detailed explanation of your changes: Why and how.
Wrap it to 72 characters.
See [here](http://chris.beams.io/posts/git-commit/)
for some more good advices.

Signed-off-by: <contributor@foo.com>
```

## Pull requests

We accept github pull requests.

If you want to work on github.com/intel-go/nff-go and your fork on the same workstation you will need to use multiple GOPATHs.  Assuming this is the case

1. Open a terminal
2. mkdir -p ~/go-fork/src/github.com/intel-go (replacing go-fork with your preferred location)
3. export GOPATH=~/go-fork
4. cd $GOPATH/src/github.com/intel-go/nff-go
5. git clone https://github.com/GITHUB-USERNAME/nff-go.git (replace GITHUB-USERNAME with your username)
6. cd nff-go
7. go install ./...

Once you've finished making your changes push them to your fork and send the PR via the github UI.  If you don't need to maintain the github.com/intel-go/nff-go repo and your fork on the same workstation you can skip steps 2 and 3.

## Quality Controls

We request you give quality assurance some consideration by:
* Adding go unit tests for changes where it makes sense.

## Issue tracking

If you have a problem, please let us know. Write e-mail to [maintainers](mailto:areg.melik-adamyan@intel.com)

If a bug is not already documented, by all means please [open an
issue in github](https://github.com/intel-go/NFF-GO/issues/new) so we all get visibility
the problem and work toward resolution.

For feature requests we're also using github issues, with the label
"enhancement".

## Closing issues

You can either close issues manually by adding the fixing commit SHA1 to the issue
comments or by adding the `Fixes` keyword to your commit message:

```
flow: test: Add Stop checking tests

We check that we get the right response when stopping flow.

Fixes #121

Signed-off-by: Ilia Filippov <ilia.filippov@intel.com>
```

Github will then automatically close that issue when parsing the
[commit message](https://help.github.com/articles/closing-issues-via-commit-messages/).
