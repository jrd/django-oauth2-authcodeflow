<!-- omit in toc -->
# Contributing to Django OAuth2 AuthCodeFlow

First off, thanks for taking the time to contribute! ❤️

All types of contributions are encouraged and valued. See the [Table of Contents](#table-of-contents) for different ways to help and details about how this project handles them. Please make sure to read the relevant section before making your contribution. It will make it a lot easier for us maintainers and smooth out the experience for all involved. The community looks forward to your contributions. 🎉

The project is mainly developped on [Gitlab](https://gitlab.com/systra/qeto/lib/django-oauth2-authcodeflow) but a mirror also exists on [Github](https://github.com/jrd/django-oauth2-authcodeflow).

> And if you like the project, but just don't have time to contribute, that's fine. There are other easy ways to support the project and show your appreciation, which we would also be very happy about:
> - Star the project
> - Refer this project in your project's readme
> - Mention the project at local meetups and tell your friends/colleagues

<!-- omit in toc -->
## Table of Contents

- [I Have a Question](#i-have-a-question)
- [I Want To Contribute](#i-want-to-contribute)
- [Reporting Bugs](#reporting-bugs)
- [Suggesting Enhancements](#suggesting-enhancements)
- [Styleguides](#styleguides)
- [Commit Messages](#commit-messages)



## I Have a Question

> If you want to ask a question, we assume that you have read the available [Documentation](https://gitlab.com/systra/qeto/lib/django-oauth2-authcodeflow/-/blob/master/README.md).

Before you ask a question, it is best to search for existing [Issues on Gitlab](https://gitlab.com/systra/qeto/lib/django-oauth2-authcodeflow/issues) and [Github](https://github.com/jrd/django-oauth2-authcodeflow/issues) that might help you. In case you have found a suitable issue and still need clarification, you can write your question in this issue. It is also advisable to search the internet for answers first.

If you then still feel the need to ask a question and need clarification, we recommend the following:

- Open an [issue on Gitlab (prefered)](https://gitlab.com/systra/qeto/lib/django-oauth2-authcodeflow/issues/new) or on [Github](https://github.com/jrd/django-oauth2-authcodeflow/issues/new).
- Provide as much context as you can about what you're running into.
- Provide project and platform versions depending on what seems relevant.

We will then take care of the issue as soon as possible.

## I Want To Contribute

> ### Legal Notice <!-- omit in toc -->
> When contributing to this project, you must agree that you have authored 100% of the content, that you have the necessary rights to the content and that the content you contribute may be provided under the [project license](https://gitlab.com/systra/qeto/lib/django-oauth2-authcodeflow/-/blob/master/LICENSE).

### Reporting Bugs

<!-- omit in toc -->
#### Before Submitting a Bug Report

A good bug report shouldn't leave others needing to chase you up for more information. Therefore, we ask you to investigate carefully, collect information and describe the issue in detail in your report. Please complete the following steps in advance to help us fix any potential bug as fast as possible.

- Make sure that you are using the latest version.
- Determine if your bug is really a bug and not an error on your side e.g. using incompatible environment components/versions (Make sure that you have read the [documentation](https://gitlab.com/systra/qeto/lib/django-oauth2-authcodeflow/-/blob/master/README.md). If you are looking for support, you might want to check [this section](#i-have-a-question)).
- To see if other users have experienced (and potentially already solved) the same issue you are having, check if there is not already a bug report existing for your bug or error in the [issues on Gitlab (prefered)](https://gitlab.com/systra/qeto/lib/django-oauth2-authcodeflow/issues) or on [Github](https://github.com/jrd/django-oauth2-authcodeflow/issues).
- Also make sure to search the internet (including Stack Overflow) to see if users outside of the git community have discussed the issue.
- Collect information about the bug:
- Stack trace (Traceback)
- OS, Python version, Django version, Django apps
- Possibly your input and the output
- Can you reliably reproduce the issue? And can you also reproduce it with older versions?

<!-- omit in toc -->
#### How Do I Submit a Good Bug Report?

> You must never report security related issues, vulnerabilities or bugs including sensitive information to the issue tracker, or elsewhere in public. Instead sensitive bugs must be sent by email to <cyrille+djangooauth2-security@enialis.net>.

We use **Gitlab** issues to track bugs and errors. Github mirror can also be used. If you run into an issue with the project:

- Open an [Issue](https://gitlab.com/systra/qeto/lib/django-oauth2-authcodeflow/issues/new). (Since we can't be sure at this point whether it is a bug or not, we ask you not to talk about a bug yet and not to label the issue.)
- Explain the behavior you would expect and the actual behavior.
- Please provide as much context as possible and describe the *reproduction steps* that someone else can follow to recreate the issue on their own. This usually includes your code. For good bug reports you should isolate the problem and create a reduced test case.
- Provide the information you collected in the previous section.

Once it's filed:

- The project team will label the issue accordingly.
- A team member will try to reproduce the issue with your provided steps. If there are no reproduction steps or no obvious way to reproduce the issue, the team will ask you for those steps.
- If the team is able to reproduce the issue, then a fix or temporary bypass will be proposed. You can also propose a merge request.


### Suggesting Enhancements

This section guides you through submitting an enhancement suggestion for Django OAuth2 AuthCodeFlow, **including completely new features and minor improvements to existing functionality**. Following these guidelines will help maintainers and the community to understand your suggestion and find related suggestions.

<!-- omit in toc -->
#### Before Submitting an Enhancement

- Make sure that you are using the latest version.
- Read the [documentation](https://gitlab.com/systra/qeto/lib/django-oauth2-authcodeflow/-/blob/master/README.md) carefully and find out if the functionality is already covered, maybe by an individual configuration.
- Perform a [search](https://gitlab.com/systra/qeto/lib/django-oauth2-authcodeflow/issues) to see if the enhancement has already been suggested. If it has, add a comment to the existing issue instead of opening a new one.
- Find out whether your idea fits with the scope and aims of the project. It's up to you to make a strong case to convince the project's developers of the merits of this feature. Keep in mind that we want features that will be useful to the majority of our users and not just a small subset. If you're just targeting a minority of users, consider writing an add-on/plugin library.

<!-- omit in toc -->
#### How Do I Submit a Good Enhancement Suggestion?

Enhancement suggestions are tracked as [Gitlab issues](https://gitlab.com/systra/qeto/lib/django-oauth2-authcodeflow/issues).

- Use a **clear and descriptive title** for the issue to identify the suggestion.
- Provide a **step-by-step description of the suggested enhancement** in as many details as possible.
- **Describe the current behavior** and **explain which behavior you expected to see instead** and why. At this point you can also tell which alternatives do not work for you.
- **Explain why this enhancement would be useful** to most Django OAuth2 AuthCodeFlow users. You may also want to point out the other projects that solved it better and which could serve as inspiration.

## Styleguides
### Code style

Make sure to follow/mimic the existing code base style.

This project is configured to use `flake8`, `isort` and `mypy` for style. Do not apply `black` to this repository. Tools are configured in the `pyproject.toml` file.

A `Makefile` exists with the following targets to help you check your code:
- linter: run linter on source code
- type: run type checker on source code
- tests: run unit tests

### Commit

Commit should **only contains** the required modifications to reach the purpose (a fix, an enhancement). No other modifications should take place in a commit (adjustement of dot files, CI change, style change, …)

The commit message should start with summary in one line ending by a reference to the **gitlab issue** as `(#18)` for instance. If the issue is on **github**, specify it like `(github #18)`.
Example: `Allow to logout even when using the Django ModelBackend (github #25)`

Second commit message line should be empty. Next ones can describe the commit in more details.

Each commit should contain a markdown file in the `_CHANGELOGS` sub directory (`Added`, `Changed`, `Deprecated`, `Fixed`, `Removed` or `Security`). Use a meaningful name with no space with `.md` extension. Markdown content should be a list of what changed.

**DO NOT** modify the root `CHANGELOG.md` file directly.