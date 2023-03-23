# Why vet?

> It has been estimated that Free and Open Source Software (FOSS) constitutes 70-90% of any given piece of modern software solutions.

<!-- Problem Space -->
Product security practices target software developed and deployed internally.
They do not cover software consumed from external sources in form of libraries
from the Open Source ecosystem. The growing risk of vulnerable, unmaintained
and malicious dependencies establishes the need for product security teams to
vet 3rd party dependencies before consumption.

<!-- Current State -->
Vetting open source packages is largely a manual and opinionated process
involving engineering teams as the requester and security teams as the service
provider. A typical OSS vetting process involves auditing dependencies to
ensure security, popularity, license compliance, trusted publisher etc. The
manual nature of this activity increases cycle time and slows down engineering 
velocity, especially for evolving products.

<!-- What vet aims to solve -->
`vet` tool solves the problem of OSS dependency vetting by providing a policy
driven automated analysis of libraries. It can be seamlessly integrated with
any CI tool or used in developer / security engineer's local environment. 

<!-- Place this tag where you want the button to render. -->
<a class="github-button" href="https://github.com/safedep/vet/releases" data-color-scheme="no-preference: light; light: light; dark: dark;" data-icon="octicon-download" data-size="large" aria-label="Download safedep/vet on GitHub">Download a Release</a>

<!-- Place this tag where you want the button to render. -->
<a class="github-button" href="https://github.com/safedep/vet/packages" data-color-scheme="no-preference: light; light: light; dark: dark;" data-icon="octicon-package" data-size="large" aria-label="Install this package safedep/vet on GitHub">Run as Container</a>

## Reference

* https://slsa.dev/spec/v0.1/threats
* https://www.linuxfoundation.org/blog/blog/a-summary-of-census-ii-open-source-software-application-libraries-the-world-depends-on
