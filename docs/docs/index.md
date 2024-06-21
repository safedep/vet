---
slug: /
sidebar_position: 1
title: 👋 Welcome
---

# 👋 Welcome to vet

![Vet](/img/vet/vet-banner.png)

## 👉 About vet

`vet` is a tool for identifying risks in open source software supply chain. It helps engineering and security teams to identify potential issues in their open source dependencies and evaluate them against organizational policies.

## 🤔 Why vet?

> It has been estimated that Free and Open Source Software (FOSS) constitutes 70-90% of any given piece of modern software solutions.
> [Source](https://www.linuxfoundation.org/blog/blog/a-summary-of-census-ii-open-source-software-application-libraries-the-world-depends-on)

Industry dependency on OSS will only increase. We need better tooling to help
engineering and security teams to safely consume OSS components.

### 👉 Problem space

Product security practices secure software developed and deployed internally. They do not cover software consumed from external sources in form of libraries from the Open Source ecosystem. The growing risk of vulnerable, unmaintained and malicious dependencies establishes the need for product security teams to vet 3rd party dependencies before consumption.

### 👉 Current state

Vetting open source packages is largely a manual and opinionated process involving engineering teams as the requester and security teams as the service provider. A typical OSS vetting process involves auditing dependencies to ensure security, popularity, license compliance, trusted publisher etc. The manual nature of this activity increases cycle time and slows down engineering  velocity, especially for evolving products.

### 🚀 What vet aims to solve

`vet` solves the problem of OSS dependency vetting by providing a policy driven automated analysis of libraries. It can be seamlessly integrated with any CI tool or used in developer / security engineer's local environment.

## 🤩 Vet in Action

![Vet Showcase](/img/vet/vet-demo.gif)
