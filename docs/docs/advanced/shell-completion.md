---
sidebar_position: 9
title: ⏩ Shell Completion
---

# ⏩ Shell completion for vet

Command-line completion or Shell completion is a feature provided by shells like `bash` or `zsh` that lets you type commands in a fast and easy way. This functionality automatically fills in partially typed commands when the user press the `tab` key.

- To enable shell completion for `vet` for various shells follow the below steps

## 1. Identify your current environment shell

```bash
❯ echo $SHELL

/bin/zsh
```

## 2. Generate the completion command for your shell

```zsh
❯ vet completion zsh -h

Generate the autocompletion script for the zsh shell.

If shell completion is not already enabled in your environment you will need
to enable it.  You can execute the following once:

	echo "autoload -U compinit; compinit" >> ~/.zshrc

To load completions in your current shell session:

	source <(vet completion zsh); compdef _vet vet

To load completions for every new session, execute once:

#### Linux:

	vet completion zsh > "${fpath[1]}/_vet"

#### macOS:

	vet completion zsh > $(brew --prefix)/share/zsh/site-functions/_vet

You will need to start a new shell for this setup to take effect.
```



## 3. Run the commands to setup completion

```zsh
echo "autoload -U compinit; compinit" >> ~/.zshrc
source <(vet completion zsh); compdef _vet vet
vet completion zsh > $(brew --prefix)/share/zsh/site-functions/_vet
```

## 4. Open new shell and you can see the completion activated

```zsh
❯ vet [tab]
```

![vet autocomplete](/img/vet/vet-autocomplete.png)
