# Shell completion

Optional static completions cover command names, common option names, phases, formats, profiles, and
severity values. They never query RubyGems or execute gem code. Options are offered as a shared list;
check the selected command's `--help` for which ones it accepts. Explicit target arguments after `--`
are the target's own interface and are not described by these completion files.

From a source checkout, use the corresponding setup below. Installed gems also ship the files under
`contrib/`; `gem which bonebed` locates the installed library directory beside it.

For Bash, add the absolute checkout path to `~/.bashrc`:

```sh
source /path/to/bonebed/contrib/bonebed.bash
```

For Zsh, add the directory before calling `compinit` in `~/.zshrc`:

```sh
fpath=(/path/to/bonebed/contrib $fpath)
autoload -Uz compinit
compinit
```

For Fish, copy `contrib/bonebed.fish` to `~/.config/fish/completions/bonebed.fish`, creating that directory
if needed. Open a new shell after setup, then type `bonebed ` and press Tab.
