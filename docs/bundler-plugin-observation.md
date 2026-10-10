# Observe Bundler plugin registration

`bonebed dig GEM --phase bundler_plugin` observes a gem's root `plugins.rb` through the public
`bundle plugin install` interface. This differs from `--phase plugin`, which observes RubyGems loading
`rubygems_plugin.rb`. It also differs from Bonebed's optional [approval plugin](bundler-plugin.md),
which checks previously saved results before an application install.

```sh
bonebed dig example-plugin --phase bundler_plugin --offline --quiet-target
bonebed dig example-plugin --phase all --offline --results results
```

The package must declare `plugins.rb` at its root. After the ordinary install phase, Bonebed creates
a local `file://` repository containing only the already prefetched archives. A fresh observed Ruby
process invokes Bundler's public plugin CLI with the exact package version and that source. Bundler
validates and executes the entrypoint, records its registrations, and creates its plugin index. The
observer does not substitute a direct `load` of the entrypoint or register plugins in the host account.

Bundler has a separate installation directory for plugins, so this phase can reinstall dependencies
and run extension builds. All that work, and dependency code required by the plugin, runs inside the
observed Session. Its capabilities belong to the aggregate phase; they are not exact per-dependency
attribution. The local source itself needs no registry access. Plugin code can still attempt network
access under the chosen observation mode; use `--offline`, `--sinkhole`, or enforcement as appropriate.

HOME and the working directory use the normal disposable honeypot environment unless explicitly
overridden. Bundler receives its own empty Gemfile, configuration/cache directories, and plugin index,
even when `--cwd` points to a real project. The project's Gemfile and inherited Bundler configuration
are not used by bootstrap. The active trusted Bundler runtime is selected and verified in the same
way as `bonebed bundle`. Both Bundler 2.4 on Ruby 3.2 and newer Bundler versions use the same local-source
bootstrap; no unsupported `--path` fallback is involved.

A matching baseline registers an empty plugin through the same public interface. Manifest metadata
distinguishes `gem.bundler_plugin` from `gem.rubygems_plugin`; the combined `capabilities.plugin` flag
is true for either. Plugin installation paths normalize to `$GEM_HOME`. The `all` sequence is install,
RubyGems plugin when declared, Bundler plugin when declared, then require. All phases share one run ID
and isolated environment. Resume, monitor checkpoints, comparisons, and approval locks require the
declared extra phase instead of accepting install/require alone. The phase records `environment.bundler`;
different Bundler versions have distinct result identities and are not interchangeable for resume.
A plugin exception is a target
failure; an observer/bootstrap infrastructure failure remains an observation failure.

This phase exercises registration-time behavior. Registered commands and lifecycle hooks that only
execute later are not automatically invoked. A successful registration does not establish that those
other execution paths are harmless. The existing filesystem and same-user process limitations in the
[threat model](threat-model.md) still apply.
