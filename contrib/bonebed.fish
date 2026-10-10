# Copy to ~/.config/fish/completions/bonebed.fish.
complete -c bonebed -n '__fish_use_subcommand' -a 'help doctor baseline dig survey run bundle report diff compare diff-lock history check lock policy migrate dataset monitor static'
for option in help offline sinkhole strict quiet-target verbose require-container allow-host writes-only real-home refresh docker summary
    complete -c bonebed -l $option
end
for option in version results timeout output-limit argv-limit cwd enforce deny trace repeat jobs require platform executable file gemfile top top-fallback policy lock output state manifest sbom last update
    complete -c bonebed -l $option -r
end
complete -c bonebed -l phase -x -a 'install require all plugin bundler_plugin exec'
complete -c bonebed -l env-profile -x -a 'dev ci prod'
complete -c bonebed -l format -x -a 'md json csv html sarif'
complete -c bonebed -l fail-on -x -a 'info low medium high critical none'
complete -c bonebed -n '__fish_seen_subcommand_from policy' -a generate
