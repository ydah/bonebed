# Source this file from ~/.bashrc. Completion never executes gem targets.
_bonebed_complete() {
  local current previous commands options
  current=${COMP_WORDS[COMP_CWORD]}
  previous=${COMP_WORDS[COMP_CWORD-1]}
  commands='help doctor baseline dig survey run bundle report diff compare diff-lock history check lock policy migrate dataset monitor static'
  options='--help --version --phase --results --timeout --offline --sinkhole --strict --quiet-target --verbose --require-container --allow-host --output-limit --argv-limit --env-profile --writes-only --real-home --cwd --enforce --deny --trace --repeat --jobs --require --platform --executable --file --gemfile --top --top-fallback --format --fail-on --policy --lock --output --state --manifest --sbom --last --update --refresh --summary --docker'
  case "$previous" in
    --phase) COMPREPLY=($(compgen -W 'install require all plugin bundler_plugin exec' -- "$current")); return ;;
    --env-profile) COMPREPLY=($(compgen -W 'dev ci prod' -- "$current")); return ;;
    --format) COMPREPLY=($(compgen -W 'md json csv html sarif' -- "$current")); return ;;
    --fail-on) COMPREPLY=($(compgen -W 'info low medium high critical none' -- "$current")); return ;;
    policy) COMPREPLY=($(compgen -W 'generate' -- "$current")); return ;;
  esac
  if (( COMP_CWORD == 1 )); then
    COMPREPLY=($(compgen -W "$commands --help --version --docker" -- "$current"))
  elif [[ "$current" == -* ]]; then
    COMPREPLY=($(compgen -W "$options" -- "$current"))
  else
    COMPREPLY=()
  fi
}
complete -o default -F _bonebed_complete bonebed
