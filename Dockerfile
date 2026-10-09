FROM ruby:4.0.6@sha256:8dc3950712ad2078bdd275b890419ba2fd3aab5a0653b291a7325f0d8a24ca05

WORKDIR /opt/bonebed
COPY lib ./lib
COPY exe ./exe
COPY schema ./schema
COPY docs ./docs
COPY contrib ./contrib
COPY examples ./examples
COPY bonebed.gemspec plugins.rb README*.md CHANGELOG.md SECURITY.md LICENSE.txt ./
RUN gem build --strict bonebed.gemspec --output bonebed.gem \
  && gem install --no-document ./bonebed.gem \
  && rm bonebed.gem \
  && useradd --uid 10001 --create-home bonebed \
  && mkdir /work \
  && chown bonebed:bonebed /work

USER 10001:10001
WORKDIR /work
ENTRYPOINT ["bonebed"]
CMD ["--help"]
