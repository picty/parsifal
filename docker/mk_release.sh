#!/bin/bash

set -e

TAG="$1"
[ -n "$TAG" ] || ( echo "$0 <tag>" >&2 ; exit 1 )

PROGDIR="$(dirname "$0")"
cd $PROGDIR

[ -n "$PUBLISH_RELEASE" ] && git tag "$TAG"

cd ..
git archive -o docker/release/parsifal.tar --format tar --prefix parsifal/ HEAD

docker build -t parsifal:"$TAG" docker/release

docker tag parsifal:"$TAG" pictyeye/parsifal:"$TAG"
docker tag parsifal:"$TAG" pictyeye/parsifal:latest
[ -n "$PUBLISH_RELEASE" ] && docker push pictyeye/parsifal:"$TAG"
[ -n "$PUBLISH_RELEASE" ] && docker push pictyeye/parsifal:latest

rm -f docker/release/parsifal.tar
