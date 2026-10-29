#!/bin/bash
# Reset: fresh target/decoy exports (new generation, grants, revisions, artifact
# bytes), clear the relay pool and observer lineage, restart the victim actor.
# Never creates the disclosure itself.
exec env FORCE_RESTART=1 /usr/local/bin/start-app.sh
