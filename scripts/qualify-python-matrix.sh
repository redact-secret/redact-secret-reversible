#!/bin/sh
# Run one Linux cell of the Python persistence matrix (gate G9) in Docker, against a PostgreSQL container.
#
#   scripts/qualify-python-matrix.sh setup
#   scripts/qualify-python-matrix.sh run <node-image> <python> <pytest-or-python-command...>
#
# Environment (all optional):
#   RSV_MATRIX_VOLUME    Docker volume that holds the repository copy, the Linux node_modules, and the Python
#                        interpreters and virtualenvs (default rsv-matrix-work)
#   RSV_MATRIX_NETWORK   Docker network that carries the database (default rsvnet)
#   RSV_MATRIX_PLATFORM  e.g. linux/amd64 to run under emulation; the record must label such a cell as emulated
#   RSV_MATRIX_PG        name of the PostgreSQL container on that network (default rsv-pg-linux)
#   RSV_MATRIX_SETUP_IMAGE image used by `setup` (default node:22-bookworm: it needs npm and curl)
#
# `setup` copies the working tree (without .git, node_modules, or build output) into the volume, runs `npm ci` and
# `npm run build` there so the native parts are the Linux ones, installs `uv` into the volume (static binary), and creates one
# virtualenv per Python version with the package installed editable together with the extras and `psycopg[binary]`.
# `run` re-copies the tree (so a changed test is picked up), then runs the command in packages/vault-py with the
# virtualenv of <python> first on PATH, `node` from <node-image>, and the database URLs of the PostgreSQL container.
#
# Run one command at a time per volume: two runs copy the tree into the same directory and can collide. Use RSV_MATRIX_VOLUME
# for a second one.
#
# The database is a disposable container started by the caller, for example
#   docker network create rsvnet
#   docker run -d --name rsv-pg-linux --network rsvnet -e POSTGRES_PASSWORD=synthetic-matrix-only postgres:17
# The password is synthetic. Nothing here uses a real credential or account.
set -eu

REPO=$(cd "$(dirname "$0")/.." && pwd)
VOLUME=${RSV_MATRIX_VOLUME:-rsv-matrix-work}
NETWORK=${RSV_MATRIX_NETWORK:-rsvnet}
PG=${RSV_MATRIX_PG:-rsv-pg-linux}
PLATFORM=${RSV_MATRIX_PLATFORM:-}
PASSWORD=synthetic-matrix-only

if [ "${RSV_IN_CONTAINER:-}" = "1" ]; then
  mode=$1
  shift
  mkdir -p /work/repo
  tar -C /src --exclude=./.git --exclude=node_modules --exclude=dist --exclude=./.claude --exclude=./graft --exclude=./.cache --exclude=__pycache__ -cf - . |
    tar -C /work/repo -xf -
  export UV_PYTHON_INSTALL_DIR=/work/uvpy UV_CACHE_DIR=/work/uvcache PYTHONDONTWRITEBYTECODE=1
  if [ "$mode" = "setup" ]; then
    cd /work/repo
    [ -d node_modules ] || npm ci
    npm run build
    # The official installer: a static binary, so the same uv works in every image of the matrix.
    [ -x /work/tools/bin/uv ] || curl -LsSf https://astral.sh/uv/install.sh | UV_INSTALL_DIR=/work/tools/bin UV_NO_MODIFY_PATH=1 sh
    for v in 3.11 3.12 3.13; do
      if [ ! -d "/work/venvs/py$v" ]; then
        /work/tools/bin/uv venv --quiet --python "$v" "/work/venvs/py$v"
        /work/tools/bin/uv pip install --quiet --python "/work/venvs/py$v/bin/python" \
          -e "/work/repo/packages/vault-py[test,lint,crypto,postgres,aws-kms]" "psycopg[binary]" psycopg-pool
      fi
    done
    echo "setup done: $(node --version), $(uname -m)"
    exit 0
  fi
  python_version=$1
  shift
  export PATH="/work/venvs/py$python_version/bin:$PATH"
  export RSV_PG_ADMIN_URL="postgres://postgres:$PASSWORD@$PG:5432/postgres"
  export RSV_PG_APP_URL="postgres://rsv_app:$PASSWORD@$PG:5432/postgres"
  export RSV_REQUIRE_POSTGRES=1
  cd /work/repo
  node packages/store-postgres/scripts/create-app-role.mjs
  node packages/vault-py/tests/pg_prepare.mjs
  cd packages/vault-py
  echo "CELL node $(node --version) python $(python --version 2>&1) $(uname -s) $(uname -m)"
  exec "$@"
fi

mode=${1:?usage: qualify-python-matrix.sh setup | run <node-image> <python> <command...>}
shift
docker volume create "$VOLUME" >/dev/null
platform_flag=""
[ -n "$PLATFORM" ] && platform_flag="--platform $PLATFORM"
if [ "$mode" = "setup" ]; then
  image=${RSV_MATRIX_SETUP_IMAGE:-node:22-bookworm}
  # shellcheck disable=SC2086
  exec docker run --rm $platform_flag -v "$VOLUME":/work -v "$REPO":/src:ro -e RSV_IN_CONTAINER=1 "$image" \
    sh /src/scripts/qualify-python-matrix.sh setup
fi
image=${1:?node image}
python_version=${2:?python version}
shift 2
# shellcheck disable=SC2086
exec docker run --rm $platform_flag --network "$NETWORK" -v "$VOLUME":/work -v "$REPO":/src:ro \
  -e RSV_IN_CONTAINER=1 -e RSV_MATRIX_PG="$PG" "$image" \
  sh /src/scripts/qualify-python-matrix.sh run "$python_version" "$@"
