#!/bin/sh
# One database and one owner per tool, on the first start of an empty volume.
set -eu

for spec in "defectdojo:$DD_DB_PASSWORD" "sonar:$SONAR_DB_PASSWORD"; do
  name=${spec%%:*}
  password=${spec#*:}
  psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" <<SQL
CREATE USER $name WITH PASSWORD '$password';
CREATE DATABASE $name OWNER $name;
SQL
done
