#! /bin/bash

target="ec2-user@10.196.180.24"

if [ $# -eq 0  ] || [ -z "$1" ] || { [ $1 != "stg" ] && [ $1 != "prd" ]; } then
    echo "==> invalid command line argument. supported values are stg or prd"
    exit 1
fi

env="$1"
targetLocation="$target:/home/ec2-user/apps/jiraAutomation/$env/"
deployFolder=".deploy"
root=$PWD
if [ -d "$deployFolder" ]; then
    rm -r "$deployFolder"
fi

echo "==> creating deployment folder: $deployFolder"
mkdir "$deployFolder"

echo "==> building JIRAAutomation"
cd cmd/JIRAAutomation/
if GOOS=linux GOARCH=amd64 CC="/usr/local/bin/x86_64-linux-musl-gcc" go build -ldflags " -s -w" -o "${root}/${deployFolder}/jiraAutomation" ; then
    echo "==> build success"
else
    echo "==> build failed, not continuing further..."
    exit 1
fi
cd "${root}"

echo "==> preping deploy folder"
cp "config/${env}.toml" "$deployFolder/"
cp "config/gapi-keys.json" "$deployFolder/"

echo "==> pushing artefacts"
scp -r "${deployFolder}/"* $targetLocation

echo "==> done"
