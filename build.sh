#!/bin/sh

userParam=$1
if [ "$userParam" = "prod" ];
then
    version=$2
    if [ -n "$version" ];
    then
        sudo docker build -t incisive.azurecr.io/iam_img:$version ./ -f ./Docker/Dockerfile_PROD
    else
        echo "You must add the docker image version"
    fi;
elif [ "$userParam" = "dev" ];
then
    version=$2
    if [ -n "$version" ];
    then
        sudo docker build -t incisive.azurecr.io/iam_img:$version ./ -f ./Docker/Dockerfile_DEV
    else
        echo "You must add the docker image version"
    fi;
else
    echo "Please tell me which version: dev/prod"
fi;
    

