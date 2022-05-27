sudo docker stop kms_test
sudo docker rm kms_test
sudo docker build -t xmargininc/kms_test_img ./ -f ./Docker/Dockerfile
sudo docker run -d  --restart unless-stopped --net=latest_appsnet --privileged -v /etc/letsencrypt:/certs -v /dev/isgx:/dev/isgx --name kms_test -v $(pwd):/usr/src/app/ xmargininc/kms_test_img 
