sudo docker stop kms_test
sudo docker rm kms_test
sudo docker build -t trustup/sgx_test_img ./ -f ./Dockerfile 
sudo docker run -d --net=latest_appsnet --privileged -v /dev/isgx:/dev/isgx --name sgx_test -v $(pwd):/usr/src/app/ trustup/sgx_test_img 
