sudo docker stop sgx_test
sudo docker rm sgx_test
sudo docker build -t trustup/sgx_test_img ./ -f ./Docker/Dockerfile 
sudo docker run -d --net=latest_appsnet --privileged --name sgx_test -v $(pwd):/usr/src/app/ trustup/sgx_test_img 
