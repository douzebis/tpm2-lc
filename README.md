# tpm2-lc

TPM2 life cycle: registration, onboarding, attestation, unsealing

## Run mock-up

Prior to running the mock-up, the following manual setup must be performed:

Create a GCP shielded vm with ubuntu 22.10 and run the mock-up on this shielded
vm, as ubuntu user:

``` bash
sudo su - ubuntu
sudo apt-get update
sudo apt-get install -y golang
sudo apt-get install -y tpm2-tools
# tpm2-tools create user tss, give it read/write access to /dev/tpmrm0
sudo usermod -a -G tss ubuntu
sudo chgrp tss /sys/kernel/security/tpm0/binary_bios_measurements 
sudo update-grub
sudo reboot now
sudo su - ubuntu
git clone https://github.com/douzebis/tpm2-lc.git
cd tpm2-lc/
go run src/init/main.go -alsologtostderr
```

Then:

``` bash
go run src/init/main.go -alsologtostderr -v 5
```

Then:

``` bash
git pull && clear && go run src/onboard/main.go -alsologtostderr -v 5
```