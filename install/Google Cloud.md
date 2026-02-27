# Google Cloud Installation

## Get an Intel TDX Confidential Computing VM

At minimum you need a `c3-standard-4` with `Confidential image (Ubuntu 24.04 LTS NVIDIA version: 580)`. Allow HTTPS traffic in the firewall and give it the network tag `ra-tls-server`.

Alternatively, run this command line (update with your `project` and `service-account`) to create a template:

```bash
gcloud compute instances create tdx-c3-4-eu-lon-dev-1 \
    --project=tdx-dev-123456 \
    --zone=europe-west9-a \
    --machine-type=c3-standard-4 \
    --network-interface=network-tier=PREMIUM,nic-type=GVNIC,stack-type=IPV4_ONLY,subnet=default \
    --maintenance-policy=TERMINATE \
    --provisioning-model=STANDARD \
    --service-account=123456789-compute@developer.gserviceaccount.com \
    --scopes=https://www.googleapis.com/auth/devstorage.read_only,https://www.googleapis.com/auth/logging.write,https://www.googleapis.com/auth/monitoring.write,https://www.googleapis.com/auth/service.management.readonly,https://www.googleapis.com/auth/servicecontrol,https://www.googleapis.com/auth/trace.append \
    --tags=https-server,ra-tls-server \
    --create-disk=auto-delete=yes,boot=yes,device-name=tdx-c3-4-eu-lon-dev-1,disk-resource-policy=projects/tdx-dev-123456/regions/europe-west9/resourcePolicies/default-schedule-1,image=projects/ubuntu-os-accelerator-images/global/images/ubuntu-accelerator-2404-amd64-with-nvidia-580-v20260225,mode=rw,size=10,type=pd-balanced \
    --shielded-secure-boot \
    --shielded-vtpm \
    --shielded-integrity-monitoring \
    --labels=goog-ec-src=vm_add-gcloud \
    --reservation-affinity=any \
    --threads-per-core=1 \
    --confidential-compute-type=TDX
```

Connect to your VM

```bash
gcloud compute ssh --zone "europe-west9-a" "tdx-c3-4-eu-lon-dev-1" --project "tdx-dev-123456"
```

## Install the Quote Generation Stack

On your **TDX Host machine**, install the necessary Intel DCAP libraries:

```bash
# Update
sudo apt update
sudo apt upgrade

# Add the Intel SGX/TDX repository (use 'noble' for 24.04 or 'jammy' for 22.04)
wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo gpg --dearmor -o /usr/share/keyrings/intel-sgx-keyring.gpg
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx-keyring.gpg] https://download.01.org/intel-sgx/sgx_repo/ubuntu noble main" | sudo tee /etc/apt/sources.list.d/intel-sgx.list
sudo apt update

# Install the Quote Library (QL) and Quote Provider Library (QPL)
sudo apt install -y libsgx-dcap-ql libsgx-dcap-default-qpl libsgx-dcap-ql-dev
```

### Point the Client to your PCCS

The Quote Provider Library (QPL) looks at a specific configuration file to find your PCCS.

```bash
# Edit the Quote Configuration Network Library file
sudo nano /etc/sgx_default_qcnl.conf
```

Update the JSON to look like this (replace `<PCCS_IP>` with the IP of your PCCS server):

```json
{
  "pccs_url": "https://<PCCS_IP>:8081/sgx/certification/v4/",
  "use_secure_cert": true,
  "pccs_api_version": "3.1",
  "retry_times": 3,
  "retry_delay": 3
}
```

Run a quick check to ensure the TDX host can reach the PCCS over the network:

```bash
curl -k https://<PCCS_IP>:8081/sgx/certification/v4/rootcacrl
```

### Verify if the TDX Hardware is active:

```bash
# Check if TDX is enabled in the CPU
lscpu | grep -i tdx_guest

# Check if the TDX guest driver device is present
ls -l /dev/tdx_guest
```

*If `/dev/tdx_guest` is missing, the VM was not booted as a Trust Domain.

### Generate a TD Quote

Intel provides a sample application that performs the full attestation flow: it talks to the TDX hardware, gets a report, sends it to the Quoting Service, and pulls certificates from your PCCS.

```bash
# Install the sample code and dependencies
sudo apt install -y libtdx-attest libtdx-attest-dev gcc make

# Navigate to the sample directory
cd /opt/intel/tdx-quote-generation-sample/ 2>/dev/null || cd /usr/share/doc/libtdx-attest/examples/ 

# Build the sample (if not pre-compiled)
sudo make

# Run the test
# -d provides 'report data' that gets hashed into the quote
sudo ./test_tdx_attest -d 1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
```

You should see a **"Successfully get the TD Quote"** and have a `quote.dat`.

### Check the MRTD and RTMRs

To prove the quote is valid and see what's inside (including those RTMRs), you can use the `sgx_utls` tool (if installed) or a verification script:

```bash
# If you have the DCAP tools installed
# This parses the quote.dat and shows the MRTD (build measurement) and RTMRs
head -c 1024 quote.dat | hexdump -C
```

## Install Caddy and Privasys's RA-TLS module

### Install Go (Privasys fork with RA-TLS support)

The RA-TLS module requires a [Go fork](https://github.com/Privasys/go/tree/ratls) that adds `ClientHelloInfo.RATLSChallenge` to `crypto/tls` for challenge-response attestation.

```bash
# Go back to home directory
cd ~

# Install build dependencies
sudo apt install -y git build-essential wget

# Install official Go (needed to bootstrap the fork)
wget https://go.dev/dl/go1.24.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.24.0.linux-amd64.tar.gz
rm go1.24.0.linux-amd64.tar.gz

# Clone the Privasys Go fork (ratls branch)
git clone -b ratls https://github.com/Privasys/go.git ~/go-ratls

# Build Go from source using official Go as bootstrap (~2-3 min on c3-standard-4)
export GOROOT_BOOTSTRAP=/usr/local/go
cd ~/go-ratls/src && ./make.bash

# Set the fork as the active Go toolchain (replaces the bootstrap)
echo 'export GOROOT=~/go-ratls' >> ~/.bashrc
echo 'export PATH=$GOROOT/bin:$HOME/go/bin:$PATH' >> ~/.bashrc
source ~/.bashrc

# Verify — should show the fork version
go version
```

### Install xcaddy

[xcaddy](https://github.com/caddyserver/xcaddy) builds Caddy with custom modules:

```bash
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
```

### Build Caddy with the RA-TLS module

```bash
# Clone ra-tls-caddy
git clone https://github.com/Privasys/ra-tls-caddy.git ~/ra-tls-caddy
cd ~/ra-tls-caddy/src

# Build Caddy with the RA-TLS issuer module
xcaddy build --with github.com/Privasys/ra-tls-caddy=.

# Move the binary somewhere in PATH
sudo mv caddy /usr/local/bin/caddy
sudo chmod +x /usr/local/bin/caddy

# Verify
caddy version
caddy list-modules | grep ra_tls
```

You should see `tls.issuance.ra_tls` in the module list.

### Prepare the CA certificates

The RA-TLS module signs certificates with a **private intermediary CA**. You need the intermediate CA certificate and key (which chains back to your root CA).

Create the certs directory on the VM:

```bash
sudo mkdir -p /etc/caddy/certs
```

From your **local machine**, upload the intermediate CA certificate and key:

```bash
scp intermediate-ca.dev.crt <user>@<vm-ip>:/tmp/
scp intermediate-ca.dev.key <user>@<vm-ip>:/tmp/
```

Then back on the **VM**, move them into place and lock down permissions:

```bash
sudo mv /tmp/intermediate-ca.dev.crt /etc/caddy/certs/
sudo mv /tmp/intermediate-ca.dev.key /etc/caddy/certs/
sudo chown root:root /etc/caddy/certs/*
sudo chmod 644 /etc/caddy/certs/intermediate-ca.dev.crt
sudo chmod 600 /etc/caddy/certs/intermediate-ca.dev.key
```

### Create the Caddyfile

```bash
sudo mkdir -p /etc/caddy
sudo nano /etc/caddy/Caddyfile
```

Minimal configuration that serves RA-TLS on port 443:

```caddyfile
https://<your_host>:443 {
    tls {
        issuer ra_tls {
            backend tdx
            ca_cert /etc/caddy/certs/intermediate-ca.dev.crt
            ca_key  /etc/caddy/certs/intermediate-ca.dev.key
        }
    }
    respond "Hello from an Intel TDX Confidential VM configured with Privasys!"
}
```

### Test Caddy manually

Before creating the systemd service, test it directly:

```bash
sudo caddy run --config /etc/caddy/Caddyfile
```

From another terminal (or your local machine):

```bash
curl -k https://<your_host>:443
# Should print: Hello from a Confidential VM!
```

Press `Ctrl+C` to stop.

### Create the systemd service

```bash
sudo nano /etc/systemd/system/caddy-ratls.service
```

Paste:

```ini
[Unit]
Description=Caddy RA-TLS Web Server
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/caddy run --config /etc/caddy/Caddyfile
ExecReload=/usr/local/bin/caddy reload --config /etc/caddy/Caddyfile
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

> **Note:** Caddy runs as root because it needs access to `/sys/kernel/config/tsm/report` for TDX attestation and to the CA private key.

Activate the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now caddy-ratls
sudo systemctl status caddy-ratls
```

View logs:

```bash
journalctl -u caddy-ratls -f
```

### Verify the RA-TLS certificate

From your local machine, inspect the certificate to confirm the TDX quote is embedded:

```bash
echo | openssl s_client -connect <your_host>:443 \
  -servername <your_host> 2>/dev/null \
  | openssl x509 -noout -text
```

Look for the TDX quote extension (`1.2.840.113741.1.5.5.1.6`) in the X.509 extensions — it should contain ~8 KB of attestation evidence.
