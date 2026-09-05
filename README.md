# swtpm-patch

makes a libvirt VM's swtpm present as a genuine AMD fTPM. manufacturer,
vendor IDs, firmware version, EK certificate, and the trust chain all read
as AMD through microsoft's TrustedTpm.cab validation.

the provision script forges a TrustedTpm.cab with the local issuer CA
injected as a trusted root, re-signs it, and serves it on microsoft's own
download domains through libvirt DNS pins. the guest imports the local CA
once, after which every check passes: EK chain, bootloader measurement,
TPM quote, PCR replay.

## files

    provision/tpm-provision.sh                 deployer
    provision/patch_libtpms.py                 libtpms identity patcher
    provision/swtpm_patch_localca_wrapper      localca wrapper (reference copy)
    provision/swtpm-patch-forge-cab.py         CAB forger
    libexec/swtpm-patch-reissue-ek-cert.py     EK cert re-signer
    libexec/swtpm-patch-tpm-aia-server.py      AIA http server
    libexec/swtpm-patch-ms-mirror.py           TLS mirror for the CAB
    libexec/swtpm-patch-verify-tpm-profile.py  verifier
    systemd/swtpm-patch-tpm-aia.service        AIA unit
    hooks/libvirt-qemu-hook                    cpu pin hook (reference copy)
    pki/amd-ftpm-ca.cer                        example CA cert

## host setup

arch-style linux, root access. packages:

    pacman -S swtpm libvirt python python-cryptography openssl cabextract

osslsigncode is not in the official repos. build from source:

    git clone https://github.com/mtrojnar/osslsigncode
    cd osslsigncode && mkdir build && cd build
    cmake -DCMAKE_INSTALL_PREFIX=/usr/local .. && make && make install

## running it

    sudo ./provision/tpm-provision.sh amd

patches libtpms, sets up the cert chain, downloads and rebuilds
TrustedTpm.cab with the issuer CA as a root, starts the AIA server on 8080
and the microsoft mirror on 443, pins DNS, pre-seeds the TPM, and prints
the guest steps.

define the VM with:

    <tpm model='tpm-crb'><backend type='emulator' version='2.0'/></tpm>

verify on the host:

    sudo python3 /usr/local/libexec/swtpm-patch-verify-tpm-profile.py

## guest setup (one time)

admin prompt in the windows guest:

    curl http://ftpm.amd.com:8080/pki/aia/patch-ca.pem -o patch-ca.pem
    certutil -f -addstore root patch-ca.pem

disable IPv6 on the adapter (the DNS pin only covers IPv4, AAAA lookups
reach real microsoft):

    Get-NetAdapterBinding | Where ComponentID -eq 'ms_tcpip6' | Disable-NetAdapterBinding -ComponentID 'ms_tcpip6'

## notes

- re-run the provision script after any swtpm or libtpms package update,
  the patch gets wiped
- the tss chown has to stay last, doing it before the pre-seed bricks
  fresh installs on lockfile permissions
- patch_libtpms.py patches all libtpms-family libs on purpose, swtpm links
  its bundled copy, not the system one
- the libvirt hook is optional, install to /etc/libvirt/hooks/qemu and
  adjust the domain and CPU pin for your box
- windows guest that stops booting after the identity change: boot
  recovery media and restore the EFI boot file

      mountvol S: /S
      copy C:\Windows\Boot\EFI\bootmgfw.efi S:\EFI\Microsoft\Boot\bootmgfw.efi
