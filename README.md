# swtpm-patch

makes a libvirt VM's swtpm present as a genuine AMD fTPM, all the way
through microsoft's TrustedTpm.cab validation. manufacturer strings, vendor
IDs, firmware, EK certificate, and the trust chain all read as AMD.

## files

    provision/tpm-provision.sh                 deployer
    provision/patch_libtpms.py                 libtpms identity patcher
    provision/swtpm_patch_localca_wrapper      localca wrapper (reference copy)
    provision/swtpm-patch-forge-cab.py         TrustedTpm.cab forger (MSZIP)
    libexec/swtpm-patch-reissue-ek-cert.py     EK cert re-signer
    libexec/swtpm-patch-tpm-aia-server.py      AIA http server
    libexec/swtpm-patch-ms-mirror.py           TLS mirror for the CAB download
    libexec/swtpm-patch-verify-tpm-profile.py  verifier
    systemd/swtpm-patch-tpm-aia.service        AIA server unit
    hooks/libvirt-qemu-hook                    swtpm cpu pin hook (reference copy)
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

patches libtpms, sets up the cert chain, forges the microsoft CAB with the
issuer CA injected as a root, starts the AIA and mirror servers, pins the DNS,
and pre-seeds validates the whole thing. the guest needs one import (below).

define the VM with `<tpm model='tpm-crb'><backend type='emulator' version='2.0'/></tpm>`.

verify on the host:

    sudo python3 /usr/local/libexec/swtpm-patch-verify-tpm-profile.py

## guest setup (one time)

in the windows guest, admin prompt:

    curl http://ftpm.amd.com:8080/pki/aia/patch-ca.pem -o patch-ca.pem
    certutil -f -addstore root patch-ca.pem

disable IPv6 on the VM's network adapter (the DNS pin only covers IPv4, and
AAAA lookups would reach real microsoft):

    Get-NetAdapterBinding | Where ComponentID -eq 'ms_tcpip6' | Disable-NetAdapterBinding -ComponentID 'ms_tcpip6'

## notes

- swtpm package updates wipe the libtpms patch. re-run the provision script
  after any swtpm/libtpms upgrade.
- the tss chown (final step) has to stay after the root pre-seed, or fresh
  installs brick on .lock.swtpm-localca permissions.
- the mirror binds the libvirt gateway IP on ports 8080 and 443 and answers
  for ftpm.amd.com, go.microsoft.com, and download.microsoft.com.
- the forged CAB uses MSZIP compression matching the original. the injected
  root cert is DER (the forge script converts automatically).
- IPv6 on the guest NIC causes AAAA lookups to bypass the DNS pin. disable
  it or configure a local AAAA override.
- patch_libtpms.py patches all libtpms-family libs on purpose, swtpm links
  its bundled copy, not the system one.
- the libvirt hook is optional. install to /etc/libvirt/hooks/qemu, adjust
  the domain name and CPU pin for your box.
- windows guest that stops booting after the identity change (bitlocker /
  boot state): boot recovery media and restore the EFI boot file:

      mountvol S: /S
      copy C:\Windows\Boot\EFI\bootmgfw.efi S:\EFI\Microsoft\Boot\bootmgfw.efi
