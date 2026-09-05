# swtpm-patch

makes a libvirt VM's swtpm present as a genuine AMD fTPM: manufacturer
strings, vendor IDs, firmware version, an EK certificate with a plausible TCG
subject and finite validity, and a resolvable AIA CA URI. guest-side TPM
checks (GetCapability properties, EK chain) then read AMD end to end.

## files

    provision/tpm-provision.sh                 deployer
    provision/patch_libtpms.py                 libtpms identity patcher
    provision/swtpm_patch_localca_wrapper      localca wrapper (reference copy)
    libexec/swtpm-patch-reissue-ek-cert.py     EK cert re-signer
    libexec/swtpm-patch-tpm-aia-server.py      AIA http server
    libexec/swtpm-patch-ms-mirror.py           TLS mirror serving the repacked CAB
    provision/swtpm-patch-forge-cab.py         CAB repacker, injects the issuer CA
    libexec/swtpm-patch-verify-tpm-profile.py  verifier
    systemd/swtpm-patch-tpm-aia.service        systemd unit for the server
    hooks/libvirt-qemu-hook                    swtpm cpu pin hook (reference copy)
    pki/amd-ftpm-ca.cer                        example CA cert

## running it

    sudo ./provision/tpm-provision.sh amd

one run does, in order:

1. byte-patches every libtpms-family lib (system + swtpm-bundled), backups in
   /var/lib/swtpm-patch/libtpms-backups
2. writes the localca wrapper and points /etc/swtpm_setup.conf
   create_certs_tool at it
3. writes /etc/swtpm-localca.options and /etc/swtpm-localca.conf
4. generates the issuer CA in /var/lib/swtpm-localca
5. generates the served AIA cert in /var/lib/swtpm-patch-tpm-aia/pki/aia/
6. installs and enables swtpm-patch-tpm-aia.service, checks it answers
7. pre-seeds swtpm once (dual EK RSA+ECC, PCR banks) to validate end to end
8. chowns CA state to tss:tss, must be last, see the note in the script

then define the VM with:

    <tpm model='tpm-crb'><backend type='emulator' version='2.0'/></tpm>

and give it DNS that resolves ftpm.amd.com to the AIA gateway (the script
wires the pin itself).

verify:

    sudo python3 /usr/local/libexec/swtpm-patch-verify-tpm-profile.py

## notes

- swtpm package updates wipe the libtpms patch. re-run
  the provision script again after any swtpm/libtpms upgrade.
- the tss chown (step 8) has to stay after the root pre-seed (step 7), or
  fresh installs brick on .lock.swtpm-localca permissions.
- the AIA server binds the libvirt gateway IP:8080 and answers for host
  ftpm.amd.com. without the DNS pin in the guest the EK chain won't resolve.
- patch_libtpms.py patches all libtpms-family libs on purpose, swtpm links
  its bundled copy, not the system one.
- the microsoft mirror (step 5b) needs osslsigncode on the host. it rebuilds
  TrustedTpm.cab with the issuer CA injected, signs it with the patch CA, and
  serves it on go.microsoft.com / download.microsoft.com via libvirt DNS pins.
- guest step, once per VM: import the patch CA into the trusted roots:

      certutil -f -addstore root patch-ca.pem

  fetch it from the AIA server:
  http://ftpm.amd.com:8080/pki/aia/patch-ca.pem
- the libvirt hook is optional. install to /etc/libvirt/hooks/qemu, adjust
  the domain name and CPU pin for your box.
- windows guest that stops booting after the identity change (bitlocker /
  boot state): boot recovery media and restore the EFI boot file:

      mountvol S: /S
      copy C:\Windows\Boot\EFI\bootmgfw.efi S:\EFI\Microsoft\Boot\bootmgfw.efi

  that brings it back.
