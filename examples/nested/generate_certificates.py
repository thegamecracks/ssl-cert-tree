import subprocess
from pathlib import Path

SCRIPT_DIRECTORY = Path(__file__).parent


def main():
    org_name = "Super Certification Company Pty Ltd"
    for i in range(1, 6):
        unit_0 = f"{i}"
        generate_certificate(
            org_name=org_name,
            org_unit=unit_0,
        )

        for j in range(1, 6 - i):
            unit_1 = f"{i}-{j}"
            generate_certificate(
                org_name=org_name,
                org_unit=unit_1,
                cafile=f"{unit_0}.pem",
            )

            for k in range(1, 6 - i - j):
                unit_2 = f"{i}-{j}-{k}"
                generate_certificate(
                    org_name=org_name,
                    org_unit=unit_2,
                    cafile=f"{unit_1}.pem",
                )


def generate_certificate(
    *,
    org_name: str | None = None,
    org_unit: str | None = None,
    cafile: str | None = None,
) -> None:
    filename = SCRIPT_DIRECTORY / f"{org_unit}.pem"

    subject = f""
    if org_name is not None:
        subject += f"/O={org_name}"
    if org_unit is not None:
        subject += f"/OU={org_unit}"

    args = [
        "openssl",
        "req",
        "-x509",        # generate an X.509 certificate instead of a CSR,
        "-subj",        # non-interactively providing the certificate subject,
        subject,
        "-newkey",      # and also generate a private key
        "ed25519",      # using the ed25519 algorithm (more compact than RSA)
        "-noenc",       # without prompting for a passphrase,
        "-out",         # then output certificate
        filename,       # to filename,
        "-keyout",      # and the private key
        filename,       # to filename
    ]

    if cafile is not None:
        # Instead of self-signing, use the given certificate + private key
        args.extend(["-CA", SCRIPT_DIRECTORY / cafile])

    subprocess.check_call(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


if __name__ == "__main__":
    main()
