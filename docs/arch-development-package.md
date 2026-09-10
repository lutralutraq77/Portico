# Arch development package

The package recipe supplies the development `portico` binary, a manual page and a notice identifying the source revision. It does not provide an installed client agent or connector/controller service. The package is unsigned and is intended for isolated development qualification; project licensing, release signers, distribution trust and supported-platform gates remain unresolved.

`scripts/prepare-arch-package.ps1` requires a clean checkout, verifies the pinned Go SDK, builds a static Linux/amd64 binary and records its Go build information. It generates a PKGBUILD with explicit SHA-256 values for every source file. Source revision, source timestamp, target, package version and hashes are retained with the input bundle under `work/arch-package/<revision>`. Existing output is preserved instead of overwritten.

The recipe uses Arch's normal `check()` and `package()` functions. It declares no runtime dependencies for this static command and retains the built binary bytes by disabling stripping and separate debug-package generation. The owner has not selected a project license; the empty license list and development notice do not invent a grant. [Arch PKGBUILD reference](https://man.archlinux.org/man/PKGBUILD.5.en).

## Qualification workflow

The hosted workflow builds from the checked-out source with Go 1.27.1 and selects the official Arch `base-devel` image by the immutable digest recorded in [the image lock](../tools/arch-package.lock.json). Downloading that pinned image and Go dependencies occurs before the two networkless container runs.

The first container runs `makepkg` as an unprivileged user, with a read-only root, no capabilities, no new privileges, private temporary storage and only the public input/output artifact directories. The disposable temporary build mount explicitly allows execution so the normal check function can run the Linux binary; it retains `nosuid` and `nodev`. A deliberately modified application must fail checksum verification before the original is restored and packaged. The package and installed build-package versions are retained. [Arch makepkg reference](https://man.archlinux.org/man/makepkg.8.en), [Docker temporary mount options](https://docs.docker.com/engine/storage/tmpfs/).

The second, fresh container installs the local package using its unchanged signature policy. It checks the installed binary's owner/mode and exact hash, invokes the commands, inspects package contents and removes the package. A separately created private state fixture must survive removal unchanged. No host installation directory or credential is mounted. The fixture records the package and log hashes; it does not sign, publish or deploy the package. [Pacman package operations](https://man.archlinux.org/man/pacman.8.en).

The first [hosted candidate](https://github.com/lutralutraq77/Portico/actions/runs/34491601050), source `6b674a34f03f64960926865a178d4ba702c981f6`, prepared the binary, pulled the pinned image, rejected modified source and passed all three input checksums. It failed before packaging because the check command could not execute the binary in the temporary build directory. The failed log is preserved at `work/reports/arch-first-failure.log`; artifact `10158023034` retains the candidate inputs. The follow-up explicitly permits execution in that disposable build mount and records its mode/options; build and install/remove qualification remain pending.

Cross-compilation and container execution do not qualify real desktop integration, systemd service behavior, user isolation, host clocks, physical suspend, hardware custody or Mullvad. Those remain in the [delivery ledger](delivery-status.md).
