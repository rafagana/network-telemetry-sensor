# Commands to Update the GitHub Repository

From a clean working directory:

```bash
git clone https://github.com/rafagana/network-telemetry-sensor.git
cd network-telemetry-sensor
```

Copy the contents of this update package into the cloned repository, then run:

```bash
git status
git add README.md CHANGELOG.md RELEASE_NOTES_v1.2.0.md UPDATE_REPO_COMMANDS.md \
  requirements-sensor.txt requirements-vault.txt .gitignore \
  sensor vault docs systemd scripts examples

git commit -m "Release v1.2.0 adaptive eBPF telemetry sensor"
git push origin main

git tag -a v1.2.0 -m "Release v1.2.0: adaptive eBPF sensor and vault receiver"
git push origin v1.2.0
```

If your default branch is not `main`, replace `main` with the correct branch name.
