# Instructions for using these dev containers

## Dependencies

1. The host platform is Linux or macOS.
1. Docker or Docker Desktop are installed and the local user has permissions to use the Docker daemon.
1. You must have a directory `$HOME/data/cvd` for the Dev Container to mount as the ClamAV database directory. See below for setup instructions.
1. `ssh-agent` must be running to share Git credentials with the container. See below for setup instructions.
1. The `UID` environment variable must be set to export your user's ID. See below for setup instructions.

## Set up database directory mount path

Create a database directory for sharing signature files from the host to the dev container:
```sh
mkdir -p $HOME/data/cvd
```

Place any ClamAV signature files in this directory that you want to make available to the dev container.

> _Tip_: If you want to change this directory, edit the path in the `devcontainer.json` file. Or, if you want to install signature files on the container itself, comment out the line that mounts this directory in the `devcontainer.json` file.

## Set up `UID` user ID environment variable.

For Bash shell, edit `$HOME/.bashrc`. Or for Zsh, edit `$HOME/.zshrc`. Add the following:
```sh
export UID=$(id -u)
```

Source this file (e.g. run `source $HOME/.bashrc` or `source $HOME/.zshrc`) to apply this change in your current shell. Or open a new terminal.

## VSCode Setup
1. Install the following extensions:
    1. Dev containers - Microsoft
    1. Container Tools - Microsoft
    1. Docker - Microsoft
    1. Remote Development - Microsoft
1. Click the green icon in the bottom-left corner of the VSCode window (or press F1)
1. Select `Dev Containers: Reopen in Container`
1. Select the devcontainer.json file for the container you wish to open.