# Instructions for using these dev containers

## Assumptions
1. The host platform is Linux or Apple/MacOS.
1. Docker and or Docker Desktop are installed and the local user has permissions to use the docker daemon.
1. ClamAV cvd files are present in $HOME/data/cvd
    - If you want to change this directory, edit the path in the devcontainer.json file
    - If you want to install cvd files on the container itself, comment out the line that mounts this directory in the
    devcontainer.json file.
1. ssh-agent is running
    - ```echo $SSH_AUTH_SOCK```
        - If no agent is running, ```eval $(ssh-agent -s)```

## Host Setup
See: https://code.visualstudio.com/remote/advancedcontainers/sharing-git-credentials
1. In your $HOME/.bash_profile (or $HOME/.zprofile if your shell is zsh), add:
```
if [ -z "$SSH_AUTH_SOCK" ]; then
   # Check for a currently running instance of the agent
   RUNNING_AGENT="`ps -ax | grep 'ssh-agent -s' | grep -v grep | wc -l | tr -d '[:space:]'`"
   if [ "$RUNNING_AGENT" = "0" ]; then
        # Launch a new instance of the agent
        ssh-agent -s &> $HOME/.ssh/ssh-agent
   fi
   eval `cat $HOME/.ssh/ssh-agent` > /dev/null
   ssh-add 2> /dev/null
fi
```
1. In your $HOME/.bashrc (of $HOME/.zshrc if your shell is zsh), add:
```export UID```
1. Note that you will need to source the files you modified and run ```code .``` to open VSCode from the shell you
sourced from to pick up the new environment variables, or reboot. (i.e. ```. ~/.bash_profile```, etc.)
1. **OPTIONAL** Install and or update cvd files in the appropriate directory on the host, which matches the mountpoint
in devcontainer.json

## VSCode Setup
1. Install the following extensions:
    1. Dev containers - Microsoft
    1. Container Tools - Microsoft
    1. Docker - Microsoft
    1. Remote Development - Microsoft
1. Click the green icon in the bottom-left corner of the VSCode window (or press F1)
1. Select ```Dev Containers: Reopen in Container```
1. Select the devcontainer.json file for the container you wish to open.