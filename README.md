# Saban

Saban is my attempt to add more automation into my hacking workflow. Currently, I type or copy and paste most of the commands that I use. Taking this approach has been great for learning and understanding what is going on.

I have noticed a lot of the capture the flag machines that I have worked on have similar patterns and I would like to try adding automation. I am not trying to replace things that humans do well.

Currently, the script runs with no human intervention and just provides information. I want to put human intervention at each point where I can analyze results and then add more tasks for the script.

As an example of what I want for this script to become; I want the script do anonymous login with FTP, recursively list the files and their contents. If the files have any information like a possible username, I would like to add a task that brute forces FTP and SSH with that username and a provided word list.

## Usage

I run this script from my attack box which is running Kali Linux. When I start up the attack box it does not save files or settings from the previous run. Since it is a sandbox environment, this script runs with the assumption that it has not been ran before.

To run the script, I provide the ip address of the capture the flag machine and an optional host name. The host name is defaulted to target.thm. Here is a sample run:

`python3 saban.py 10.10.1.1`

If I wanted that machine to use the host name saban.thm, I would run the above command with the optional parameter:

`python3 saban.py 10.10.1.1 --host saban.thm`
