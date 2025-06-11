# Saban

Saban is my attempt to add more automation into my hacking workflow. Currently, I type or copy and paste most of the commands that I use. Taking this approach has been great for learning and understanding what is going on.

I have noticed a lot of the capture the flag machines that I have worked on have similar patterns and I would like to try adding automation. I am not trying to replace things that humans do well.

## Usage

I run this script from my attack box which is running Kali Linux. When I start up the attack box it does not save files or settings from the previous run. Since it is a sandbox environment, this script runs with the assumption that it has not been ran before.

To run the script, I provide the ip address of the capture the flag machine and an optional domain name. The domain name is defaulted to target.thm. Here is a sample run:

`python3 saban.py 10.10.1.1`

If I wanted that machine to use the domain saban.thm, I would run the above command with the optional parameter:

`python3 saban.py 10.10.1.1 saban.thm`
