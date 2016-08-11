# CATNET

This command-line application is sort'of confusingly named, mostly a pun of sorts. I'm ok with this. This application is meant to help monitor IPv4 connections similar to the way the netstat command works including ascii art, colors ( including rainbows ), logs, and customizable policies for interacting or responding to information. Very effective for understanding tcp/udp IPv4 communications for linux distributions. 

TODO: 
* Extending the logging options further.
* Assess celluloid implementation for better speed.
* More customizable options.
* IPv6 support?

---

## Usage

```
Usage: catnet [options]

    -t, --tcp                        show tcp connections only
    -u, --udp                        show udp connections only
    -s, --start                      start application with defaults
    -m, --monitor                    start application in monitor mode
    -n, --notify                     use notifications if avaiable
    -b, --[no-]banner                use cool ascii cat banner
    -p, --policy <FILE.yaml>         define a policy to use
    -C, --config <FILE.yaml>         define a custom config to use
    -L, --[no-]log                   Choose to use logging ( off default ).
    -D, --debug                      Enter a debug mode with pry.
    -l, --listen                     only show ports which are listening
    -r, --rainbow                    rainbow support, because we need it.
```

---

## Examples

Start catnet using default everything ( useful to get up and running without the fuss ):

`ruby catnet.rb -s`

Only show tcp connections that are listening, including cool ascii art banner:

`ruby catnet.rb -b -l`

Log catnet connections to catnet.log:

`ruby catnet.rb -L`

Start catnet in monitor mode using a custom policy which will notify users if policy has a match:

`ruby catnet.rb -m -n -p policy.yaml`

---

#### Credits

[Kent 'picat' Gruber](https://github.com/picatz)

---
