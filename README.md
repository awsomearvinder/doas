# doas clone for linux written in rust

This is just a fun project cause I got bored one day - don't expect much support and I wouldn't reccomend using it. If you _do_ decide to use it, file issues by all means, but again: this is a hobby project, nothing more, nothing less. Keep your expectations low and use sudo or whatever unless you _really_ want to try this out.

Currently configuration has just been added however it is not yet very secure. I'm not sure if it's behavior is as of yet perfect - specifically around how it handles command line arguments in `deny` cases.

NOTE: I'm decently confident that the subset of the config that is implemented is implemented correctly, that said - I haven't completely tested it yet. You can give it a shot, and I wouldn't worry about security *too* much surrounding the config, but your running an app that replaces sudo from a random dev. Take it as you wish.

As of now, I haven't really used any doas code or looked at how it works, this is purely my code, meaning I'm not basing my code off of any more robust codebase's code either. Look around and play with it if you want, but that's all I'm reccomending.


# In case it wasn't obvious enough - look at #23.
First example of a regression that *heavily* would of compromised security if it was actually used. Don't use this. Please. Don't be dumb.
