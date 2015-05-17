## JHU ACM Minecraft Bot
By Brian Ho, bho6@jhu.edu

# Overview

This project aims to create an *extensible and standalone* Minecraft bot that will reside on the JHU ACM Minecraft server (london.acm.jhu.edu:25565). The bot will send and receive packets from the server (like any old Notchian client) to update global position and *maintain an internal representation of the environment*. Thus, the bot will abstract away all low level packet encoding/decoding and instead expose a simple interface for accessing information about the world or performing actions. The bot programmer can then use these high level functions to write scripts that dictate bot behavior.


# Exposed API

This section is still in flux as the bot is being developed, but the basic design is as follows:

- The bot's functionality is split into two parts. The first is the master program which maintains world information, and the second is any number of user created programs that the master program coordinates. Each user created program can subscribe to events from the master program like timer, movement_update, and chat with a callback function. The master program emits events to subscribers upon receiving the relevant packets from the server and envoke the corresponding callback function. The master program also divides its child programs into two groups: active and inactive. Through this, inactive programs will not receive event updates, and any program's execution state can be controlled through in-game chat (ex: mcbot run defend_base).

- The master program in the bot authenticates and logs into the server on its own and then starts decoding received packets. Based on the content in these packets, the bot will be able to maintain an internal representation of the surrounding world (chunk data, nearby players, health, current position, etc). The bot will also expose methods for performing actions (move forward, turn x degrees, chat, jump, etc). Upon receiving events, running child programs can use the world representation and actions API to express almost any bot behavior.

- The bot will first be created as a minimum viable product that only handles a subset of events based on incoming packets and performable actions. For example, this implementation will not have functionality for emitting an event when fireworks are displayed or making the bot hop into a minecart. However, the bot will be easily extended to handle any packet, so the eager programmer should be able to add functionality as needed without much hassle or low-level code glue.


# Special Thanks

I would like to thank the folks at [http://wiki.vg/](http://wiki.vg/) for providing relatively complete documentation on the server protocol.