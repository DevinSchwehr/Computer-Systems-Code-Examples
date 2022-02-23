# Computer-Systems-Code-Examples
This repository contains a few files that showcase good code developed by me for a class at the University of Utah. While they had some base starter code within them, I fully implemented the core concepts found within each of these files.

This code is NOT to be plagiarized or copied in any way.

# Shell

This program (tsh.c) was developed to exercise skill in process/job control, signals and signal handling, I/O piping, and concurrent jobs.

While the jobs themselves that are performed are simple, the code is more about the act of creating foreground and background jobs, sending signals and handling them, and managing piping between two jobs. Developed in C.

# Memory Allocator

This program (mm.c) was developed with the goal of making a dynamic memory allocator for C programs that imitates _malloc_ and _free_ without actually calling either of these functions. It utilizes coalescing and best-fit search. The allocator has an emphasis on space-efficiency and speed.

# Concurrent Web Server

This assignment modified an existing base of code to create a concurrent web server that would handle a list of friends. If one person befriended another (Say Alice and Bob became friends) then Alice would be in Bob's friend list, and Bob within Alice's. There was also functionality to remove friends, to view a list of friends, and also to send a request to another server to retrieve a list of friends and add them to the current server.

It utilizes threads, locking and unlocking, as well as parsing a URL in order to figure out what request is being made.
