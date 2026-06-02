---
title: Hunting for Linux Kernel Public Vulnerabilities
date: 2022-06-06
author: kiks
---
## Introduction
Recently was looking for a vulnerability that permitted me to practise what I've learned during the last few months on Linux Kernel Exploitation with a "real-life" scenario. Since I had a week to dedicate my time in Hacktive Security to deepen a specific argument, I decided to search for a public vulnerability without a public exploit to develop it by myself. The next blog post will be related to the development of that 1day, this one is a quick post about how I discovered and choose the vulnerability using online sources, since I didn't found anything similar online.

## TL;DR
This blog post is about public resourses to identify known vulnerabilities in the Linux Kernel in order to practise some Kernel Exploitation in a real-life scenario. These resources includes: BugZilla, SyzBot, changelogs and git logs.

## Public bugs
The first thing I asked myself was: how do I find a suitable bug for my purpose? I excluded searching it by CVE since not all vulnerabilities have an assigned CVE (and usually they are the most "famous" ones) and that's when I used the most powerful hacking skill: googling. That led me to various resources that I would like to share today starting by saying that that's only the result of my personal work that could not reflect the best way to perform the same job. That said, this is what I've used to find my "matched" Nday:

-   Bugzilla
-   SyzBot
-   Changelogs
-   Git log

Kernel changelogs is definitely my favourite one but let's say few words on all of them.

### BugZilla
[BugZilla](https://bugzilla.kernel.org/) is the standard way to [report bugs](https://www.kernel.org/doc/html/v4.19/admin-guide/reporting-bugs.html) in the upstream Linux kernels. You can find interesting vulnerabilities organised by subsystem (e.g. Networking with IPv4 and IPv6 or file system with ext* types and so on) and you can also search for keywords (such as "overflow", "heap", "UAF" and so on ..) using the standard search or the more advanced one. The personal downside is the mix of a lot of "non vulnerabilities", hangs and stuff like that. Also, you do not have the most powerful search options (e.g. some bash). However, it is still a good option and I personally pinned few vulnerabilities that i excluded afterwards.

### Syzbot
"syzbot is a continuous fuzzing/reporting system based on syzkaller fuzzer" [source](https://lwn.net/Articles/749910/).  
Not the best GUI but at least you can have a lot of potentially open and fixed vulnerabilties. There isn't a built-in search option but you can use your browser's one or parse the HTML with an HTML parser. One of the downside, beyond the lack of searching, is the presence of tons of false-positives (in the "Open section"). However, upsides are pretty good: you can find open vulnerabilites (still not fixed), reproducers (C or syzlang), fixed commits and reported issues have the syzkaller nomenclature that is pretty self-explainationary.

#### Syzkaller-bugs (Google Group)
The lack of a search functionality in syz-bot is well replaced by the ["syzkaller-bugs" Google Group](https://groups.google.com/g/syzkaller-bugs/) from where you can find syz-bot reported bugs with additional information from the comment section and an enanched search bar. I really enjoy this option !

### Changelogs
That's my favourite method: download all changelogs from the [kernel CDN](https://cdn.kernel.org/pub/linux/kernel/VERSION/) of your desired kernel version and you can enjoy all downloaded files with your favourite bash commands. This approach is similar to search from git commits but with the advantage that it is way faster. With some bash-fu, you can download all changelogs for a target kernel version (e.g. 4.x) with the following inline: `URL=https://cdn.kernel.org/pub/linux/kernel/v4.x/ && curl $URL | grep "ChangeLog-4.9" | grep -v '.sign' | cut -d "\"" -f 2 | while read line; do wget "$URL/$line"; done`.  
Once all changelogs have been downloaded it's possible to `grep` for juicy keywoards like UAF, OOB, overflow and so on. I found very useful to display text before and after the selected keyword, like: `grep -A5 -B5 UAF *`. In that way, you can instantly have quick information about vulnerability details, impacted subsystem, limitations, ..  
For each identified vulnerability, it's possible to see its patch by diffing the patch commit with the previous one (linux source from git is needed): `git diff <commit before> <commit patch>`.

### Git log
As said before, this is a similar approach to the "Changelogs" method. The concept is pretty simple: clone the github repository and search for juicy keywoards in the commit history. You can do that with the following commands:

```bash
git clone git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git
cd linux-stable
git checkout -f <TAG -> # e.g. git checkout -f v4.9.316 (from https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git)
git log > ../git.log
```

In that way, you can do the same thing as before on `git.log` file. The big downside, however, is that the file is too big and it takes more time (11.429.573 lines on 4.9.316). That's the reason why I prefer the "Changelog" method.

## Personal Experience
I was searching for an Use-After-Free vulnerability and I started to search for it in all mentioned resources: BugZilla, SyzBot, Changelogs and git history. I wrote them down in a table with a resume description in order to further analyze them later on. I started to dig into few of them viewing their patch and source code in order to understand reachability, compile dependencies and exploitability. I strumbled into an interesting one: a vulnerability in the RAWMIDI interface (commit c13f1463d84b86bedb664e509838bef37e6ea317). I discovered it with the "Changelog" method, by searching for the "UAF" keyword reading the previous and next five lines: `grep -A5 -B5 UAF *`. By seeing its behaviours, I was convinced to go with that vulnerability, an Use-After-Free triggered in a race condition.

## Conclusion
I illustrated my experience on finding a public vulnerability to practise some linux kernel exploitation using public resources. The next blog post will be about the mentioned vulnerability in the RAWMIDI interface with all steps involved in the exploitation phase.

## References
- https://bugzilla.kernel.org/  
- https://www.kernel.org/doc/html/v4.19/admin-guide/reporting-bugs.html  
- https://lwn.net/Articles/749910/  
- https://groups.google.com/g/syzkaller-bugs/  
- https://cdn.kernel.org/pub/linux/kernel/VERSION/
