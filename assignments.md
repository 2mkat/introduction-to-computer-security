# Assignments

## Attack Tree
Build an attack tree describing ways to realize a chosen computer security threat. You may use [draw.io](https://michenriksen.com/blog/drawio-for-threat-modeling/).

## CVSS Scoring
Calculate scores for 3 popular and known vulnerabilities within [DREAD](https://msdn.microsoft.com/en-us/library/aa302419.aspx) and [CVSSv3](https://www.first.org/cvss/calculator/3.0) models.

## Covert Channel
Develop a covert channel in a web application in Go. Some ideas and inspiration you can find [here](https://github.com/cdpxe/Network-Covert-Channels-A-University-level-Course).

## Cryptopals
Solve all challenges in [Cryptopals Set 1](https://cryptopals.com/sets/1) in Go.

## Constant-time String Comparison
Implement a string comparison algorithm on your own and then implement secure one comparing strings in constant time.
To understand why it is necessary and where it is used see this [link](https://github.com/veorq/cryptocoding#compare-secret-strings-in-constant-time).

## Hash Function
This task is proposed and used in [the Blockchain class](https://github.com/matthewdgreen/blockchains/wiki/Assignment-1) by Matthew Green.

Suppose Mallory is launching a new 'secure' messaging app.
When Alice installs the app, it creates an account for her on the server using a hash of her phone number.
The app then queries the server by sending a hash of each phone number in Alice's contacts to learn which of Alice's friends are already on the platform.
The goal is that users can discover their friends without the server learning the contents of every user's address book.
Assuming phone numbers are 10 digits, explain why this does not achieve the intended security goal.
How can Mallory act maliciously to determine the phone numbers of every one of Alice's contacts?

## Paper Review
Prepare an executive summary (1 or 2 pages) for a scientific paper related to computer security in a broad sense.

Some questions you have to answer are as follows:
- What problem is this paper tackling?
- How security is defined? What an adversary is assumed?  
- What is the potential impact of the results?
- What advances over the previous state of knowledge are made?
- What are the main results; what do the security bounds “say”?
- Do the hardness assumptions that are used to support proofs seem reasonable?
- What open problems are surfaced by the authors, for future work?
