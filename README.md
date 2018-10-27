# Introduction to Computer Security

## Course Overview

This course focuses on computer security fundamentals, the main concepts, terms and principles. Students will learn to understand what computer security is (and is not), learn threats, vulnerabilities and attacks, principles of practical and provable security,  and get hands-on experience with common security features.
The course is lectured in [Tomsk State University](http://en.tsu.ru).

## Syllabus and Readings

### Part 1: Basics

#### Introduction
Topics:
* Information security, computer security, and cyber security
* Ethics in security research
* Why information security is hard
* Information security myths
* Cryptography and computer security
* Who are the hackers?

Readings:  
* [Noise Security Bit. Об образовании в области ИБ](http://noisebit.podster.fm/6)
* [Noise Security Bit. О практической безопасности](http://noisebit.podster.fm/3)
* [Matt Bishop. Introduction to Computer Security. Chapter 1](http://nob.cs.ucdavis.edu/book/book-intro/)
* [Ken Thompson. Reflections on Trusting Trust](https://crypto.stanford.edu/cs155/papers/thompson.pdf)
* [Phillip Rogaway. The Moral Character of Cryptographic Work](http://web.cs.ucdavis.edu/~rogaway/papers/moral-fn.pdf)

#### Foundational Concepts in Security
Topics:
* Threat, weakness, vulnerability, and attack
* Security policy, security and safety
* Threat modelling
* Attack and attacker modelling
* Security mechanisms
* Risk-oriented approach to computer security

Readings:
* [Sergey Gordeichik. Threat Hunting](https://www.youtube.com/watch?v=i2K0NKV_zho)
* [Threat Model for Secure Password Storage](http://goo.gl/Spvzs)
* [DFD](https://www.owasp.org/index.php/Application_Threat_Modeling) and [Attack Trees](https://en.wikipedia.org/wiki/Attack_tree)
* [STRIDE](http://msdn.microsoft.com/en-us/library/ee823899(v=cs.20).aspx) and [DREAD](http://msdn.microsoft.com/en-us/library/ff648644.aspx)
* [CVSS](https://www.first.org/cvss/calculator/3.0) and [vulnerabilities within CVSS](https://www.first.org/cvss/examples)
* [Robert Graham. Top 10 Most Obvious Hacks of All Time](https://blog.erratasec.com/2017/07/top-10-most-obvious-hacks-of-all-time.html)

#### Security Principles
Topics:
* Kerckhoffs's principle
* Saltzer and Schroeder's design principles
* Defence in depth
* Security by obscurity
* Usability and human factors in security 
* Failures in practice or what goes wrong

Readings:
* [The Protection of Information in Computer Systems. Saltser's and Schroeder's security principles](http://www.cs.virginia.edu/~evans/cs551/saltzer/)
* [Defence in Depth](https://www.sans.org/reading-room/whitepapers/basics/defense-in-depth-525)
* [Security by Obscurity](https://danielmiessler.com/study/security-by-obscurity/)
* [Devdatta Akhawe, Adrienne Porter Felt. Alice in Warningland: A Large-Scale Field Study of Browser Security Warning Effectiveness](https://static.googleusercontent.com/media/research.google.com/en/us/pubs/archive/41323.pdf)
* [Andy Ozment, Stuart E. Schechter. Milk or Wine: Does Software Security Improve with Age?](http://static.usenix.org/event/sec06/tech/full_papers/ozment/ozment.pdf)

#### Provable Security
Topics: 
* Modeling computer insecurity
* Exploitability and provable unexploitability
* Language-based security
* Science of security

Readings:
* [Matt Bishop. Modeling Computer Insecurity](http://nob.cs.ucdavis.edu/bishop/notes/2008-cse-14/2008-cse-14.pdf)
* [Thomas Dullien. Weird machines, exploitability, and provable unexploitability](http://www.dullien.net/thomas/weird-machines-exploitability.pdf)
* [L.Sassaman, M. Patterson, S. Bratus, M. Locasto, A. Shubina. Security Applications of Formal Language Theory](http://www.langsec.org/papers/langsec-tr.pdf)
* [Cormac Herley, P.C. van Oorschot. SoK: Science, Security, and the Elusive Goal of Security as a Scientific Pursuit](https://www.ieee-security.org/TC/SP2017/papers/165.pdf)

#### Access Control
Topics:
* Access control policy
* DAC, MAC, RBAC, and ABAC
* Access control models overview

Readings:
* [HRU Model](http://dl.acm.org/citation.cfm?doid=360303.360333)
* [Take-Grant Model](http://www.cs.nmt.edu/~doshin/t/s06/cs589/pub/2.JLS-TG.pdf)
* [David Bell. Looking Back at the Bell-La Padula Model](https://www.acsac.org/2005/papers/Bell.pdf) 
 
#### Covert channels and side channels attacks
Topics:
* Covert channels
* Side channels

Readings:
* [Jakub Szefer. Survey of Microarchitectural Side and Covert Channels, Attacks, and Defenses](https://eprint.iacr.org/2016/479.pdf) 

### Part 2: Practical Introduction to Cryptography

#### Introduction
Topics:
* Cryptography and computer security
* Historic ciphers

Readings:  
* [A Graduate Course in Applied Cryptography. Introduction](https://crypto.stanford.edu/~dabo/cryptobook/BonehShoup_0_4.pdf)
* [Phillip Rogaway. The Moral Character of Cryptographic Work](http://web.cs.ucdavis.edu/~rogaway/papers/moral-fn.pdf)

#### Cryptographic Security
* Semantic security and attack games
* Informational and computational security
* Perfect security

Readings:
* [A Graduate Course in Applied Cryptography. Chapter 2.3. Computational ciphers and semantic security](https://crypto.stanford.edu/~dabo/cryptobook/BonehShoup_0_4.pdf)
* Jean-Philippe Aumasson. Serious Cryptography. Chapter 3

#### How Things Can Go Wrong
* Attacks
* Cryptography coding 

Readings:
* [Cryptography Coding Standard](https://cryptocoding.net/index.php/Cryptography_Coding_Standard)
* [SoK: Lessons Learned From SSL/TLS Attacks](https://www.ei.ruhr-uni-bochum.de/media/nds/veroeffentlichungen/2013/08/19/paper.pdf)

### Part 3: Practical Introduction to Web Security
* Same-Origin Policy
* Injections
* Cross-Site Request Forgery

Readings:
* [J.Schwenk et al. Same-Origin Policy: Evaluation in Modern Browsers](https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-schwenk.pdf)
* [A.Barth, C.Jackson, J.Mitchell. Robust Defenses for Cross-Site Request Forgery](https://seclab.stanford.edu/websec/csrf/csrf.pdf)
* [Z.Su, G.Wassermann. The Essence of Command Injection Attacks in Web Applications](http://web.cs.ucdavis.edu/~su/publications/popl06.pdf)

## References
### Threat Models
* [GENIVI Threat Model](https://at.projects.genivi.org/wiki/display/SEC/Threat+Model)
* [NIST Mobile Threat Catalogue](https://pages.nist.gov/mobile-threat-catalogue/)
* [Vault Threat Model](https://www.vaultproject.io/docs/internals/security.html)
* [SPIFFE Threat Model](https://docs.google.com/spreadsheets/d/1M2AgqBQTlZSfCL7La2Kz8KhD1M17rbV_OJZN_POQVGg/edit?usp=sharing)
* [OWASP Threat Model for Secure Password Storage](https://www.owasp.org/images/1/12/Secure_Password_Storage.pdf)

## Assignments
* [Course assignments](assignments.md)

## Cources
* [University of Maryland. Computer & Network Security](http://www.cs.umd.edu/class/spring2017/cmsc818O/index.html)
* [University of California, San Diego. CSE 227: Computer Security](http://cseweb.ucsd.edu/classes/fa17/cse227-a/index.html)
* [NYU Paris. Introduction to Computer Security](https://sites.google.com/nyu.edu/paris-csci-ua9480/home)
