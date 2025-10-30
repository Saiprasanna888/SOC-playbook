import { TermDefinition } from "./socTermsData";

export const attackTypes: TermDefinition[] = [
  {
    term: 'Phishing',
    description: 'An attacker sends a deceptive email or message, pretending to be a trustworthy company (like a bank or IT support), to trick you into clicking a malicious link or giving up your password. **Real-life example:** You get an email from "Netflix" saying your payment failed and asking you to log in via a link to update your billing details.',
  },
  {
    term: 'Spear Phishing',
    description: 'A highly targeted phishing attack aimed at a specific individual or organization. The attacker uses personal information (like your name, job title, or recent projects) to make the email look extremely convincing and relevant. **Real-life example:** An email appears to come from your CEO, mentioning a project you are working on, and urgently asks you to transfer funds to a new vendor account.',
  },
  {
    term: 'Whaling',
    description: 'A specific type of spear phishing that targets senior executives (whales) like the CEO or CFO. These attacks aim for maximum impact, often involving large financial fraud or access to highly confidential data. **Real-life example:** An attacker impersonates a board member to trick the CFO into releasing quarterly financial reports early.',
  },
  {
    term: 'Vishing (Voice Phishing)',
    description: 'Phishing conducted over the phone. Attackers use voice calls, often employing automated systems or spoofed caller IDs, to trick victims into revealing personal or financial information. **Real-life example:** A call from "Amazon Support" claims your account was compromised and asks you to verify your credit card number to secure it.',
  },
  {
    term: 'Smishing (SMS Phishing)',
    description: 'Phishing conducted via text message (SMS). The message usually contains a malicious link or a phone number to call, often related to package delivery or bank alerts. **Real-life example:** You receive a text message claiming your package delivery failed and includes a tiny URL link to reschedule, which actually leads to a credential harvesting site.',
  },
  {
    term: 'Ransomware',
    description: 'Malicious software that locks or encrypts all your files and demands a payment (ransom), usually in cryptocurrency, in exchange for the decryption key. **Real-life example:** A user opens a malicious attachment, and suddenly all documents, photos, and spreadsheets on their computer and shared drives are renamed with a ".lock" extension, and a ransom note appears on the screen.',
  },
  {
    term: 'DDoS Attack (Distributed Denial of Service)',
    description: 'An attack that floods a website or online service with massive amounts of traffic from many compromised computers (a botnet), overwhelming the target and making it unavailable to legitimate users. **Real-life example:** A banking website slows down to a crawl or crashes completely because millions of fake requests are hitting its servers simultaneously.',
  },
  {
    term: 'SQL Injection',
    description: 'An attack that exploits weaknesses in web applications that use databases. The attacker inserts malicious database commands (SQL statements) into input fields (like a login box) to steal, modify, or delete data. **Real-life example:** An attacker types a special string like `\' OR 1=1 --` into a username field, tricking the application into logging them in without a password.',
  },
  {
    term: 'Cross-Site Scripting (XSS)',
    description: 'A vulnerability that allows an attacker to inject malicious code (usually JavaScript) into a legitimate website. When another user views that website, the malicious script runs in their browser, potentially stealing cookies or session tokens. **Real-life example:** An attacker posts a comment on a forum containing a malicious script. When other users read the comment, the script runs and steals their session cookies.',
  },
  {
    term: 'Cross-Site Request Forgery (CSRF)',
    description: 'An attack that tricks a logged-in user\'s browser into sending an unwanted request to a web application where they are currently authenticated. The attacker exploits the trust the application has in the user\'s browser. **Real-life example:** While logged into your bank, you visit a malicious website that contains hidden code forcing your browser to send a request to your bank to transfer money to the attacker.',
  },
  {
    term: 'Man-in-the-Middle (MitM) Attack',
    description: 'An attacker secretly intercepts and relays communication between two parties who believe they are talking directly. The attacker can listen in, steal data, or even alter the messages being exchanged. **Real-life example:** An attacker sets up a fake Wi-Fi hotspot in a coffee shop to intercept all traffic, including login credentials, between users and the internet.',
  },
  {
    term: 'Malware',
    description: 'A general term for any software intentionally designed to cause damage, gain unauthorized access, or disrupt a computer system. This includes viruses, worms, Trojans, and ransomware. **Real-life example:** A user downloads a free game that secretly contains a program designed to steal their banking information.',
  },
  {
    term: 'Spyware',
    description: 'Malware designed to secretly monitor and record a user\'s activity on their computer, such as keystrokes, screenshots, and web browsing history, and transmit that data back to the attacker. **Real-life example:** A program installed without your knowledge tracks every website you visit and reports it to a third party for targeted advertising or theft.',
  },
  {
    term: 'Adware',
    description: 'Software that automatically displays unwanted advertisements, often in the form of pop-up windows or banners, while a program is running. While often annoying, some adware can also contain spyware components. **Real-life example:** After installing a free utility tool, your browser is constantly flooded with pop-up ads, even when you are not using the utility.',
  },
  {
    term: 'Trojan Horse',
    description: 'A type of malware disguised as legitimate, useful software. It tricks the user into installing it, and once executed, it performs malicious actions hidden from the user, such as creating a backdoor. **Real-life example:** A file named "Free_Antivirus_Installer.exe" is downloaded, but when run, it installs a remote access tool instead of security software.',
  },
  {
    term: 'Rootkit',
    description: 'A stealthy set of software tools designed to hide the existence of certain processes, files, or network connections from the operating system and security tools, allowing an attacker to maintain persistent, undetectable control. **Real-life example:** An attacker installs a rootkit on a server that hides the malicious process used for Command and Control (C2) communication, making it invisible to standard system monitoring.',
  },
  {
    term: 'Worm',
    description: 'A standalone malicious program that replicates itself and spreads automatically across a network without needing a host file or user interaction. Worms often exploit network vulnerabilities to jump from one computer to the next. **Real-life example:** The WannaCry worm spread rapidly by exploiting a vulnerability in Windows SMB, infecting thousands of computers globally within hours.',
  },
  {
    term: 'Botnet',
    description: 'A network of compromised, internet-connected devices (bots) controlled remotely by a single attacker (bot-herder). Botnets are used to launch massive coordinated attacks, like DDoS or large-scale spam campaigns. **Real-life example:** Thousands of infected IoT devices (like security cameras) are secretly commanded to simultaneously flood a target website with traffic, causing it to crash.',
  },
  {
    term: 'Keylogger',
    description: 'A type of surveillance software or hardware that records every keystroke a user types on a specific computer\'s keyboard, capturing passwords, credit card numbers, and private messages. **Real-life example:** A keylogger installed on a public library computer records the login credentials of every user who accesses their email or bank account.',
  },
  {
    term: 'Zero-Day Exploit',
    description: 'An attack that targets a software vulnerability that is completely unknown to the software vendor and the public. Since the vendor has had "zero days" to prepare a patch, the attack is highly effective until a fix is released. **Real-life example:** An attacker discovers a flaw in a popular web browser and uses it to gain control of users\' computers before the browser company even knows the flaw exists.',
  },
  {
    term: 'Drive-By Download',
    description: 'An unintended download of malicious software that occurs simply by visiting a compromised website, often without the user clicking anything. This usually happens when the website exploits a vulnerability in the user\'s browser or operating system. **Real-life example:** You visit a legitimate news site that has been secretly compromised, and malware is automatically downloaded and executed on your computer in the background.',
  },
  {
    term: 'Brute Force Attack',
    description: 'A trial-and-error method used to guess a password, encryption key, or hidden web page by systematically trying every possible combination until the correct one is found. **Real-life example:** An attacker uses an automated tool to try thousands of common passwords (like "password123", "qwerty", "123456") against a user\'s account until one works.',
  },
  {
    term: 'Dictionary Attack',
    description: 'A specific type of brute force attack that attempts to crack a password by systematically trying every word found in a dictionary or a list of common passwords. This is much faster than trying every possible character combination. **Real-life example:** An attacker uses a list of the top 10,000 most common passwords to quickly compromise accounts that use weak, dictionary-based passwords.',
  },
  {
    term: 'Session Hijacking',
    description: 'The exploitation of a valid computer session (e.g., a logged-in web session) to gain unauthorized access to information or services. The attacker steals the session token (cookie) and uses it to impersonate the legitimate user. **Real-life example:** An attacker steals your session cookie after you log into an online store and uses that cookie to make purchases under your name without needing your password.',
  },
  {
    term: 'Credential Stuffing',
    description: 'A large-scale attack where attackers take lists of usernames and passwords stolen from one website breach and automatically try them against many other unrelated websites (e.g., social media, banking) because many users reuse passwords. **Real-life example:** An attacker obtains a list of 1 million credentials from a gaming site leak and uses a bot to test those same email/password combinations against 50 different e-commerce sites.',
  },
  {
    term: 'Clickjacking',
    description: 'A technique that tricks a user into clicking on a hidden, malicious element (like a button or link) that is overlaid on a legitimate web page. The user thinks they are clicking one thing, but they are actually clicking another. **Real-life example:** A user tries to click a "Play Video" button, but they are secretly clicking a hidden "Authorize Webcam Access" button on a different, invisible page.',
  },
  {
    term: 'Cryptojacking',
    description: 'The unauthorized use of someone else\'s computer processing power to secretly mine cryptocurrency for the attacker. This often happens via malicious code embedded in a website or malware installed on the victim\'s machine. **Real-life example:** A user visits a compromised website, and their computer\'s CPU usage spikes to 100% because the website is secretly running a script to mine Monero using their resources.',
  },
  {
    term: 'Watering Hole Attack',
    description: 'An attack where the attacker compromises a website that a specific group of targets (e.g., employees of a certain company) is known to frequently visit, waiting for them to become infected. **Real-life example:** An attacker knows all employees of Company X read a specific industry blog, so they infect that blog with malware, waiting for Company X employees to visit and download the payload.',
  },
  {
    term: 'Side-Channel Attack',
    description: 'An attack based on information gained from the physical implementation of a computer system, rather than weaknesses in the implemented software or algorithm. This includes measuring power consumption, electromagnetic radiation, or timing of operations. **Real-life example:** A researcher measures the exact time it takes for a smart card to perform a cryptographic operation to deduce the secret key being used.',
  },
  {
    term: 'Supply Chain Attack',
    description: 'An attack that infiltrates a system by targeting a less secure element in the supply chain, such as an outside partner, a software vendor, or a hardware manufacturer, to compromise the final product or service. **Real-life example:** Attackers compromise a software company\'s update server and inject malware into a legitimate software update, which is then distributed to thousands of customers (like the SolarWinds attack).',
  },
  {
    term: 'BEC (Business Email Compromise)',
    description: 'A sophisticated scam where a cybercriminal uses compromised email credentials or spoofs a corporate email address to trick an employee (often in finance) into making an urgent wire transfer or sending sensitive data. **Real-life example:** The finance department receives an email, seemingly from the CEO, instructing them to immediately pay an invoice to a new, fraudulent bank account.',
  },
  {
    term: 'Eavesdropping Attack',
    description: 'A passive attack where the attacker secretly listens to or intercepts private communication or data transfer over a network. This is often done by monitoring unencrypted traffic. **Real-life example:** An attacker uses a packet sniffer on a network segment to capture unencrypted FTP login credentials as they are transmitted.',
  },
  {
    term: 'Replay Attack',
    description: 'A network attack where a valid data transmission (e.g., an authentication request) is captured by an attacker and then maliciously repeated or delayed to trick the system into granting access or performing an action. **Real-life example:** An attacker captures a packet that successfully authenticates a user and resends that exact packet later to gain access without knowing the password.',
  },
  {
    term: 'Packet Sniffing',
    description: 'The practice of monitoring and capturing all data packets passing through a given network using specialized software (like Wireshark). Attackers use this to steal sensitive information, especially if the traffic is unencrypted. **Real-life example:** An attacker connects a laptop to a network switch and runs a sniffer to capture all local network traffic, looking for passwords or sensitive file contents.',
  },
  {
    term: 'Buffer Overflow',
    description: 'A low-level programming flaw where a program tries to write more data into a temporary storage area (buffer) than it was designed to hold. This excess data spills over and overwrites adjacent memory, which can be exploited by an attacker to execute malicious code. **Real-life example:** An attacker inputs an extremely long string into a program\'s input field, causing the program to crash and allowing the attacker to inject their own commands into the system\'s memory.',
  },
  {
    term: 'Backdoor',
    description: 'A secret method of bypassing normal security and authentication procedures to gain unauthorized, persistent access to a computer system. Backdoors can be intentionally created by developers or secretly installed by attackers. **Real-life example:** An attacker installs a small piece of code on a web server that allows them to log in using a hidden username and password, even if the main admin password is changed.',
  },
  {
    term: 'Logic Bomb',
    description: 'A piece of malicious code intentionally inserted into a software system that remains dormant until a specific condition is met (e.g., a specific date, a user\'s termination, or a file being deleted), at which point it executes its harmful payload. **Real-life example:** A disgruntled employee inserts code that will wipe the company\'s database exactly 30 days after their user account is disabled.',
  },
  {
    term: 'Birthday Attack',
    description: 'A statistical attack that exploits the mathematics behind the "Birthday Problem" (the probability that two people in a group share the same birthday). In cryptography, it makes it easier for an attacker to find two different inputs that produce the same hash value (a collision). **Real-life example:** An attacker uses this statistical method to quickly generate two different malicious documents that have the same digital signature hash, tricking a system that relies on hash uniqueness.',
  },
  {
    term: 'Ping of Death',
    description: 'An old, simple denial-of-service attack that involves sending an oversized or malformed network packet (a "ping") to a target computer. The target system cannot properly handle the packet, causing it to crash or freeze. **Real-life example:** An attacker sends a massive ping packet to an outdated server, causing its network stack to overflow and the server to reboot unexpectedly.',
  },
  {
    term: 'Bluesnarfing',
    description: 'The unauthorized access, theft, and viewing of information (like contacts, calendars, and emails) from a wireless device (usually a phone) via a vulnerable Bluetooth connection without the owner\'s knowledge. **Real-life example:** An attacker walks past a victim with an old phone and uses a tool to silently download their entire contact list via Bluetooth.',
  },
  {
    term: 'Bluejacking',
    description: 'The practice of sending unsolicited messages (like text or images) to nearby Bluetooth-enabled devices. This is usually harmless but is considered a nuisance and a security policy violation. **Real-life example:** Someone in a crowded train station sends a random text message advertisement to every nearby phone with Bluetooth enabled.',
  },
  {
    term: 'Evil Twin',
    description: 'A fraudulent Wi-Fi access point that mimics a legitimate one (e.g., "Starbucks Free Wi-Fi"). Users connect to the Evil Twin, allowing the attacker to eavesdrop on all their wireless communications, including passwords and session data. **Real-life example:** An attacker sets up a router outside a hotel, naming the network "Hotel Guest Wi-Fi," and captures the credentials of guests who connect.',
  },
  {
    term: 'War Driving',
    description: 'The act of searching for and mapping vulnerable Wi-Fi wireless networks by a person, usually in a moving vehicle, using a laptop or smartphone. The goal is often to find open or weakly secured networks to exploit later. **Real-life example:** A hacker drives through a suburban neighborhood, logging the GPS coordinates of every unsecured Wi-Fi network they detect.',
  },
  {
    term: 'Rogue Security Software',
    description: 'Malicious software that tricks users into believing their computer is infected with a virus and demands payment for a fake malware removal tool. This is a form of scareware designed to steal money. **Real-life example:** A pop-up window appears on your screen, flashing red warnings that your system is critically infected, and prompts you to buy "Antivirus Pro 2024" immediately to fix it.',
  },
];