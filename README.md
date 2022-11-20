# Introduction-to-Pentesting-and-OSINT

Objectives of this article:
1. Understand the role of a pentester in assessing a business's security.
2. Collect domain information using OSINT techniques and tools like Google dorking, Shodan, and certificate transparency.
3. Use Shodan and Recon-ng to discover domain server information.

****PLEASE DO NOT practice these techniques against computers that you do not own or have clear written permission to interact with.******

Penetration testing, often referred to as pentesting or ethical hacking, is the offensive security practice of attacking a network using the same techniques that a malicious hacker would use, in an effort to identify security holes and raise awareness within an organization.

An engagement consists of five phases: Planning and Reconnaissance, Scanning, Exploitation, Post Exploitation, and Reporting.

![image](https://user-images.githubusercontent.com/118358126/202851885-f39b194a-f89c-4564-afcf-070464f39746.png)

![image](https://user-images.githubusercontent.com/118358126/202851901-d009dc10-ffb8-4b96-9ac0-bf5191e0282a.png)

During the planning phase, the engagement's scope and purpose are defined.

The scope includes the type of penetration test that will be run. Types include: no view, full view, and partial view.

# MITRE ATT&CK

![image](https://user-images.githubusercontent.com/118358126/202852045-fc5f9652-88c1-448f-b43e-13921c69c12b.png)

The company MITRE developed the MITRE ATT&CK matrix to provide a visual representation of the most popular techniques, tactics, and procedures (TTPs) that may be performed throughout an assessment.

MITRE ATT&CK is a “hacker’s playbook.”

The matrix is comprehensive, meaning that virtually every potential attack falls under a tactic and maps to a specific technique.

As a penetration tester, it’s beneficial to map out the techniques that you performed in an assessment so that the customer can learn which TTPs were successful and what needs to be addressed.


# Reconnaissance

Reconnaissance, or recon, means gathering information about your target.

Reconnaissance is divided into two types:

1. `Passive Recon`

Often refers to open source intelligence (OSINT), which leverages information about the target that is publicly available on the internet. This includes all domains and hosts belonging to a target that are publicly viewable.

2. `Active Recon`

Also refers to gathering information about the target, but active reconnaissance involves directly interacting with the target.

Reconnaissance can be conducted:

![image](https://user-images.githubusercontent.com/118358126/202852297-b129eb01-d3c3-4aca-92c0-f5123c34f11f.png)


# Google Dorking

Sometimes we're able to identify useful information on the public internet using search engines. 

**Google dorking** enables us to manipulate Google searches to narrow down our queries in order to acquire actionable intel. 

- For example, with a Google search, we could potentially identify email addresses associated with our target. The email addresses could then be used for future phishing campaigns or even for a brute force attack where we guess a password with the email address on a login page. 

- Sometimes, companies accidentally leave sensitive information on the public internet, allowing it to be found through a search engine. 

   - For example: [Vice News: ISP Left Corporate Passwords and Keys Exposed](https://www.vice.com/en/article/zm9dmj/an-isp-left-corporate-passwords-keys-and-all-its-data-exposed-on-the-internet).

Google dorking falls under the technique **Search Open Websites/Domains: Search Engines**, **ID T1593-002**: https://attack.mitre.org/techniques/T1593/002/.
	

***Example***

1. In a browser, navigate to www.google.com. 

2. In the search bar, enter "site:sans.org".

    - This search will filter results to only show links belonging to sans.org.

3. Next, in the search bar, add to the existing search "type:pdf", so the search is now "site:sans.org type:pdf".

    - This search will filter all results to show only PDF documents from the sans.org website. 

4. Replace "type:pdf" with "intext:password", so the search is now "site:sans.org intext:password".

    - This will show any webpage with "password" on the page. This is especially useful for searching for passwords. 

Refer to the following additional resources:

- [Cybrary: Google Dorking Commands](https://www.cybrary.it/blog/0p3n/advanced-google-dorking-commands/)
- [SANS.org: Google Cheat Sheet](https://www.sans.org/security-resources/GoogleCheatSheet.pdf)



# Certificate transparency

Certificate issuers publish logs of SSL/TLS certificates that they issue to organizations. This is known as certificate transparency. 

  - Certificate issuers publish logs of the SSL/TLS certificates that they issue to organizations. This is known as **certificate transparency**. 
  - An SSL/TLS certificate is used to make an HTTP site HTTPS--that is, **secure**. 
  - This certificate transparency can be exploited by attackers and used to search for subdomains. 
  - Using certificate transparency to find subdomains of targets falls under the **Search Open Technical Databases: Digital Certificates**  MITRE technique, **ID T1596.003**. 

    -  https://attack.mitre.org/techniques/T1596/003/.

Remember: Every technique we are performing is attributable back to MITRE. This reference can not only help provide ideas about what to do next as a penetration tester, it can also help defenders recognize what attacks are possible. 

***Example***

1. Open a web browser and navigate to the certificate searching tool at https://crt.sh. 

      - Enter "sans.org" into the search box.

      - Contained within our search results are all the certificates associated with every variation of the example.com domain, as the following image shows:
         
![image](https://user-images.githubusercontent.com/118358126/202889322-8bec465b-e243-4593-85b0-c5ded44888c2.png)

2.  Clicking a certificate result reveals highly detailed information regarding the digital certificate, as the following image shows:

![image](https://user-images.githubusercontent.com/118358126/202889340-cba0feb3-ed32-47e1-a36f-d6a91e7916bf.png)

This information is very useful for finding subdomains of targets. For instance, in this example we can see that the certificate was issued on 07-07-2021, which means the domain that this certificate was applied to is likely still active. An expired certificate would suggest the domain is inactive.
    
    

# Shodan

During reconnaissance and OSINT, we utilize several tools and techniques in order to gather information about the target. The next reconnaissance tool that we'll learn is **Shodan.io**. 

  - **Shodan.io** is a website that conducts port scanning across the entire internet and catalogs the results for quick searching.
  - This site is useful, because it saves us the time we would spend conducting a port scan. Not having to conduct this scan also allows us to keep our originating IP address hidden.
  - Shodan is just one of several websites that conduct port scanning. These fall under the MITRE technique **Search Open Technical Databases: Scan Databases**, **ID T1596.005**.

	-  https://attack.mitre.org/techniques/T1596/005/.

***Example***

1. Navigate to Shodan.io and log in with the Shodan account that you created before class.

      - In the search bar, type "www.sans.org".

      - This search will return several findings, including SSL certs and IP addresses that have a DNS entry with "SANS" in the name, as the following image shows:

![image](https://user-images.githubusercontent.com/118358126/202889417-4ebe56ff-2de2-434b-a101-08a8fce3f8c5.png)

2.  Click the second result, the IP address 192.241.255.118.

    - This page contains a lot of useful information. Note the open ports of the IP address and the DNS name in the "Location" field of one of the ports, as the following image shows:
    
 ![image](https://user-images.githubusercontent.com/118358126/202889450-c354a4e4-f89d-4774-9a4a-cad52833d573.png)
   
3. **CVE** stands for **common vulnerabilities and exposures**. Any vulnerability that is found for any OS, application, API, etc. is assigned a CVE number.

    - Shodan automatically scans for CVEs and will suggest any potential CVEs that the application is vulnerable to.

    - In this example, we can see that CVE-2019-0220 may be applicable to this site, suggesting a denial of service attack is possible. Note that just because a CVE is listed here, doesn't mean that the application is confirmed to be vulnerable. Shodan, like other vulnerability scanners, make assumptions based on versions of services.
    
    
**Summary**

- **Certificate transparency** is a reconnaissance tactic where a penetration tester can gather information from certificate issuers, which publish logs of the SSL/TLS certificates that they issue to organizations.
  - Certificate transparency can be exploited by attackers and used to search for subdomains.
- **Shodan.io** is a reconnaissance website that conducts port scanning across the entire internet and catalogs the results for quick searching.    



# Recon-ng

Recon-ng is a web reconnaissance framework written in Python.

The Recon-ng framework ingests many popular OSINT modules, allowing the results of multiple tools to be combined into a single report.

- Recon-ng provides a powerful, open source, web-based framework for conducting reconnaissance quickly and thoroughly. It includes the following features:
  - Independent modules
  - Database interaction
  - Built-in convenience functions
  - Interactive help
  - Command completion 

There are many scripts and programs that can assist with integrating OSINT tools into Recon-ng.
  - Recon-ng is a framework that ingests a lot of popular OSINT modules, allowing the results of multiple tools to be combined into a single report.
  - Recon-ng also went through a major update recently. The following link details changes from version 4.x to 5.x and a set of new, handy commands that comes with the newer 5.x version. [Read about the changes](https://www.blackhillsinfosec.com/wp-content/uploads/2019/11/recon-ng-5.x-cheat-sheet-Sheet1-1.pdf). 

***Example***

1. in Kali Linux:

    - Run `recon-ng`, as the following image shows:

![image](https://user-images.githubusercontent.com/118358126/202889565-57489add-bdf1-4462-aca1-d1401cfed4ab.png)

- Recon-ng doesn’t come preinstalled with modules, so you must download them as needed.

- We get the error "shodan_api key not set. shodan_ip module will likely fail at runtime. See keys add." That's okay; we'll set up the key in the next step. 
   
2. We need to set an API key for modules that require it before they can be used.

- We'll set an API key for Shodan inside Recon-ng. This allows Recon-ng to ingest Shodan results.

- Using the account that you created for the previous Shodan demonstration, log in to Shodan and click **My Account** in the top-right corner, as the following image shows:

![image](https://user-images.githubusercontent.com/118358126/202889615-79baea33-e9eb-4c63-a999-2d0b03f75d09.png)

- Copy the API key to your clipboard, as the following image shows. You'll use it again in Step 4. 

![image](https://user-images.githubusercontent.com/118358126/202889633-eea05c9c-aa60-478b-bb9e-c9ca5764f6ff.png)

3. In Recon-ng, run `modules search` to view all of the currently installed modules.

- For this activity, we'll use the following two modules:

     - `recon/domains-hosts/hackertarget`
     - `recon/hosts-ports/shodan_ip`
     
     The following image shows these modules:

![image](https://user-images.githubusercontent.com/118358126/202889735-5ea53aab-0767-460c-8a93-a6c9a98d5f51.png)

4. Run `modules load recon/hosts-ports/shodan_ip` to load the `shodan_ip` scanner module.

- Modules need to be loaded prior to modification and use.

- Now that the module has been loaded, we can add the API key by typing:
   
     - `keys add shodan_api [key]`
      
     - Replace `[key]` with the key that you copied to your clipboard earlier.

- This API key allows information sharing between Shodan and Recon-ng. 

5. Run `keys list` to verify that it is imported.

6. Run `info` to get information regarding the Shodan module.

- The `SOURCE` option is required. This option specifies which target Recon-ng will scan. This can be:

     - A list of IP addresses in a text file
     - Individual IPs
     - A domain name
   
- For this example, we'll set the domain name sans.org as our `SOURCE` option.

![image](https://user-images.githubusercontent.com/118358126/202889777-abec7d89-d275-465d-81bb-2078cdda938d.png)

- Set the `SOURCE` to sans.org by typing `options set SOURCE sans.org`, as the following image shows:

![image](https://user-images.githubusercontent.com/118358126/202889786-2a5d4072-2179-4e92-8088-fcdaba669970.png)

- Using Shodan with a pro account allows you to query open ports on your discovered hosts without having to send packets to target systems.

7. Now, we'll use an additional module called **HackerTarget**. 

- HackerTarget will use Shodan to query all of the hosts that belong to sans.org. 

- **Note**: Although HackerTarget can find hosts by itself, combining modules produces better scan results by discovering additional hosts that would otherwise be missed.

   Next, we'll load the `recon/domains-hosts/hackertarget` module and change its `SOURCE` to that of the target.

- Type `modules load recon/domains-hosts/hackertarget`.

- This will load the `recon/domains-hosts/hackertarget` scanner module.
     
- Now that the module is loaded, type `info` to check the `SOURCE` setting, as the following image shows:

![image](https://user-images.githubusercontent.com/118358126/202889828-c6f19419-485e-4468-b00b-04690e8ed104.png)

- Set the `SOURCE` to sans.org by typing `options set SOURCE sans.org`, as the following image shows:

![image](https://user-images.githubusercontent.com/118358126/202889847-23587ae3-b1b0-40a3-b13e-7260f0e989c3.png)

   - The HackerTarget and Shodan modules serve two distinct purposes:
   
      - The HackerTarget module uses the `SOURCE` option to display scan results verbosely.

      - The Shodan module uses the `SOURCE` option to specify which target Recon-ng will scan.  
      
8. From within the `hackertarget` module, type `run`, as the following image shows:

![image](https://user-images.githubusercontent.com/118358126/202889870-9f6e4a2b-0e84-415e-a84a-69656f13ea51.png)

- Recon-ng will query Shodan for sans.org.

- The results will automatically display verbosely in the terminal window.
      
**Summary**      
	  
- **Recon-ng** is a tool written in Python and used primarily for information gathering by ethical hackers, such as penetration testers.
- Recon-ng comes preloaded with numerous modules that use online search engines, plugins, and APIs, which work together to gather information against a target.
- Network defenders use information obtained from Recon-ng to formulate mitigation strategies that help defend their networks.














