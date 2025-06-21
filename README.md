# YoungDevInterns_Cyber-Security_Expert_Tasks
# 🔐 Web Security Tasks Documentation

This repository contains detailed step-by-step guides for three fundamental cybersecurity tasks, tested on **Parrot OS** using widely accepted tools and methodologies.

---

## 📌 Task 1: Conduct a Penetration Test on a Web Application

### 🎯 Objective:
Perform a basic penetration test on a vulnerable web application to identify issues like SQL Injection and XSS.

### 🧪 Test Target:
- [http://testphp.vulnweb.com](http://testphp.vulnweb.com) — intentionally vulnerable site by Acunetix.

### 🔧 Tools Used:
- Burp Suite (Community Edition)
- sqlmap
- Firefox (configured to use Burp as proxy)
- Nikto

### 🛠️ Procedure:

1. **Start Burp Suite**:
   ```bash
   java -jar ~/BurpSuiteCommunity/burpsuite_community.jar

2. **Configure Firefox Proxy**:

  - HTTP Proxy: 127.0.0.1
  - Port: 8080

3. **Install Burp Certificate**:

   - Visit: http://burpsuite
   - Download and import into Firefox

4. **Capture Requests**:

   - Visit http://testphp.vulnweb.com
   - View in Proxy > HTTP History in Burp

5. **SQL Injection Test**:

   - URL: /artists.php?artist=1
   - Modify to: artist=1' OR 1=1--

6. **XSS Test**:

  - URL: /search.php
  - Payload: <script>alert('XSS')</script>

7. **sqlmap Scan**:

            sqlmap -u "http://testphp.vulnweb.com/artists.php?artist=1" --dbs
8. **Nikto Scan**:
       nikto -h http://testphp.vulnweb.com
       
# 📌 Task 2: Develop and Implement an Incident Response Plan

##  🎯 Objective:

Develop a structured process to detect, contain, respond to, and recover from a cybersecurity incident.

### 🧩 Incident Response Phases:
1. **🔧 Preparation**:
Assign roles (Incident Commander, Forensic Analyst)

Prepare tools: rkhunter, chkrootkit, tcpdump, etc.

2. **🔎 Detection**:

           tail -f /var/log/auth.log
           sudo netstat -tulnp
           sudo rkhunter --check
   
3. **🛑 Containment**:
  
           sudo ifconfig eth0 down
           sudo iptables -A INPUT -s <attacker-ip> -j DROP
           sudo dd if=/dev/sda of=/mnt/usb/image.dd bs=4M

4. **🧹 Eradication**:
 - Remove malware, backdoors
 - Patch vulnerabilities

5. **🔁 Recovery**:
   
  - Restore from backups
  - Monitor again

6. **📝 Lessons Learned**:
 
- Document timeline, fixes, improvements

# 📌 Task 3: Secure a Web Application

## 🎯 Objective:

Strengthen a web application against common attacks by applying security headers, fixing code-level flaws, and setting proper configurations.

### 🔐 Key Security Techniques

1. **✅ Security Headers (Apache/Nginx)**

             Header set Content-Security-Policy "default-src 'self';"
             Header set Strict-Transport-Security "max-age=31536000; includeSubDomains"
             Header set X-Frame-Options "DENY"
             Header set X-XSS-Protection "1; mode=block"
             Header set X-Content-Type-Options "nosniff"

2. **✅ SQL Injection Mitigation**:

             $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
             $stmt->execute([$_GET['id']]);

3. **✅ XSS Protection**:

             echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');

4. **✅ Input Validation**:
              $email = filter_input(INPUT_POST, 'email', FILTER_VALIDATE_EMAIL);

5. **✅ Enable HTTPS**

               sudo apt install certbot
               sudo certbot --apache

6. **✅ Scan the Site**

               nikto -h http://localhost
               sqlmap -u "http://localhost/page.php?id=1" --dbs

7. **✅ File Permission Hardening**:

               chmod 644 *.php
               chmod 755 /var/www/html/

**✅ Summary**

- These three tasks cover the following essential skills:
- Web application vulnerability testing using Burp Suite and sqlmap
- Building and deploying an incident response plan
-Securing web applications via headers, HTTPS, and code validation

## ⚠️ Always test in legal environments. Use ethical hacking best practices.
