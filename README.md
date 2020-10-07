# sevenminutevpn

Build an OpenVPN-based VPN and secure web server to host configs in less than seven minutes on Amazon Lightsail. This is a companion repository for the book [The Seven Minute Server: Build Your Own VPN](https://www.amazon.com/Minute-Server-Build-Your-Own/dp/1545371016) but you don't necessarily need the book to run and use this.

Caveat: These scripts were tested on the Amazon Linux 2018 and Amazon Linux 2 AMIs and the Ubuntu 16.04 AMI using Amazon EC2/Lightsail, and *should* work on almost any CentOS 7.x or Ubuntu 16.04 install...however, they're intended to be run on single-purpose ephemeral and disposable cloud-based systems -- not production or personal systems. Any time you're letting a random script muck around with your firewall, it's a good idea to use something with a standard configuration that you can painlessly blow away and recreate.

This currently installs 2.4.9 (stable) on Amazon Linux/RHEL/CentOS (tested on CentOS 8, image centos-8-v20200910, on Google Cloud Platform). The Ubuntu scripts still install 2.3...will update if there's a demand for it.

## Instructions

### Running From the Command Line

1. ssh into your server and run:

    git clone https://github.com/jenh/sevenminutevpn.git /tmp/sevenminutevpn

2. chmod 755 /tmp/sevenminutevpn/\*.sh

3. Run the following, where *script-name* is ubuntu-vpn.sh if you're using Debian/Ubuntu or build-vpn.sh if you're using CentOS/Red Hat.

    cd /tmp/sevenminutevpn && sudo ./*script-name*.sh

4. When the scripts are finished, jump to step 10 in the Lightsail instructions.


### Lightsail Instructions

1. Log onto [Amazon Lightsail](https://lightsail.aws.amazon.com).

2. Click **Create Instance**.

3. Click **OS Only**, select **Amazon Linux**.

4. Click **Add Launch Script** and paste the contents of ``launchscript.sh`` inside.

5. Choose the **$3.50/First Month Free** plan.

6. Enter a name for your instance in the **Name Your Instance** field and click **Create.**

7. You'll see Pending for a few seconds while your instance loads up. Tap the menu associated with the instance and select **Manage.**

7. Tap the **Networking** tab and scroll down to **Firewall**.

8. Add two new rules:

   - Custom TCP rule for port 443 (this is for our client file web server)

   - Custom UDP rule for port 1194 (default OpenVPN port)

   **Note:** These ports are open to the world. You can set up firewall rules on
   the instance itself if you want to restrict incoming access (or use EC2!).

9. Tap the **Connect** tab, then click the **Connect Using SSH** button to open a console connection to your system.

10. Check status of the install by running ``tail -f /tmp/.build-vpn.log.$timestamp``. When complete, find your login password for the client configuration files:

   ```
   [ec2-user~] cat /home/ec2-user/.web
   8nS&i<wOy
   ```
11. Navigate to https://server_ip/downloads. You'll see an angry warning because we're using a self-signed SSL cert. Proceed anyway. The browser doesn't trust us, but we trust ourselves.

12. When prompted, enter the username ``vpn`` and the password you obtained when you catted the .web file.

13. You should see a list of files: An ONC and p12 file for use with Google ChromeOS and an OVPN file for all other platforms. Download the file and import it into your OpenVPN client of choice.

If you can't connect within a few seconds, check to make sure you enabled **UDP 1194** in your firewall, not TCP. It's really easy to add two TCP rules in the Lightsail interface.





For ChromeOS Users
------------------

ChromeOS on Google Chromebook requires a few extra steps to configure.

1. On your Chromebook, open Chrome, chrome://settings/certificates.
2. Import & Bind to Device, select the p12. Currently, this is given an insecure "chrome" password on generation; you can change this in the script if you want.
3. Then chrome://net-internals > ChromeOS.
4. Click Import ONC, navigate to your generated onc file, Import. The interface will tell you "no file chosen," but if you tap your wifi network icon in the system tray, tap VPN Connections, it should show up unless there was a parsing error. (If you find out where or whether these parsing errors get logged anywhere, lemme know - couldn't find 'em in /var/log/\*)
5. Connect. You'll be prompted for a password, you can put anything there if you're just using certificates, the server doesn't care if it doesn't need it, but Chrome won't let you connect without a value there.
