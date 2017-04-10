sevenminutevpn
==============

Build an OpenVPN-based VPN and secure web server to host configs in less than seven minutes on Amazon Lightsail.

Caveat: These scripts were tested on the Amazon Linux AMI using EC2 & Lightsail, and *should* work on almost any CentOS 7.x install...however, they' a're intended to be run on single-purpose ephemeral and disposable VMs -- not production or personal systems.

1. Log onto Amazon Lightsail [Amazon Lightsail](https://lightsail.aws.amazon.com).

2. Click **Create Instance**.

3. Click **OS Only**, select **Amazon Linux**.

4. Click **Add Launch Script** and paste the contents of ``launchscript.sh`` inside.

5. Choose the **$5/First Month Free** plan.

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

You'll also want to disable ``tls-version-min`` in ``/etc/openvpn/server.conf`` and restart OpenVPN (``sudo service openvpn restart``) as ChromeOS is stuck on OpenVPN 2.3.2, which can't go higher than TLS 1.0 and can't connect if we bar the door to them. We mitigate around that a little by restricting the TLS ciphers that can be used in our config. Also, in testing, other modern OpenVPN clients will negotiate with TLS 1.1 or 1.2 even if not forced. If you're a ChromeOS user, help us out and star this [Chromium bug](https://bugs.chromium.org/p/chromium/issues/detail?id=707517) so that we can encourage Google to update OpenVPN on ChromeOS.

1. On your Chromebook, open Chrome, chrome://settings/certificates.
2. Import & Bind to Device, select the p12. Currently, this is given an insecure "chrome" password on generation; you can change this in the script if you want.
3. Then chrome://net-internals > ChromeOS.
4. Click Import ONC, navigate to your generated onc file, Import. The interface will tell you "no file chosen," but if you tap your wifi network icon in the system tray, tap VPN Connections, it should show up unless there was a parsing error. (If you find out where or whether these parsing errors get logged anywhere, lemme know - couldn't find 'em in /var/log/\*)
5. Connect. You'll be prompted for a password, you can put anything there if you're just using certificates, the server doesn't care if it doesn't need it, but Chrome won't let you connect without a value there.
