# ---------------------------------------|
# Configuration Class                    |
#                                        |
# Author: @jfaust0                       |
#                                        |
# Description: This class contains the   |
# Reddit API specifics for a proper      |
# connection as well as the search and   |
# scraping specifics. This class is      |
# designed to be edited/amended by the   |
# user to suit their needs.              |
# ---------------------------------------|


class configuration:

    def __init__(self):
        
        # Network Setup
        self.use_proxy = False
        
        # Reddit API Variables
        self.r_username = ""
        self.r_password = ""
        self.r_client_id = ""
        self.r_client_secret = ""
        self.r_user_agent = ""

        # Reddit SubReddits to Search:
        self.sub_reddits = ["onions", "deepweb", "darknet", "tor", "conspiracy", "privacy", "vpn", "deepwebintel",
                            "emailprivacy", "drugs", "blackhat", "HowToHack", "netsec", "hacking",
                            "blackhatunderground", "blackhats", "blackhatting", "blackhatexploits",
                            "reverseengineering"]
        
        self.aws_access_key = ""
        self.aws_secret_key = ""

        # Keywords to Search each Onions Address for.
        ## Searches the .onion source code retrived via an HTTP GET request.
        self.keywords = ["Hacker", "drugs"]
