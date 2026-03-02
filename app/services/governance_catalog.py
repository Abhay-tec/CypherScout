from app.services.trusted_apps import normalize_app_key

# 300+ mainstream apps grouped for the governance vault.
APP_CATALOG_BY_CATEGORY = {
    "Social": [
        "WhatsApp", "Instagram", "Facebook", "Messenger", "LinkedIn", "X", "Telegram", "Discord", "Snapchat",
        "Reddit", "Pinterest", "Threads", "Tumblr", "Quora", "Skype", "Viber", "WeChat", "LINE", "KakaoTalk",
        "Signal", "Clubhouse", "Mastodon", "Meetup", "BeReal", "Bigo Live", "imo", "Hike", "Nimo TV",
        "ShareChat", "Moj", "Josh", "Likee", "Triller", "Roposo", "Chingari", "Plato", "Wink", "Amino",
        "Weverse", "Truth Social", "Nextdoor", "Zalo", "VK", "OmeTV", "Tango", "Houseparty", "Bumble", "Tinder",
    ],
    "Finance": [
        "PayPal", "Google Pay", "PhonePe", "Paytm", "Cash App", "Venmo", "Wise", "Revolut", "Skrill", "N26",
        "Chime", "Robinhood", "Webull", "Etrade", "Fidelity", "Charles Schwab", "SBI YONO", "HDFC Bank",
        "ICICI iMobile", "Axis Mobile", "Kotak 811", "IDFC First Bank", "AU 0101", "Canara ai1", "PNB One",
        "BOB World", "Union Bank", "FedMobile", "IndusMobile", "RBL MoBank", "Yes Mobile", "HSBC India",
        "Citi Mobile", "Standard Chartered", "Amex India", "American Express", "Navy Federal", "Wells Fargo",
        "Bank of America", "Chase Mobile", "Capital One", "Santander", "Monzo", "Lloyds Bank", "NatWest",
        "Barclays", "ANZ", "Westpac", "CommBank", "NAB", "DBS digibank", "OCBC Digital", "UOB TMRW",
        "Alipay", "GCash", "Klarna", "Afterpay", "Zelle", "Remitly", "Xe Money", "MobiKwik", "Freecharge",
        "Airtel Thanks", "Jupiter", "Fi Money", "RazorpayX", "CRED", "BharatPe", "JioFinance", "FamPay",
    ],
    "E-commerce": [
        "Amazon", "Flipkart", "Myntra", "Meesho", "Ajio", "eBay", "Alibaba", "AliExpress", "Etsy", "Walmart",
        "Target", "Best Buy", "Costco", "Noon", "Carrefour", "Shopee", "Lazada", "Rakuten", "Mercado Libre",
        "Temu", "Shein", "Zara", "H&M", "Nike", "Adidas", "Puma", "Nykaa", "Sephora", "Tata CLiQ", "Snapdeal",
        "Pepperfry", "Urban Ladder", "IKEA", "Wayfair", "Home Depot", "Lowe's", "Apple Store", "Samsung Shop",
        "Croma", "Reliance Digital", "BigBasket", "Blinkit", "Zepto", "Instacart", "Swiggy Instamart", "Dunzo",
        "FirstCry", "Hamleys", "Lenskart", "Apollo 24/7", "Netmeds", "1mg", "PharmEasy", "BookMyShow",
    ],
    "Utilities": [
        "Gmail", "Outlook", "Yahoo Mail", "Proton Mail", "Google Drive", "Dropbox", "OneDrive", "iCloud",
        "Google Photos", "Adobe Scan", "CamScanner", "Evernote", "Notion", "Trello", "Asana", "ClickUp",
        "Slack", "Microsoft Teams", "Zoom", "Google Meet", "Webex", "AnyDesk", "TeamViewer", "Remote Desktop",
        "LastPass", "1Password", "Bitwarden", "Dashlane", "Authy", "Google Authenticator", "Microsoft Authenticator",
        "NordVPN", "ExpressVPN", "Surfshark", "Proton VPN", "Avast", "Bitdefender", "Kaspersky", "McAfee",
        "Norton 360", "CCleaner", "Files by Google", "Xender", "ShareIt", "Mi Remote", "Truecaller", "DigiLocker",
        "mAadhaar", "IRCTC Rail Connect", "Google Maps", "Waze", "Uber", "Ola", "Rapido", "InDrive",
    ],
    "Education": [
        "YouTube", "YouTube Kids", "Khan Academy", "Coursera", "Udemy", "edX", "Skillshare", "Udacity", "Duolingo",
        "Babbel", "Memrise", "BYJU'S", "Unacademy", "Vedantu", "PW", "Toppr", "Simplilearn", "upGrad",
        "Google Classroom", "Microsoft Learn", "LinkedIn Learning", "Codecademy", "Brilliant", "Photomath",
        "Brainly", "Chegg", "Quizlet", "Anki", "Notability", "GoodNotes", "Mathway", "Wolfram Alpha",
        "SoloLearn", "LeetCode", "HackerRank", "GeeksforGeeks", "Pluralsight", "Datacamp", "DeepLearning.AI",
        "MasterClass", "FutureLearn", "OpenClassrooms", "IXL", "WhiteHat Jr", "Busuu", "Rosetta Stone",
    ],
    "Crypto": [
        "Binance", "Coinbase", "Kraken", "KuCoin", "Bybit", "OKX", "Bitget", "Gate.io", "Gemini", "Crypto.com",
        "MetaMask", "Trust Wallet", "CoinDCX", "WazirX", "ZebPay", "Unocoin", "Bitbns", "Phantom", "Rainbow",
        "Ledger Live", "Trezor Suite", "Exodus", "Atomic Wallet", "CoinMarketCap", "CoinGecko", "MoonPay",
        "Transak", "Uniswap", "PancakeSwap", "1inch", "OpenSea", "Magic Eden", "DappRadar", "TokenPocket",
        "SafePal", "Binance Web3 Wallet", "WalletConnect", "Nexo", "Celsius", "BlockFi", "CoinSwitch",
        "Bitstamp", "Bittrex", "Bitfinex", "Luno", "Paybis", "Changelly", "Simplex", "Fasset",
    ],
    "Gaming": [
        "Steam", "Epic Games", "EA App", "Ubisoft Connect", "Xbox", "PlayStation", "Nintendo Switch Online",
        "Roblox", "Minecraft", "Fortnite", "PUBG Mobile", "BGMI", "Call of Duty Mobile", "Free Fire", "Genshin Impact",
        "Clash of Clans", "Clash Royale", "Brawl Stars", "Pokémon GO", "Among Us", "Subway Surfers", "Candy Crush",
        "8 Ball Pool", "Ludo King", "Dream11", "MPL", "WinZO", "Chess.com", "Lichess", "Twitch", "Kick",
        "Discord Nitro", "GameLoop", "BlueStacks", "Riot Mobile", "Valorant", "League of Legends", "Dota 2",
        "Apex Legends", "Rocket League", "Fall Guys", "Shadow Fight", "Asphalt 9", "Real Cricket", "FIFA Mobile",
        "eFootball", "Clash Mini", "Stumble Guys", "Pokemon Unite",
    ],
}

DOMAIN_OVERRIDES = {
    "x": "x.com",
    "whatsapp": "whatsapp.com",
    "instagram": "instagram.com",
    "facebook": "facebook.com",
    "messenger": "messenger.com",
    "linkedin": "linkedin.com",
    "telegram": "telegram.org",
    "discord": "discord.com",
    "snapchat": "snapchat.com",
    "reddit": "reddit.com",
    "gmail": "mail.google.com",
    "google-drive": "drive.google.com",
    "google-photos": "photos.google.com",
    "google-maps": "maps.google.com",
    "google-meet": "meet.google.com",
    "google-classroom": "classroom.google.com",
    "youtube": "youtube.com",
    "paypal": "paypal.com",
    "google-pay": "pay.google.com",
    "phonepe": "phonepe.com",
    "paytm": "paytm.com",
    "amazon": "amazon.com",
    "flipkart": "flipkart.com",
    "myntra": "myntra.com",
    "ebay": "ebay.com",
    "alibaba": "alibaba.com",
    "zara": "zara.com",
    "meta-mask": "metamask.io",
    "metamask": "metamask.io",
    "binance": "binance.com",
    "coinbase": "coinbase.com",
    "kraken": "kraken.com",
    "trust-wallet": "trustwallet.com",
    "steam": "store.steampowered.com",
    "epic-games": "epicgames.com",
    "roblox": "roblox.com",
    "minecraft": "minecraft.net",
    "pubg-mobile": "pubgmobile.com",
    "bgmi": "battlegroundsmobileindia.com",
    "bookmyshow": "bookmyshow.com",
}


def build_app_catalog() -> list[dict]:
    entries = []
    for category, names in APP_CATALOG_BY_CATEGORY.items():
        for name in names:
            key = normalize_app_key(name)
            host = DOMAIN_OVERRIDES.get(key, f"{key}.com")
            entries.append(
                {
                    "app_key": key,
                    "display_name": name,
                    "category": category,
                    "homepage": f"https://{host}",
                    "host_key": host.lower(),
                }
            )
    return entries
