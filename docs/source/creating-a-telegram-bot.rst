Creating a Telegram Bot for the AI VPN
======================================

Telegram is one of the supported technologies of the AI VPN used to request new VPN profiles. Requesting new VPN profiles via Telegram may be beneficial for a number of reasons, but mostly when individuals suspect their email is being monitored. 

These steps need to be followed only if you are deploying the AI VPN on your organization. To complete this process you need to have a Telegram account already registered. 

----------------------------------------------
Registering a new bot using Telegram BotFather
----------------------------------------------

The first step is to register a new Telegram bot using the Telegram BotFather bot:

    1. Go to your Telegram application
    2. Click on `Search for messages or users` and type `@BotFather`. 
    3. Click on the menu on the lower top left of the screen and select the option `/newbot`
    4. The `@BotFather` will ask first for the name of the bot. This is the name displayed to the users of the service. This should represent your own organization and should be such, that users will not be able to confuse your bot with a third party bot. Remember that users will connect to the VPN profiles sent here. It is your responsibility to set this data responsibly.
    5. The `@BotFather` will ask then for the username of the bot. This is the username of the bot that users will search for when trying to find the service. The username should represent your organization and be such that users will not confuse this with any other service.
    6. After the previous two values are shown correctly, the `@BotFather` will display a text and an access token. Please copy the token and continue on the configuration of the AI VPN
